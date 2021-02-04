import base64
import hashlib
import hmac
import json
from typing import List

from agora import solana
from agora.client import Environment
from agora.error import WebhookRequestError, InvoiceErrorReason
from agora.keys import PrivateKey
from agora.webhook.events import Event
from agora.webhook.handler import WebhookHandler
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse
from tests.utils import generate_keys

_TEST_PRIVATE_KEY = PrivateKey.random()


class TestWebhookHandler:
    def test_is_valid_signature(self):
        secret = 'secret'
        handler = WebhookHandler(Environment.TEST, secret=secret)

        req_body = 'somebody'
        sig = base64.b64encode(hmac.new(secret.encode(), req_body.encode(), hashlib.sha256).digest())

        assert handler.is_valid_signature(req_body, sig)

        other_sig = base64.b64encode(hmac.new(secret.encode(), b'', hashlib.sha256).digest())
        assert not handler.is_valid_signature(req_body, other_sig)

        assert not handler.is_valid_signature(req_body, "")

    def test_handle_event(self):
        secret = 'secret'
        handler = WebhookHandler(Environment.TEST, secret=secret)

        keys = [key.public_key for key in generate_keys(4)]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.transfer(
                    keys[1],
                    keys[1],
                    keys[2],
                    20,
                    keys[3],
                ),
            ]
        )
        data = [{
            'transaction_event': {
                'tx_id': base64.b64encode(b'txsig').decode('utf-8'),
                'solana_event': {
                    'transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
                }
            }
        }]
        req_body = json.dumps(data)
        sig = base64.b64encode(hmac.new(secret.encode(), req_body.encode(), hashlib.sha256).digest())
        text_sig = base64.b64encode(hmac.new(secret.encode(), b'someotherdata', hashlib.sha256).digest())

        # invalid signature
        status_code, resp_body = handler.handle_events(self._event_return_none, text_sig, req_body)
        assert status_code == 401
        assert resp_body == ''

        # invalid req body
        status_code, resp_body = handler.handle_events(self._event_return_none, text_sig, 'someotherdata')
        assert status_code == 400
        assert resp_body == 'invalid request body'

        # webhook request error
        status_code, resp_body = handler.handle_events(self._event_raise_webhook_request_error, sig, req_body)
        assert status_code == 400
        assert resp_body == 'some error'

        # other error
        status_code, resp_body = handler.handle_events(self._event_raise_other_error, sig, req_body)
        assert status_code == 500
        assert resp_body == 'bad stuff'

        # successful
        status_code, resp_body = handler.handle_events(self._event_return_none, sig, req_body)
        assert status_code == 200

        # fake signature with no webhook secret should result in a successful response
        handler = WebhookHandler(Environment.TEST)
        status_code, resp_body = handler.handle_events(self._event_return_none, "fakesig", req_body)
        assert status_code == 200

    def test_handle_sign_transaction(self):
        secret = 'secret'
        handler = WebhookHandler(Environment.TEST, secret=secret)

        keys = [key.public_key for key in generate_keys(4)]
        token_program = keys[3]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                    token_program,
                ),
            ]
        )

        data = {
            'kin_version': 4,
            'solana_transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
        }

        req_body = json.dumps(data)
        sig = base64.b64encode(hmac.new(secret.encode(), req_body.encode(), hashlib.sha256).digest())
        text_sig = base64.b64encode(hmac.new(secret.encode(), b'someotherdata', hashlib.sha256).digest())

        # invalid signature
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_success, text_sig, req_body)
        assert status_code == 401
        assert resp_body == ''

        # invalid req body
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_success, text_sig,
                                                                 'someotherdata')
        assert status_code == 400
        assert resp_body == 'invalid request body'

        # webhook request error
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_raise_webhook_request_error, sig,
                                                                 req_body)
        assert status_code == 400
        assert resp_body == 'some error'

        # other error
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_raise_other_error, sig, req_body)
        assert status_code == 500
        assert resp_body == 'bad stuff'

        # rejected
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_return_rejected, sig, req_body)
        assert status_code == 403
        assert json.loads(resp_body) == {
            'invoice_errors': [
                {'operation_index': 0, 'reason': InvoiceErrorReason.UNKNOWN.to_lowercase()}
            ]
        }

        # successful
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_success, sig, req_body)
        assert status_code == 200
        assert json.loads(resp_body) == {}

        # fake signature with no webhook secret should result in a successful response
        handler = WebhookHandler(Environment.TEST)
        status_code, resp_body = handler.handle_sign_transaction(self._sign_tx_success, "fakesig", req_body)
        assert status_code == 200
        assert json.loads(resp_body) == {}

    @staticmethod
    def _event_return_none(events: List[Event]):
        return None

    @staticmethod
    def _event_raise_webhook_request_error(events: List[Event]):
        raise WebhookRequestError(400, response_body='some error')

    @staticmethod
    def _event_raise_other_error(events: List[Event]):
        raise Exception('bad stuff')

    @staticmethod
    def _sign_tx_success(req: SignTransactionRequest, resp: SignTransactionResponse):
        resp.sign(_TEST_PRIVATE_KEY)

    @staticmethod
    def _sign_tx_return_rejected(req: SignTransactionRequest, resp: SignTransactionResponse):
        resp.mark_invoice_error(0, InvoiceErrorReason.UNKNOWN)

    @staticmethod
    def _sign_tx_raise_webhook_request_error(req: SignTransactionRequest, resp: SignTransactionResponse):
        raise WebhookRequestError(400, response_body='some error')

    @staticmethod
    def _sign_tx_raise_other_error(req: SignTransactionRequest, resp: SignTransactionResponse):
        raise Exception('bad stuff')
