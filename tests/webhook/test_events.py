import base64

import pytest
from agoraapi.common.v3 import model_pb2
from google.protobuf.json_format import MessageToDict

from agora import solana
from agora.error import InvalidSignatureError, BadNonceError
from agora.model import AgoraMemo, TransactionType
from agora.webhook.events import TransactionEvent, Event, SolanaEvent
from tests.utils import generate_keys


class TestSolanaData:
    def test_from_json(self):
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, b'somefk')
        keys = [key.public_key for key in generate_keys(4)]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.memo_instruction(base64.b64encode(memo.val).decode('utf-8')),
                solana.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                ),
            ]
        )

        data = {
            'transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
            'transaction_error': 'unauthorized',
            'transaction_error_raw': 'raw_error'
        }

        solana_event = SolanaEvent.from_json(data)
        assert solana_event.transaction == tx
        assert isinstance(solana_event.tx_error, InvalidSignatureError)
        assert solana_event.tx_error_raw == 'raw_error'


class TestTransactionEvent:
    def test_from_json_full_kin_4(self):
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, b'somefk')
        keys = [key.public_key for key in generate_keys(4)]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.memo_instruction(base64.b64encode(memo.val).decode('utf-8')),
                solana.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                ),
            ]
        )

        il = model_pb2.InvoiceList(
            invoices=[
                model_pb2.Invoice(
                    items=[
                        model_pb2.Invoice.LineItem(title='title1', description='desc1', amount=50, sku=b'somesku')
                    ]
                )
            ]
        )

        data = {
            'tx_id': base64.b64encode(b'txsig').decode('utf-8'),
            'invoice_list': MessageToDict(il),
            'solana_event': {
                'transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
                'transaction_error': 'bad_nonce',
                'transaction_error_raw': 'raw_error',
            }
        }

        event = TransactionEvent.from_json(data)
        assert event.tx_id == b'txsig'
        assert len(event.invoice_list.invoices) == 1
        assert len(event.invoice_list.invoices[0].items) == 1

        line_item = event.invoice_list.invoices[0].items[0]
        assert line_item.title == 'title1'
        assert line_item.description == 'desc1'
        assert line_item.amount == 50
        assert line_item.sku == b'somesku'

        assert event.solana_event.transaction == tx
        assert isinstance(event.solana_event.tx_error, BadNonceError)
        assert event.solana_event.tx_error_raw == 'raw_error'

    def test_from_json_invalid(self):
        # missing tx_id
        with pytest.raises(ValueError):
            TransactionEvent.from_json({})

            # missing solana_event
            with pytest.raises(ValueError):
                TransactionEvent.from_json({'tx_id': base64.b64encode(b'txsig')})


class TestEvent:
    def test_from_json_empty(self):
        event = Event.from_json({})
        assert not event.transaction_event

    def test_from_json_with_tx_event(self):
        keys = [key.public_key for key in generate_keys(3)]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.transfer(
                    keys[1],
                    keys[1],
                    keys[2],
                    20,
                ),
            ]
        )

        event = Event.from_json({
            'transaction_event': {
                'tx_id': base64.b64encode(b'txsig'),
                'solana_event': {
                    'transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
                }
            }
        })
        assert event.transaction_event.tx_id == b'txsig'
        assert event.transaction_event.solana_event
