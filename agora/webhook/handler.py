import base64
import hashlib
import hmac
import json
from json import JSONDecodeError
from typing import Tuple, Callable, List, Optional

from agora.client import Environment
from agora.error import WebhookRequestError
from agora.webhook.events import Event
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse

AGORA_HMAC_HEADER = 'X-Agora-HMAC-SHA256'
APP_USER_ID_HEADER = "X-App-User-ID"
APP_USER_PASSKEY_HEADER = "X-App-User-Passkey"


class WebhookHandler:
    """The :class:`WebhookHelper <WebhookHelper>` contains hooks and methods that can be used to add support for Agora
    webhooks.

    :param secret: The secret used to verify request signatures.
    """

    def __init__(self, environment: Environment, secret: Optional[str] = None):
        self.environment = environment
        self.secret = secret

    def is_valid_signature(self, req_body: str, signature: str) -> bool:
        """Verifies that the provided signature is valid for the provided data.

        :param req_body: The request body that the provided signature is supposedly for.
        :param signature: The base64-encoded signature to verify for the corresponding `req_body`.
        :return: A bool indicating whether or not the signature is valid.
        """
        if not signature:
            return False

        decoded_sig = base64.b64decode(signature)
        calculated_sig = hmac.new(self.secret.encode(), req_body.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(calculated_sig, decoded_sig)

    def handle_events(self, f: Callable[[List[Event]], None], signature: str, req_body: str) -> Tuple[int, str]:
        """A hook for handling an event request from Agora.

        :param f: A function to call with the received event. Implementations can raise
        :exc:`WebhookRequestError <agora.error.WebhookRequestError>` to return a specific HTTP status code and body.
        :param signature: The Agora HMAC signature included in the request headers.
        :param req_body: The request body.
        :return: A Tuple of the status code (int) and the request body (str)
        """
        if self.secret and not self.is_valid_signature(req_body, signature):
            return 401, ''

        try:
            json_events = json.loads(req_body)
        except JSONDecodeError:
            return 400, 'invalid request body'

        events = [Event.from_json(json_event) for json_event in json_events]
        try:
            f(events)
        except WebhookRequestError as req_error:
            return req_error.status_code, req_error.response_body
        except Exception as e:
            return 500, str(e)

        return 200, ''

    def handle_sign_transaction(
        self, f: Callable[[SignTransactionRequest, SignTransactionResponse], None], signature: str, req_body: str
    ) -> Tuple[int, str]:
        """A hook for handling a sign transaction request from Agora.

        :param f: A function to call with the received event. Implementations can raise
            :exc:`InvoiceError <agora.error.InvoiceError>` to return a 403 response with invoice error details or
            :exc:`WebhookRequestError <agora.error.WebhookRequestError>` to return a specific HTTP status code and body.
        :param signature: The Agora HMAC signature included in the request headers.
        :param req_body: The request body.
        :return: A Tuple of the status code (int) and the request body (str).
        """

        if self.secret and not self.is_valid_signature(req_body, signature):
            return 401, ''

        try:
            json_req_body = json.loads(req_body)
        except JSONDecodeError:
            return 400, 'invalid request body'

        req = SignTransactionRequest.from_json(json_req_body, self.environment)
        resp = SignTransactionResponse(req.envelope)
        try:
            f(req, resp)
        except WebhookRequestError as e:
            return e.status_code, e.response_body
        except Exception as e:
            return 500, str(e)

        data = resp.to_json()
        if resp.rejected:
            return 403, json.dumps(data)

        return 200, json.dumps(data)
