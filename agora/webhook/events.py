import base64
import json
from typing import Optional

from agoraapi.common.v3 import model_pb2
from google.protobuf.json_format import Parse

from agora import solana
from agora.error import Error, InvalidSignatureError, BadNonceError, InsufficientBalanceError, AccountNotFoundError
from agora.model.invoice import InvoiceList


class SolanaEvent:
    """Solana event data related to a transaction.

    :param transaction: The :class:`Transaction <agora.solana.transaction.Transaction>` object.
    :param tx_error: (optional) The :class:`Error <agora.error.Error` indicating why the transaction failed.
    :param tx_error_raw: (optional) The raw transaction error.
    """

    def __init__(
        self, transaction: solana.Transaction, tx_error: Optional[Error] = None, tx_error_raw: Optional[str] = None
    ):
        self.transaction = transaction
        self.tx_error = tx_error
        self.tx_error_raw = tx_error_raw

    @classmethod
    def from_json(cls, data: dict) -> 'SolanaEvent':
        tx_string = data.get('transaction', "")
        if not tx_string:
            raise ValueError('`transaction` is required in Solana transaction events')

        return cls(
            solana.Transaction.unmarshal(base64.b64decode(tx_string)),
            tx_error=cls._convert_error(data.get('transaction_error', '')),
            tx_error_raw=data.get('transaction_error_raw', None),
        )

    @staticmethod
    def _convert_error(e: str):
        if len(e) == 0 or e == 'none':
            return None
        if e == 'unknown':
            return Error(f'unknown error')
        if e == 'unauthorized':
            return InvalidSignatureError()
        if e == 'bad_nonce':
            return BadNonceError()
        if e == 'insufficient_funds':
            return InsufficientBalanceError()
        if e == 'invalid_account':
            return AccountNotFoundError()
        return Error(f'error: {e}')


class TransactionEvent:
    """An event indicating a transaction has completed (either successfully or
    unsuccessfully).

    :param tx_id: the id of the transaction. Either a 32-byte Stellar transaction hash or a 64-byte Solana transaction
        signature.
    :param solana_event: any Solana data related to the transaction.
    :param invoice_list: (optional) the InvoiceList related to the transaction.
    """

    def __init__(
        self, tx_id: bytes, solana_event: SolanaEvent, invoice_list: InvoiceList = None,
    ):
        self.tx_id = tx_id
        self.invoice_list = invoice_list
        self.solana_event = solana_event

    @classmethod
    def from_json(cls, data: dict) -> 'TransactionEvent':
        tx_id = base64.b64decode(data.get('tx_id')) if 'tx_id' in data else b''
        if len(tx_id) == 0:
            raise ValueError('`tx_id` is required')

        il = data.get('invoice_list')
        if il:
            proto_il = Parse(json.dumps(il), model_pb2.InvoiceList())
            invoice_list = InvoiceList.from_proto(proto_il)
        else:
            invoice_list = None

        solana_data = data.get('solana_event', None)
        if not solana_data:
            raise ValueError('`solana_event` is required')

        return cls(tx_id, SolanaEvent.from_json(solana_data), invoice_list=invoice_list)


class Event:
    """An event container for a specific type of event triggered by a blockchain operation.

    :param transaction_event: (optional) A :class:`TransactionEvent <TransactionEvent>`.
    """

    def __init__(self, transaction_event: Optional['TransactionEvent'] = None):
        self.transaction_event = transaction_event

    @classmethod
    def from_json(cls, data: dict) -> 'Event':
        tx_event_data = data.get('transaction_event')
        tx_event = TransactionEvent.from_json(tx_event_data) if tx_event_data else None
        return cls(transaction_event=tx_event)
