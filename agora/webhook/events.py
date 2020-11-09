import base64
from typing import Optional

from agoraapi.common.v3 import model_pb2

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


class StellarEvent:
    """Stellar event data related to a transaction.

    :param result_xdr: A base64-encoded transaction result XDR.
    :param envelope_xdr: A base64-encoded transaction envelope XDR.
    """

    def __init__(self, result_xdr: str, envelope_xdr: str):
        self.result_xdr = result_xdr
        self.envelope_xdr = envelope_xdr

    @classmethod
    def from_json(cls, data: dict) -> 'StellarEvent':
        return cls(
            result_xdr=data.get('result_xdr'),
            envelope_xdr=data.get('envelope_xdr'),
        )


class TransactionEvent:
    """An event indicating a transaction has completed (either successfully or
    unsuccessfully).

    :param kin_version: the version of Kin the transaction was submitted to
    :param tx_id: the id of the transaction. Either a 32-byte Stellar transaction hash or a 64-byte Solana transaction
        signature.
    :param invoice_list: (optional) the InvoiceList related to the transaction.
    :param stellar_event: (optional) any Stellar data related to the transaction. Set on Kin 2 and Kin 3 transaction
        events.
    :param solana_event: (optional) any Solana data related to the transaction. Set on Kin 4 transaction events.
    """

    def __init__(
        self, kin_version: int, tx_id: bytes, invoice_list: InvoiceList = None, stellar_event: StellarEvent = None,
        solana_event: SolanaEvent = None,
    ):
        self.kin_version = kin_version
        self.tx_id = tx_id
        self.invoice_list = invoice_list
        self.stellar_event = stellar_event
        self.solana_event = solana_event

    @classmethod
    def from_json(cls, data: dict) -> 'TransactionEvent':
        kin_version = data.get('kin_version')
        if not kin_version:
            raise ValueError('kin_version is required')
        if kin_version > 4 or kin_version < 2:
            raise ValueError(f'invalid kin version: {kin_version}')

        tx_id = base64.b64decode(data.get('tx_id')) if 'tx_id' in data else b''
        if len(tx_id) == 0:
            tx_id = base64.b64decode(data.get('tx_hash')) if 'tx_hash' in data else b''
            if len(tx_id) == 0:
                raise ValueError('`tx_id` or `tx_hash` is required')

        il = data.get('invoice_list')
        if il:
            proto_il = model_pb2.InvoiceList()
            proto_il.ParseFromString(il)
            invoice_list = InvoiceList.from_proto(proto_il)
        else:
            invoice_list = None

        tx_event = cls(kin_version, tx_id, invoice_list=invoice_list)

        solana_data = data.get('solana_event', None)
        if solana_data:
            tx_event.solana_event = SolanaEvent.from_json(solana_data)
        stellar_data = data.get('stellar_event', None)
        if stellar_data:
            tx_event.stellar_event = StellarEvent.from_json(stellar_data)

        return tx_event


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
