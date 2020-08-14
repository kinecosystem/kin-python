import base64
from typing import Optional

from agoraapi.common.v3 import model_pb2

from agora.model.invoice import InvoiceList


class StellarData:
    """Stellar-specific data related to a transaction.

    :param result_xdr: A base64-encoded transaction result XDR.
    :param envelope_xdr: A base64-encoded transaction envelope XDR.
    """

    def __init__(self, result_xdr: str, envelope_xdr: str):
        self.result_xdr = result_xdr
        self.envelope_xdr = envelope_xdr

    @classmethod
    def from_json(cls, data: dict) -> 'StellarData':
        return cls(
            result_xdr=data.get('result_xdr'),
            envelope_xdr=data.get('envelope_xdr'),
        )


class TransactionEvent:
    """An event indicating a transaction has completed (either successfully or
    unsuccessfully).

    :param: kin_version: the version of Kin the transaction was submitted to
    :param tx_hash: the hash of the transaction
    :param invoice_list: (optional) the InvoiceList related to the transaction.
    :param stellar_data: (optional) any Stellar data related to the transaction.
    """

    def __init__(
        self, kin_version: int, tx_hash: bytes,
        invoice_list: InvoiceList = None, stellar_data: StellarData = None
    ):
        self.kin_version = kin_version
        self.tx_hash = tx_hash
        self.invoice_list = invoice_list
        self.stellar_data = stellar_data

    @classmethod
    def from_json(cls, data: dict):
        kin_version = data.get('kin_version')
        if not kin_version:
            raise ValueError('kin_version is required')

        tx_hash = base64.b64decode(data.get('tx_hash') if 'tx_hash' in data else b'')
        if len(tx_hash) == 0:
            raise ValueError('tx_hash is required')

        il = data.get('invoice_list')
        if il:
            proto_il = model_pb2.InvoiceList()
            proto_il.ParseFromString(il)
            invoice_list = InvoiceList.from_proto(proto_il)
        else:
            invoice_list = None

        data = data.get('stellar_data')
        stellar_data = StellarData.from_json(data) if data else None

        return cls(kin_version, tx_hash, invoice_list=invoice_list,
                   stellar_data=stellar_data)


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
