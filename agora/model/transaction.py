import base64
from typing import List, Optional

from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base import transaction_envelope as te

from agora.error import TransactionErrors
from agora.model.payment import ReadOnlyPayment


class TransactionData:
    """The :class:`TransactionData <TransactionData>` object, which contains information about the payments in a
    transaction.

    :param tx_hash: The hash of the transaction.
    :param payments: (optional) A list of :class:`ReadOnlyPayment <agora.model.payment.ReadOnlyPayment>` objects.
    :param error: (optional)) A :class:`TransactionError <agora.error.TransactionError>` object that contains extra
        details about why a transaction failed. If present, it indicates that the transaction failed.
    """

    def __init__(
        self, tx_hash: bytes, payments: List[ReadOnlyPayment] = None, error: Optional[TransactionErrors] = None
    ):
        self.tx_hash = tx_hash
        self.payments = payments if payments else []
        self.error = error

    def __eq__(self, other):
        if not isinstance(other, TransactionData):
            return False

        return (self.tx_hash == other.tx_hash and
                all(payment == other.payments[idx] for idx, payment in enumerate(self.payments)) and
                self.error == other.error)

    @classmethod
    def from_proto(cls, item: tx_pb.HistoryItem) -> 'TransactionData':
        data = cls(
            item.hash.value,
            error=TransactionErrors.from_result(item.result_xdr),
        )
        if item.envelope_xdr:
            env = te.TransactionEnvelope.from_xdr(base64.b64encode(item.envelope_xdr))
            data.payments = ReadOnlyPayment.payments_from_envelope(env, item.invoice_list)

        return data
