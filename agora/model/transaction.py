import base64
from enum import Enum
from typing import List

from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base import transaction_envelope as te

from agora.model.payment import ReadOnlyPayment


class TransactionState(Enum):
    """The state of a transaction.
    """
    UNKNOWN = 0
    SUCCESS = 1
    FAILED = 2

    @classmethod
    def from_proto(cls, state: tx_pb.GetTransactionResponse.State) -> 'TransactionState':
        if state == tx_pb.GetTransactionResponse.State.SUCCESS:
            return cls.SUCCESS
        if state == tx_pb.GetTransactionResponse.State.FAILED:
            return cls.FAILED
        return cls.UNKNOWN


class TransactionData(object):
    """The :class:`TransactionData <TransactionData>` object, which contains information about the payments in a
    transaction.

    :param tx_hash: The hash of the transaction.
    :param payments: A list of :class:`ReadOnlyPayment <agora.payment.ReadOnlyPayment>` objects.
    """

    def __init__(self, tx_hash: bytes, payments: List[ReadOnlyPayment]):
        self.tx_hash = tx_hash
        self.payments = payments

    def __eq__(self, other):
        if not isinstance(other, TransactionData):
            return False

        return (self.tx_hash == other.tx_hash and
                all(payment == other.payments[idx] for idx, payment in enumerate(self.payments)))

    @classmethod
    def from_proto(cls, item: tx_pb.HistoryItem) -> 'TransactionData':
        env = te.TransactionEnvelope.from_xdr(base64.b64encode(item.envelope_xdr))

        return cls(
            tx_hash=item.hash.value,
            payments=ReadOnlyPayment.payments_from_envelope(env, item.invoice_list)
        )
