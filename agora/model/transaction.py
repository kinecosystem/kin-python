import base64
from enum import IntEnum
from typing import List, Optional

from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb_v4
from kin_base import transaction_envelope as te, memo as stellar_memo

from agora import solana
from agora.error import TransactionErrors
from agora.keys import PublicKey
from agora.model.invoice import InvoiceList
from agora.model.memo import AgoraMemo
from agora.model.payment import ReadOnlyPayment
from agora.model.transaction_type import TransactionType


class TransactionState(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILED = 2
    PENDING = 3

    @staticmethod
    def from_proto(state: tx_pb.GetTransactionResponse.State):
        if state == tx_pb.GetTransactionResponse.State.SUCCESS:
            return TransactionState.SUCCESS
        return TransactionState.UNKNOWN

    @staticmethod
    def from_proto_v4(state: tx_pb_v4.GetTransactionResponse.State):
        if state == tx_pb_v4.GetTransactionResponse.State.SUCCESS:
            return TransactionState.SUCCESS
        if state == tx_pb_v4.GetTransactionResponse.State.FAILED:
            return TransactionState.FAILED
        if state == tx_pb_v4.GetTransactionResponse.State.PENDING:
            return TransactionState.PENDING

        return TransactionState.UNKNOWN


class TransactionData:
    """The :class:`TransactionData <TransactionData>` object, which contains information about the payments in a
    transaction.

    :param tx_id: Either a 32-byte transaction hash, or a 64-byte transaction signature.
    :param payments: (optional) A list of :class:`ReadOnlyPayment <agora.model.payment.ReadOnlyPayment>` objects.
    :param error: (optional)) A :class:`TransactionError <agora.error.TransactionError>` object that contains extra
        details about why a transaction failed. If present, it indicates that the transaction failed.
    """

    def __init__(
        self, tx_id: bytes, transaction_state: TransactionState, payments: List[ReadOnlyPayment] = None,
        error: Optional[TransactionErrors] = None,
    ):
        self.tx_id = tx_id
        self.transaction_state = transaction_state
        self.payments = payments if payments else []
        self.error = error

    def __eq__(self, other):
        if not isinstance(other, TransactionData):
            return False

        return (self.tx_id == other.tx_id and
                all(payment == other.payments[idx] for idx, payment in enumerate(self.payments)) and
                self.error == other.error)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'tx_id={self.tx_id}, payments={[p for p in self.payments]!r}, error={self.error!r})'

    @classmethod
    def from_proto(
        cls, item: tx_pb_v4.HistoryItem, state: tx_pb_v4.GetTransactionResponse.State
    ) -> 'TransactionData':
        payments = []
        if item.invoice_list and item.invoice_list.invoices:
            if len(item.payments) != len(item.invoice_list.invoices):
                raise ValueError('number of invoices does not match number of payments')
            il = InvoiceList.from_proto(item.invoice_list)
        else:
            il = None

        tx_type = TransactionType.UNKNOWN
        memo = None
        if item.solana_transaction.value:
            solana_tx = solana.Transaction.unmarshal(item.solana_transaction.value)
            program_idx = solana_tx.message.instructions[0].program_index
            if solana_tx.message.accounts[program_idx] == solana.MEMO_PROGRAM_KEY:
                decompiled_memo = solana.decompile_memo(solana_tx.message, 0)
                memo_data = decompiled_memo.data.decode('utf-8')
                try:
                    agora_memo = AgoraMemo.from_b64_string(memo_data)
                    tx_type = agora_memo.tx_type()
                except ValueError:
                    memo = memo_data
        elif item.stellar_transaction.envelope_xdr:
            env = te.TransactionEnvelope.from_xdr(base64.b64encode(item.stellar_transaction.envelope_xdr))
            tx = env.tx
            if isinstance(tx.memo, stellar_memo.HashMemo):
                try:
                    agora_memo = AgoraMemo.from_base_memo(tx.memo)
                    tx_type = agora_memo.tx_type()
                except ValueError:
                    pass
            elif isinstance(tx.memo, stellar_memo.TextMemo):
                memo = tx.memo.text.decode()

        for idx, p in enumerate(item.payments):
            inv = il.invoices[idx] if il and il.invoices else None
            payments.append(ReadOnlyPayment(PublicKey(p.source.value), PublicKey(p.destination.value),
                                            tx_type, p.amount, invoice=inv, memo=memo))

        return cls(
            item.transaction_id.value,
            TransactionState.from_proto_v4(state),
            payments,
            error=TransactionErrors.from_proto_error(item.transaction_error) if item.transaction_error else None,
        )
