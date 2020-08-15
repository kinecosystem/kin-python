from typing import Optional, List

from agoraapi.common.v3 import model_pb2
from kin_base import transaction_envelope as te, operation, memo

from agora.model.invoice import Invoice
from agora.model.keys import PrivateKey, PublicKey
from agora.model.memo import AgoraMemo
from agora.model.transaction_type import TransactionType
from agora.utils import kin_to_quarks


class Payment:
    """The :class:`Payment <Payment>` object, which represents a payment that will get submitted.

    :param sender: The :class:`PrivateKey <agora.model.keys.PrivateKey` of the account from which funds will be sent.
    :param destination: The :class:`PublicKey <agora.model.keys.PublicKey` of the account to which funds will be sent.
    :param payment_type: The :class:`TransactionType <agora.model.transaction_type.TransactionType>` of this payment.
    :param quarks: The amount being sent.
    :param source: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey` of the account that will act as the
        source of the transaction. If unset, the sender will be used as the transaction source.

        On Stellar, this is where the transaction fee and sequence number is taken/chosen from.

        On Solana, this is where the fee is taken from.
    :param invoice: (optional) An :class:`Invoice <agora.model.invoice.Invoice>` to associate with this payment. Only
        one of invoice or memo should be set.
    :param memo: (optional) The text memo to include with the transaction. Only one of invoice or memo should be set.
    """

    def __init__(
        self, sender: PrivateKey, destination: PublicKey, payment_type: TransactionType, quarks: int,
        source: Optional[PrivateKey] = None, invoice: Optional[Invoice] = None, memo: Optional[str] = None
    ):
        self.sender = sender
        self.destination = destination
        self.payment_type = payment_type
        self.quarks = quarks
        self.source = source

        if invoice and memo:
            raise ValueError("only one of `invoice` or `memo` can be set, not both")

        self.invoice = invoice
        self.memo = memo

    def __eq__(self, other):
        if not isinstance(other, Payment):
            return False

        return (self.sender == other.sender and
                self.destination == other.destination and
                self.payment_type == other.payment_type and
                self.quarks == other.quarks and
                self.source == other.source and
                self.invoice == other.invoice and
                self.memo == other.memo)


class ReadOnlyPayment:
    """The :class:`ReadOnlyPayment <ReadOnlyPayment>` object, which represents a payment that was retrieved from
    history.

    :param sender: The :class:`PublicKey <agora.model.keys.PublicKey` of the sending account.
    :param dest: The :class:`PublicKey <agora.model.keys.PublicKey` of the destination account.
    :param payment_type: The type of this payment.
    :param quarks: The amount of the payment.
    :param invoice: (optional) The :class:`Invoice <agora.model.invoice.Invoice>` associated with this payment. Only one
        of invoice or memo will be set.
    :param memo: (optional) The text memo associated with this transaction. Only one of invoice or memo will be set.
    """

    def __init__(
        self, sender: PublicKey, dest: PublicKey, payment_type: TransactionType, quarks: int,
        invoice: Optional[Invoice] = None, memo: Optional[str] = None
    ):
        self.sender = sender
        self.dest = dest
        self.payment_type = payment_type
        self.quarks = quarks
        self.invoice = invoice
        self.memo = memo

    def __eq__(self, other):
        if not isinstance(other, ReadOnlyPayment):
            return False

        return (self.sender == other.sender and
                self.dest == other.dest and
                self.payment_type == other.payment_type and
                self.quarks == other.quarks and
                self.invoice == other.invoice and
                self.memo == other.memo)

    @classmethod
    def payments_from_envelope(
        cls, envelope: te.TransactionEnvelope, invoice_list: Optional[model_pb2.InvoiceList] = None
    ) -> List['ReadOnlyPayment']:
        """Returns a list of read only payments from a transaction envelope.

        :param envelope: A :class:`TransactionEnvelope <kin_base.transaction_envelope.TransactionEnvelope>.
        :param invoice_list: (optional) A protobuf invoice list associated with the transaction.
        :return: A List of :class:`ReadOnlyPayment <ReadOnlyPayment>` objects.
        """
        if invoice_list and invoice_list.invoices and len(invoice_list.invoices) != len(envelope.tx.operations):
            raise ValueError("number of invoices ({}) does not match number of transaction operations ({})".format(
                len(invoice_list.invoices), len(envelope.tx.operations)))

        tx = envelope.tx

        text_memo = None
        agora_memo = None
        if isinstance(tx.memo, memo.HashMemo):
            try:
                agora_memo = AgoraMemo.from_base_memo(tx.memo, False)
            except ValueError:
                pass
        elif isinstance(tx.memo, memo.TextMemo):
            text_memo = tx.memo

        payments = []
        for idx, op in enumerate(envelope.tx.operations):
            # Currently, only payment operations are supported in this method. Eventually, create account and merge
            # account operations could potentially be supported, but currently this is primarily only used for payment
            # operations
            if not isinstance(op, operation.Payment):
                continue

            inv = invoice_list.invoices[idx] if invoice_list and invoice_list.invoices else None

            payments.append(ReadOnlyPayment(
                sender=PublicKey.from_string(op.source if op.source else tx.source.decode()),
                dest=PublicKey.from_string(op.destination),
                payment_type=agora_memo.tx_type() if agora_memo else
                TransactionType.UNKNOWN,
                quarks=kin_to_quarks(op.amount),
                invoice=Invoice.from_proto(inv) if inv else None,
                memo=text_memo.text.decode() if text_memo else None,
            ))

        return payments
