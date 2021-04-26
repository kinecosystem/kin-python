from typing import Optional

from agora.keys import PrivateKey, PublicKey
from agora.model.invoice import Invoice
from agora.model.transaction_type import TransactionType


class Payment:
    """The :class:`Payment <Payment>` object, which represents a payment that will get submitted.

    :param sender: The :class:`PrivateKey <agora.keys.PrivateKey>` of the account from which funds will be sent.
    :param destination: The :class:`PublicKey <agora.keys.PublicKey>` of the account to which funds will be sent.
    :param tx_type: The :class:`TransactionType <agora.model.transaction_type.TransactionType>` of this payment.
    :param quarks: The amount being sent.
    :param invoice: (optional) An :class:`Invoice <agora.model.invoice.Invoice>` to associate with this payment. Only
        one of invoice or memo should be set.
    :param memo: (optional) The text memo to include with the transaction. Only one of invoice or memo should be set.
    :param subsidizer: (optional) The subsidizer to use for the create account transaction. The subsidizer will be
            used as the payer of the transaction.
    :param dedupe_id: (optional) The dedupe ID to use for the transaction submission. If included, Agora will verify
        that no transaction was previously submitted the same dedupe ID before submitting the transaction to the
        blockchain.
    """

    def __init__(
        self, sender: PrivateKey, destination: PublicKey, tx_type: TransactionType, quarks: int,
        invoice: Optional[Invoice] = None, memo: Optional[str] = None, subsidizer: Optional[PrivateKey] = None,
        dedupe_id: Optional[bytes] = None,
    ):
        self.sender = sender
        self.destination = destination
        self.tx_type = tx_type
        self.quarks = quarks
        self.subsidizer = subsidizer

        if invoice and memo:
            raise ValueError('only one of `invoice` or `memo` can be set, not both')

        self.invoice = invoice
        self.memo = memo
        self.dedupe_id = dedupe_id

    def __eq__(self, other):
        if not isinstance(other, Payment):
            return False

        return (self.sender == other.sender and
                self.destination == other.destination and
                self.tx_type == other.tx_type and
                self.quarks == other.quarks and
                self.invoice == other.invoice and
                self.memo == other.memo and
                self.subsidizer == other.subsidizer)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'sender={self.sender!r}, destination={self.destination!r}, tx_type={self.tx_type!r}, ' \
               f'quarks={self.quarks}, invoice={self.invoice!r}, memo={self.memo!r}, ' \
               f'subsidizer={self.subsidizer!r}, dedupe_id={self.dedupe_id})'


class ReadOnlyPayment:
    """The :class:`ReadOnlyPayment <ReadOnlyPayment>` object, which represents a payment that was retrieved from
    history.

    :param sender: The :class:`PublicKey <agora.keys.PublicKey>` of the sending account.
    :param destination: The :class:`PublicKey <agora.keys.PublicKey>` of the destination account.
    :param tx_type: The type of this payment.
    :param quarks: The amount of the payment.
    :param invoice: (optional) The :class:`Invoice <agora.model.invoice.Invoice>` associated with this payment. Only one
        of invoice or memo will be set.
    :param memo: (optional) The text memo associated with this transaction. Only one of invoice or memo will be set.
    """

    def __init__(
        self, sender: PublicKey, destination: PublicKey, tx_type: TransactionType, quarks: int,
        invoice: Optional[Invoice] = None, memo: Optional[str] = None
    ):
        self.sender = sender
        self.destination = destination
        self.tx_type = tx_type
        self.quarks = quarks
        self.invoice = invoice
        self.memo = memo

    def __eq__(self, other):
        if not isinstance(other, ReadOnlyPayment):
            return False

        return (self.sender == other.sender and
                self.destination == other.destination and
                self.tx_type == other.tx_type and
                self.quarks == other.quarks and
                self.invoice == other.invoice and
                self.memo == other.memo)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'sender={self.sender!r}, destination={self.destination!r}, tx_type={self.tx_type!r}, ' \
               f'quarks={self.quarks}, invoice={self.invoice!r}, memo={self.memo!r})'
