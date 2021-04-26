from typing import Optional, List

from agora.keys import PublicKey, PrivateKey
from agora.model.invoice import Invoice


class Earn:
    """The :class:`Earn <Earn>` object, which represents an earn payment that will get submitted.

    :param destination: The :class:`PublicKey <agora.keys.PublicKey>` of the account the earn will be sent to.
    :param quarks: The amount being sent.
    :param invoice: (optional) An :class:`Invoice <agora.model.invoice.Invoice>` object to associate with this earn.
    """

    def __init__(self, destination: PublicKey, quarks: int, invoice: Optional[Invoice] = None):
        self.destination = destination
        self.quarks = quarks
        self.invoice = invoice

    def __eq__(self, other):
        if not isinstance(other, Earn):
            return False

        return (self.destination == other.destination and
                self.quarks == other.quarks and
                self.invoice == other.invoice)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'destination={self.destination!r}, quarks={self.quarks}, invoice={self.invoice!r})'


class EarnBatch:
    """The :class:`EarnBatch <EarnBatch>` object, which represents a batch of Earn payments coming from a single
    sender.

    :param sender: The :class:`PrivateKey <agora.keys.PrivateKey>` of the sender
    :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
    :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
        will be applied.
    :param subsidizer: (optional) The subsidizer to use for the create account transaction. The subsidizer will be
            used as the payer of the transaction.
    :param dedupe_id: (optional) The dedupe ID to use for the transaction submission. If included, Agora will verify
        that no transaction was previously submitted the same dedupe ID before submitting the transaction to the
        blockchain.

    """

    def __init__(
        self, sender: PrivateKey, earns: List[Earn], memo: Optional[str] = None,
        subsidizer: Optional[PrivateKey] = None, dedupe_id: Optional[bytes] = None
    ):
        self.sender = sender
        self.earns = earns
        self.memo = memo
        self.subsidizer = subsidizer
        self.dedupe_id = dedupe_id

    def __eq__(self, other):
        if not isinstance(other, EarnBatch):
            return False

        return (self.sender == other.sender and
                self.earns == other.earns and
                self.memo == other.memo and
                self.subsidizer == other.subsidizer)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'sender={self.sender!r}, earns={[e for e in self.earns]!r}, memo={self.memo!r}, ' \
               f'subsidizer={self.subsidizer!r}), dedupe_id={self.dedupe_id}'
