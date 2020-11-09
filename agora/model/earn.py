from typing import Optional, List

from agora.model.invoice import Invoice
from agora.keys import PublicKey, PrivateKey


class Earn:
    """The :class:`Earn <Earn>` object, which represents an earn payment that will get submitted.

    :param destination: The :class:`PublicKey <agora.model.keys.PublicKey>` of the account the earn will be sent to.
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

    :param sender: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the sender
    :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
    :param channel: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey>` of a channel account to use as
        the transaction source. If not set, the `sender` will be used as the source.
    :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
        will be applied.
    :param subsidizer: (optional) The subsidizer to use for the create account transaction. The subsidizer will be
            used both as the payer of the transaction. Only applicable for Kin 4 transactions.

    """

    def __init__(self, sender: PrivateKey, earns: List[Earn], channel: Optional[PrivateKey] = None,
                 memo: Optional[str] = None, subsidizer: Optional[PrivateKey] = None):
        self.sender = sender
        self.earns = earns
        self.channel = channel
        self.memo = memo
        self.subsidizer = subsidizer

    def __eq__(self, other):
        if not isinstance(other, EarnBatch):
            return False

        return (self.sender == other.sender and
                self.earns == other.earns and
                self.channel == other.channel and
                self.memo == other.memo and
                self.subsidizer == other.subsidizer)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'sender={self.sender!r}, earns={[e for e in self.earns]!r}, channel={self.channel!r}, ' \
               f'memo={self.memo!r}, subsidizer={self.subsidizer!r})'
