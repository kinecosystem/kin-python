from typing import Optional

from agora.model.invoice import Invoice
from agora.model.keys import PublicKey


class Earn:
    """The :class:`Earn <Earn>` object, which represents an earn payment that will get submitted.

    :param destination: The :class:`PublicKey <agora.model.keys.PublicKey` of the account the earn will be sent to.
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
