import hashlib
from typing import List, Optional

from agoraapi.common.v3 import model_pb2


class LineItem:
    """The :class:`LineItem` object, which represents a line item in an invoice.

    :param title: The title of the line item.
    :param amount: The amount, in quarks.
    :param description: (optional) A description of the line item.
    :param sku: (optional) A SKU associated with the line item.
    """

    def __init__(self, title: str, amount: int, description: Optional[str] = "", sku: Optional[bytes] = None):
        self.title = title
        self.amount = amount
        self.description = description
        self.sku = sku

    def __eq__(self, other):
        if not isinstance(other, LineItem):
            return False

        return self.to_proto().SerializeToString() == other.to_proto().SerializeToString()

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'title={self.title}, amount={self.amount}, description={self.description}, sku={self.sku})'

    @classmethod
    def from_proto(cls, proto: model_pb2.Invoice.LineItem) -> 'LineItem':
        return cls(
            title=proto.title,
            description=proto.description,
            amount=proto.amount,
            sku=proto.sku
        )

    def to_proto(self) -> model_pb2.Invoice.LineItem:
        return model_pb2.Invoice.LineItem(
            title=self.title,
            description=self.description,
            amount=self.amount,
            sku=self.sku
        )


class Invoice:
    """The :class: `Invoice <Invoice>` object, which represents a transaction invoice for a single payment.

    :param items: A list of :class:`LineItem <LineItem>` objects.
    """

    def __init__(self, items: List[LineItem]):
        self.items = items

    def __eq__(self, other):
        if not isinstance(other, Invoice):
            return False

        return self.to_proto().SerializeToString() == other.to_proto().SerializeToString()

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'items={[item for item in self.items]!r})'

    @classmethod
    def from_proto(cls, proto: model_pb2.Invoice) -> 'Invoice':
        return cls([LineItem.from_proto(item) for item in proto.items])

    def to_proto(self) -> model_pb2.Invoice:
        return model_pb2.Invoice(items=[item.to_proto() for item in self.items])


class InvoiceList:
    """The :class:`InvoiceList <InvoiceList>` object, which is a list of
    invoices associated with a transaction.

    :param invoices: a list of :class:`Invoice <Invoice>` objects.
    """

    def __init__(self, invoices: List[Invoice]):
        self.invoices = invoices

    def __eq__(self, other):
        if not isinstance(other, InvoiceList):
            return False

        return self.to_proto().SerializeToString() == other.to_proto().SerializeToString()

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'invoices={[inv for inv in self.invoices]!r})'

    @classmethod
    def from_proto(cls, proto: model_pb2.InvoiceList) -> 'InvoiceList':
        return cls(invoices=[Invoice.from_proto(inv) for inv in proto.invoices])

    def to_proto(self) -> model_pb2.InvoiceList:
        return model_pb2.InvoiceList(invoices=[invoice.to_proto() for invoice in self.invoices])

    def get_sha_224_hash(self) -> bytes:
        """Returns the SHA-224 of the marshaled protobuf form of this invoice.

        :return: the SHA-224 hash.
        """
        return hashlib.sha224(self.to_proto().SerializeToString()).digest()
