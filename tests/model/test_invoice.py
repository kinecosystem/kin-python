from agoraapi.common.v3 import model_pb2

from agora.model.invoice import Invoice, InvoiceList, LineItem


class TestLineItem:
    def test_from_proto(self):
        proto = model_pb2.Invoice.LineItem(
            title='title1',
            description='description1',
            amount=200,
            sku=b'skubytes'
        )

        item = LineItem.from_proto(proto)
        assert item.title == proto.title
        assert item.description == proto.description
        assert item.amount == proto.amount
        assert item.sku == proto.sku

    def test_to_proto(self):
        item = LineItem('title1', 150, 'description1', b'skubytes')

        proto = item.to_proto()
        assert proto.title == item.title
        assert proto.amount == item.amount
        assert proto.description == item.description
        assert proto.sku == item.sku


class TestInvoice:
    def test_from_proto(self):
        proto = model_pb2.Invoice(items=[
            model_pb2.Invoice.LineItem(title='t1', amount=100),
            model_pb2.Invoice.LineItem(title='t2', amount=150),
        ])

        invoice = Invoice.from_proto(proto)
        assert len(invoice.items) == len(proto.items)

        for idx, item in enumerate(invoice.items):
            assert item.title == proto.items[idx].title
            assert item.amount == proto.items[idx].amount

    def test_to_proto(self):
        invoice = Invoice([
            LineItem('title1', 150),
            LineItem('title2', 200),
        ])

        proto = invoice.to_proto()
        assert len(proto.items) == len(invoice.items)

        for idx, proto_item in enumerate(proto.items):
            item = invoice.items[idx]
            assert proto_item.title == item.title
            assert proto_item.amount == item.amount


class TestInvoiceList:
    def test_from_proto(self):
        proto = model_pb2.InvoiceList(invoices=[
            model_pb2.Invoice(
                items=[
                    model_pb2.Invoice.LineItem(title='t1', amount=100),
                ]
            ),
            model_pb2.Invoice(
                items=[
                    model_pb2.Invoice.LineItem(title='t2', amount=150),
                ]
            )
        ])

        invoice_list = InvoiceList.from_proto(proto)
        assert len(invoice_list.invoices) == len(proto.invoices)

        for idx, invoice in enumerate(invoice_list.invoices):
            proto_invoice = invoice_list.invoices[idx]
            assert len(invoice.items) == len(proto_invoice.items)
            assert invoice.items[0].title == proto_invoice.items[0].title
            assert invoice.items[0].amount == proto_invoice.items[0].amount

    def test_to_proto(self):
        invoice_list = InvoiceList([
            Invoice([
                LineItem(title='t1', amount=100)
            ]),
            Invoice([
                LineItem(title='t2', amount=200)
            ])
        ])

        proto = invoice_list.to_proto()
        assert len(proto.invoices) == len(invoice_list.invoices)

        for idx, proto_invoice in enumerate(proto.invoices):
            invoice = invoice_list.invoices[idx]
            assert proto_invoice.items[0].title == invoice.items[0].title
            assert proto_invoice.items[0].amount == invoice.items[0].amount
