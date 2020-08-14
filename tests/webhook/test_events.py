import base64

import pytest
from agoraapi.common.v3 import model_pb2

from agora.webhook.events import StellarData, TransactionEvent, Event


class TestStellarData:
    def test_from_json(self):
        data = {
            'result_xdr': 'resultxdr',
            'envelope_xdr': 'envelopexdr'
        }

        stellar_data = StellarData.from_json(data)
        assert stellar_data.result_xdr == 'resultxdr'
        assert stellar_data.envelope_xdr == 'envelopexdr'


class TestTransactionEvent:
    def test_from_json_simple(self):
        data = {
            'kin_version': 3,
            'tx_hash': base64.b64encode(b'txhash'),
        }

        event = TransactionEvent.from_json(data)
        assert event.kin_version == 3
        assert event.tx_hash == b'txhash'
        assert not event.invoice_list
        assert not event.stellar_data

    def test_from_json_full(self):
        il = model_pb2.InvoiceList(
            invoices=[
                model_pb2.Invoice(
                    items=[
                        model_pb2.Invoice.LineItem(title='title1', description='desc1', amount=50, sku=b'somesku')
                    ]
                )
            ]
        )

        data = {
            'kin_version': 3,
            'tx_hash': base64.b64encode(b'txhash'),
            'invoice_list': il.SerializeToString(),
            'stellar_data': {
                'result_xdr': 'resultxdr',
                'envelope_xdr': 'envelopexdr',
            }
        }

        event = TransactionEvent.from_json(data)
        assert event.kin_version == 3
        assert event.tx_hash == b'txhash'
        assert len(event.invoice_list.invoices) == 1
        assert len(event.invoice_list.invoices[0].items) == 1

        line_item = event.invoice_list.invoices[0].items[0]
        assert line_item.title == 'title1'
        assert line_item.description == 'desc1'
        assert line_item.amount == 50
        assert line_item.sku == b'somesku'

        assert event.stellar_data.result_xdr == 'resultxdr'
        assert event.stellar_data.envelope_xdr == 'envelopexdr'

    def test_from_json_invalid(self):
        # missing kin_version
        with pytest.raises(ValueError):
            TransactionEvent.from_json({'tx_hash': base64.b64encode(b'txhash')})

        # missing tx_hash
        with pytest.raises(ValueError):
            TransactionEvent.from_json({'kin_version': 3})


class TestEvent:
    def test_from_json_empty(self):
        event = Event.from_json({})
        assert not event.transaction_event

    def test_from_json_with_tx_event(self):
        event = Event.from_json({
            'transaction_event': {
                'kin_version': 3,
                'tx_hash': base64.b64encode(b'txhash')
            }
        })
        assert event.transaction_event.kin_version == 3
        assert event.transaction_event.tx_hash == b'txhash'
