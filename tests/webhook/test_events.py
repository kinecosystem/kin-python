import base64

import pytest
from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.error import InvalidSignatureError, BadNonceError
from agora.model import AgoraMemo, TransactionType
from agora.webhook.events import StellarData, TransactionEvent, Event, SolanaData
from tests.utils import generate_keys


class TestSolanaData:
    def test_from_json(self):
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, b'somefk')
        keys = [key.public_key for key in generate_keys(4)]
        token_program = keys[3]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.memo_instruction(base64.b64encode(memo.val).decode('utf-8')),
                solana.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                    token_program,
                ),
            ]
        )

        data = {
            'transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
            'transaction_error': 'unauthorized',
            'transaction_error_raw': 'raw_error'
        }

        solana_data = SolanaData.from_json(data)
        assert solana_data.transaction == tx
        assert isinstance(solana_data.tx_error, InvalidSignatureError)
        assert solana_data.tx_error_raw == 'raw_error'


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
        assert event.tx_id == b'txhash'
        assert not event.invoice_list
        assert not event.stellar_data
        assert not event.solana_data

    def test_from_json_full_kin_3(self):
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
        assert event.tx_id == b'txhash'
        assert len(event.invoice_list.invoices) == 1
        assert len(event.invoice_list.invoices[0].items) == 1

        line_item = event.invoice_list.invoices[0].items[0]
        assert line_item.title == 'title1'
        assert line_item.description == 'desc1'
        assert line_item.amount == 50
        assert line_item.sku == b'somesku'

        assert event.stellar_data.result_xdr == 'resultxdr'
        assert event.stellar_data.envelope_xdr == 'envelopexdr'

        assert not event.solana_data

    def test_from_json_full_kin_4(self):
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, b'somefk')
        keys = [key.public_key for key in generate_keys(4)]
        token_program = keys[3]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.memo_instruction(base64.b64encode(memo.val).decode('utf-8')),
                solana.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                    token_program,
                ),
            ]
        )

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
            'kin_version': 4,
            'tx_id': base64.b64encode(b'txsig'),
            'invoice_list': il.SerializeToString(),
            'solana_data': {
                'transaction': base64.b64encode(tx.marshal()).decode('utf-8'),
                'transaction_error': 'bad_nonce',
                'transaction_error_raw': 'raw_error',
            }
        }

        event = TransactionEvent.from_json(data)
        assert event.kin_version == 4
        assert event.tx_id == b'txsig'
        assert len(event.invoice_list.invoices) == 1
        assert len(event.invoice_list.invoices[0].items) == 1

        line_item = event.invoice_list.invoices[0].items[0]
        assert line_item.title == 'title1'
        assert line_item.description == 'desc1'
        assert line_item.amount == 50
        assert line_item.sku == b'somesku'

        assert not event.stellar_data

        assert event.solana_data.transaction == tx
        assert isinstance(event.solana_data.tx_error, BadNonceError)
        assert event.solana_data.tx_error_raw == 'raw_error'

    def test_from_json_invalid(self):
        # missing/invalid kin_version
        with pytest.raises(ValueError):
            TransactionEvent.from_json({'tx_hash': base64.b64encode(b'txhash')})

        invalid_versions = [1, 5]
        for version in invalid_versions:
            data = {
                'kin_version': version
            }

            with pytest.raises(ValueError):
                TransactionEvent.from_json(data)

        # missing both tx_id and tx_hash
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
        assert event.transaction_event.tx_id == b'txhash'
