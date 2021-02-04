import base64

import pytest
from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.model.invoice import InvoiceList, Invoice
from agora.model.memo import AgoraMemo
from agora.model.payment import ReadOnlyPayment
from agora.model.transaction_type import TransactionType
from tests.utils import generate_keys


class TestReadOnlyPayment:
    def test_payments_from_transaction(self):
        keys = [key.public_key for key in generate_keys(5)]
        token_program = keys[4]
        tx = solana.Transaction.new(
            keys[0],
            [
                solana.memo_instruction('somememo'),
                solana.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                    token_program,
                ),
                solana.transfer(
                    keys[2],
                    keys[3],
                    keys[1],
                    40,
                    token_program,
                ),
            ]
        )

        payments = ReadOnlyPayment.payments_from_transaction(tx)

        assert len(payments) == 2

        assert payments[0].sender == keys[1]
        assert payments[0].destination == keys[2]
        assert payments[0].tx_type == TransactionType.UNKNOWN
        assert payments[0].quarks == 20
        assert not payments[0].invoice
        assert payments[0].memo == 'somememo'

        assert payments[1].sender == keys[2]
        assert payments[1].destination == keys[3]
        assert payments[1].tx_type == TransactionType.UNKNOWN
        assert payments[1].quarks == 40
        assert not payments[1].invoice
        assert payments[1].memo == 'somememo'

    def test_payments_from_transaction_with_invoice_list(self):
        il = model_pb2.InvoiceList(invoices=[
            model_pb2.Invoice(
                items=[
                    model_pb2.Invoice.LineItem(title='t1', amount=10),
                ]
            ),
            model_pb2.Invoice(
                items=[
                    model_pb2.Invoice.LineItem(title='t1', amount=15),
                ]
            ),
        ])
        fk = InvoiceList.from_proto(il).get_sha_224_hash()
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, fk)

        keys = [key.public_key for key in generate_keys(5)]
        token_program = keys[4]
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
                solana.transfer(
                    keys[2],
                    keys[3],
                    keys[1],
                    40,
                    token_program,
                ),
            ]
        )

        payments = ReadOnlyPayment.payments_from_transaction(tx, il)

        assert len(payments) == 2

        assert payments[0].sender == keys[1]
        assert payments[0].destination == keys[2]
        assert payments[0].tx_type == TransactionType.P2P
        assert payments[0].quarks == 20
        assert payments[0].invoice == Invoice.from_proto(il.invoices[0])
        assert not payments[0].memo

        assert payments[1].sender == keys[2]
        assert payments[1].destination == keys[3]
        assert payments[1].tx_type == TransactionType.P2P
        assert payments[1].quarks == 40
        assert payments[1].invoice == Invoice.from_proto(il.invoices[1])
        assert not payments[1].memo

    def test_payments_from_transaction_invalid(self):
        il = model_pb2.InvoiceList(invoices=[
            model_pb2.Invoice(
                items=[
                    model_pb2.Invoice.LineItem(title='t1', amount=10),
                ]
            ),
        ])
        fk = InvoiceList.from_proto(il).get_sha_224_hash()
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, fk)

        keys = [key.public_key for key in generate_keys(5)]
        token_program = keys[4]
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
                solana.transfer(
                    keys[2],
                    keys[3],
                    keys[1],
                    40,
                    token_program,
                ),
            ]
        )

        # mismatching number of invoices and instructions
        with pytest.raises(ValueError):
            ReadOnlyPayment.payments_from_transaction(tx, il)
