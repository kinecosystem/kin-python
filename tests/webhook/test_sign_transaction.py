import base64

import pytest
from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.error import InvoiceErrorReason
from agora.model import AgoraMemo, TransactionType
from agora.model.invoice import Invoice, InvoiceList
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse
from tests.utils import generate_keys


class TestSignTransactionRequest:
    def test_from_json_kin_4(self):
        il = model_pb2.InvoiceList(
            invoices=[
                model_pb2.Invoice(
                    items=[
                        model_pb2.Invoice.LineItem(title='title1', description='desc1', amount=50, sku=b'somesku')
                    ]
                )
            ]
        )

        fk = InvoiceList.from_proto(il).get_sha_224_hash()
        memo = AgoraMemo.new(1, TransactionType.P2P, 0, fk)

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
            'solana_transaction': base64.b64encode(tx.marshal()),
            'invoice_list': base64.b64encode(il.SerializeToString()),
        }

        req = SignTransactionRequest.from_json(data)
        assert len(req.payments) == 1
        assert req.payments[0].invoice == Invoice.from_proto(il.invoices[0])
        assert req.transaction == tx

    def test_get_tx_id(self):
        keys = generate_keys(4)
        public_keys = [key.public_key for key in keys]
        token_program = public_keys[3]

        tx = solana.Transaction.new(
            public_keys[0],
            [
                solana.transfer(
                    public_keys[1],
                    public_keys[2],
                    public_keys[3],
                    20,
                    token_program,
                ),
            ]
        )
        tx.sign([keys[0]])

        data = {
            'kin_version': 4,
            'solana_transaction': base64.b64encode(tx.marshal()),
        }

        req = SignTransactionRequest.from_json(data)
        assert req.get_tx_id() == tx.signatures[0]

    def test_from_json_invalid(self):
        # missing transaction
        with pytest.raises(ValueError):
            SignTransactionRequest.from_json({})


class TestSignTransactionResponse:
    # TODO: add test_sign when solana transaction signing is supported

    def test_reject(self):
        resp = SignTransactionResponse()
        assert not resp.rejected

        resp.reject()
        assert resp.rejected

    def test_mark_invoice_error(self):
        resp = SignTransactionResponse()
        resp.mark_invoice_error(5, InvoiceErrorReason.SKU_NOT_FOUND)

        assert resp.rejected
        assert len(resp.invoice_errors) == 1
        assert resp.invoice_errors[0].op_index == 5
        assert resp.invoice_errors[0].reason == InvoiceErrorReason.SKU_NOT_FOUND

    def test_to_json(self):
        # not rejected
        resp = SignTransactionResponse()
        assert resp.to_json() == {}

        # rejected
        resp.reject()
        assert resp.to_json() == {}

        # rejected with invoice errors
        resp.mark_invoice_error(0, InvoiceErrorReason.ALREADY_PAID)
        assert resp.to_json() == {
            "invoice_errors": [
                {
                    "operation_index": 0,
                    "reason": InvoiceErrorReason.ALREADY_PAID.to_lowercase()
                }
            ]
        }
