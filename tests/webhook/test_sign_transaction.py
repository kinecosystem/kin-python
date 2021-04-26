import base64
from typing import Optional, Tuple

import pytest
from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.error import InvoiceErrorReason
from agora.keys import PrivateKey
from agora.model import AgoraMemo, TransactionType
from agora.model.invoice import Invoice, InvoiceList
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse
from tests.utils import generate_keys

_SIGNING_KEY = PrivateKey.random()


class TestSignTransactionRequest:
    def test_from_json_kin_4(self):
        tx, il = _generate_tx(True)

        data = {
            'solana_transaction': base64.b64encode(tx.marshal()),
            'invoice_list': base64.b64encode(il.SerializeToString()),
        }

        req = SignTransactionRequest.from_json(data)
        assert len(req.payments) == 1
        assert req.payments[0].invoice == Invoice.from_proto(il.invoices[0])
        assert req.transaction == tx

    def test_get_tx_id(self):
        tx, _ = _generate_tx(False)
        tx.sign([_SIGNING_KEY])

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
    def test_sign(self):
        tx, _ = _generate_tx(False)
        resp = SignTransactionResponse(tx)
        resp.sign(_SIGNING_KEY)

        _SIGNING_KEY.public_key.verify(resp.transaction.message.marshal(), resp.transaction.signatures[0])

    def test_reject(self):
        tx, _ = _generate_tx(False)
        resp = SignTransactionResponse(tx)
        assert not resp.rejected

        resp.reject()
        assert resp.rejected

    def test_mark_invoice_error(self):
        tx, _ = _generate_tx(False)
        resp = SignTransactionResponse(tx)
        resp.mark_invoice_error(5, InvoiceErrorReason.SKU_NOT_FOUND)

        assert resp.rejected
        assert len(resp.invoice_errors) == 1
        assert resp.invoice_errors[0].op_index == 5
        assert resp.invoice_errors[0].reason == InvoiceErrorReason.SKU_NOT_FOUND


def _generate_tx(with_il: Optional[bool] = False) -> Tuple[solana.Transaction, Optional[model_pb2.InvoiceList]]:
    il = None
    instructions = []

    if with_il:
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
        instructions.append(solana.memo_instruction(base64.b64encode(memo.val).decode('utf-8')))

    keys = [key.public_key for key in generate_keys(3)]
    instructions.append(solana.transfer(
        keys[0],
        keys[1],
        keys[2],
        20,
    ), )

    return solana.Transaction.new(
        _SIGNING_KEY.public_key,
        instructions
    ), il
