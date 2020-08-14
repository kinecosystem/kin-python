import base64

import pytest
from agoraapi.common.v3 import model_pb2
from kin_base import transaction_envelope as te

from agora.error import InvoiceErrorReason
from agora.model import PrivateKey
from agora.model.invoice import Invoice
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse
from tests.utils import gen_account_id, gen_payment_op, gen_tx_envelope_xdr, gen_text_memo


class TestSignTransactionRequest(object):
    def test_from_json_simple(self):
        envelope = _generate_envelope()
        data = {
            'kin_version': 3,
            'envelope_xdr': envelope.xdr(),
        }

        req = SignTransactionRequest.from_json(data)
        assert len(req.payments) == 1

        assert req.kin_version == data['kin_version']
        assert req.envelope.xdr() == envelope.xdr()

    def test_from_json_full(self):
        envelope = _generate_envelope()
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
            'envelope_xdr': envelope.xdr(),
            'invoice_list': base64.b64encode(il.SerializeToString()),
        }

        req = SignTransactionRequest.from_json(data)
        assert len(req.payments) == 1
        assert req.payments[0].invoice == Invoice.from_proto(il.invoices[0])

        assert req.kin_version == data['kin_version']
        assert req.envelope.xdr() == envelope.xdr()

    def test_from_json_invalid(self):
        # missing kin_version
        with pytest.raises(ValueError):
            SignTransactionRequest.from_json({'envelope_xdr': 'envelopexdr'})

        # missing envelope_xdr
        with pytest.raises(ValueError):
            SignTransactionRequest.from_json({'kin_version': 3})


class TestSignTransactionResponse(object):
    def test_sign(self):
        resp = SignTransactionResponse(_generate_envelope())

        private_key = PrivateKey.random()
        resp.sign(private_key)

        # kp.verify throws an error if the signature doesn't match
        private_key.verify(resp.envelope.hash_meta(), resp.envelope.signatures[-1].signature)

    def test_reject(self):
        resp = SignTransactionResponse(_generate_envelope())
        assert not resp.rejected

        resp.reject()
        assert resp.rejected

    def test_mark_invoice_error(self):
        resp = SignTransactionResponse(_generate_envelope())
        resp.mark_invoice_error(5, InvoiceErrorReason.SKU_NOT_FOUND)

        assert resp.rejected
        assert len(resp.invoice_errors) == 1
        assert resp.invoice_errors[0].op_index == 5
        assert resp.invoice_errors[0].reason == InvoiceErrorReason.SKU_NOT_FOUND

    def test_to_json(self):
        env = _generate_envelope()
        # not rejected
        resp = SignTransactionResponse(env)
        assert resp.to_json() == {
            "envelope_xdr": env.xdr().decode()
        }

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


def _generate_envelope():
    acc1 = gen_account_id()
    acc2 = gen_account_id()
    operations = [gen_payment_op(acc2)]
    envelope_xdr = gen_tx_envelope_xdr(acc1, 1, operations,
                                       gen_text_memo(b'somememo'))
    return te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))
