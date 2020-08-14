import base64

from agoraapi.common.v3 import model_pb2
from kin_base import transaction_envelope as te

from agora.model.invoice import InvoiceList, Invoice
from agora.model.memo import AgoraMemo
from agora.model.payment import ReadOnlyPayment
from agora.model.transaction_type import TransactionType
from tests.utils import gen_account_id, gen_payment_op, gen_tx_envelope_xdr, gen_text_memo, gen_hash_memo


class TestReadOnlyPayment:
    def test_payments_from_envelope(self):
        acc1 = gen_account_id()
        acc2 = gen_account_id()
        acc3 = gen_account_id()
        operations = [gen_payment_op(acc2, amount=20),
                      gen_payment_op(acc3, src=acc2, amount=40)]
        envelope_xdr = gen_tx_envelope_xdr(acc1, 1, operations,
                                           gen_text_memo(b'somememo'))
        env = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))

        payments = ReadOnlyPayment.payments_from_envelope(env)

        assert len(payments) == 2

        assert payments[0].sender.raw == acc1.ed25519
        assert payments[0].dest.raw == acc2.ed25519
        assert payments[0].payment_type == TransactionType.UNKNOWN
        assert payments[0].quarks == 20
        assert not payments[0].invoice
        assert payments[0].memo == 'somememo'

        assert payments[1].sender.raw == acc2.ed25519
        assert payments[1].dest.raw == acc3.ed25519
        assert payments[1].payment_type == TransactionType.UNKNOWN
        assert payments[1].quarks == 40
        assert not payments[1].invoice
        assert payments[1].memo == 'somememo'

    def test_payments_from_envelope_with_invoice_list(self):
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
        hash_memo = gen_hash_memo(memo.val)

        acc1 = gen_account_id()
        acc2 = gen_account_id()
        acc3 = gen_account_id()
        operations = [gen_payment_op(acc2, amount=20),
                      gen_payment_op(acc3, src=acc2, amount=40)]
        envelope_xdr = gen_tx_envelope_xdr(acc1, 1, operations, hash_memo)
        env = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))

        payments = ReadOnlyPayment.payments_from_envelope(env, il)

        assert len(payments) == 2

        assert payments[0].sender.raw == acc1.ed25519
        assert payments[0].dest.raw == acc2.ed25519
        assert payments[0].payment_type == TransactionType.P2P
        assert payments[0].quarks == 20
        assert payments[0].invoice == Invoice.from_proto(il.invoices[0])
        assert not payments[0].memo

        assert payments[1].sender.raw == acc2.ed25519
        assert payments[1].dest.raw == acc3.ed25519
        assert payments[1].payment_type == TransactionType.P2P
        assert payments[1].quarks == 40
        assert payments[1].invoice == Invoice.from_proto(il.invoices[1])
        assert not payments[1].memo
