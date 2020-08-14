from agoraapi.common.v3 import model_pb2
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora.model.invoice import InvoiceList
from agora.model.memo import AgoraMemo
from agora.model.transaction import TransactionData
from agora.model.transaction_type import TransactionType
from tests.utils import gen_account_id, gen_tx_envelope_xdr, gen_payment_op, \
    gen_payment_op_result, gen_result_xdr, gen_hash_memo, gen_text_memo


class TestTransaction(object):
    def test_from_proto_text_memo(self):
        op_result = gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED)
        result_xdr = gen_result_xdr(xdr_const.txFAILED, [op_result])

        tx_src = gen_account_id()
        dest = gen_account_id()
        operations = [gen_payment_op(dest, amount=20)]
        envelope_xdr = gen_tx_envelope_xdr(tx_src, 1, operations,
                                           gen_text_memo(b'somememo'))

        history_item = tx_pb.HistoryItem(
            hash=model_pb2.TransactionHash(value=b'somehash'),
            result_xdr=result_xdr,
            envelope_xdr=envelope_xdr,
            cursor=tx_pb.Cursor(value=b'cursor1'),
        )

        data = TransactionData.from_proto(history_item)
        assert data.tx_hash == b'somehash'
        assert len(data.payments) == 1

        payment = data.payments[0]
        assert payment.sender.raw == tx_src.ed25519
        assert payment.dest.raw == dest.ed25519
        assert payment.payment_type == TransactionType.UNKNOWN
        assert payment.quarks == 20
        assert not payment.invoice
        assert payment.memo == 'somememo'

    def test_from_proto_agora_memo(self):
        op_result = gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [op_result, op_result])

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
        operations = [
            gen_payment_op(acc2, src=acc1, amount=10),
            gen_payment_op(acc1, src=acc2, amount=15),
        ]
        envelope_xdr = gen_tx_envelope_xdr(acc3, 1, operations, hash_memo)

        history_item = tx_pb.HistoryItem(
            hash=model_pb2.TransactionHash(value=b'somehash'),
            result_xdr=result_xdr,
            envelope_xdr=envelope_xdr,
            cursor=tx_pb.Cursor(value=b'cursor1'),
            invoice_list=il,
        )

        data = TransactionData.from_proto(history_item)
        assert data.tx_hash == b'somehash'
        assert len(data.payments) == 2

        payment1 = data.payments[0]
        assert payment1.sender.raw == acc1.ed25519
        assert payment1.dest.raw == acc2.ed25519
        assert payment1.payment_type == memo.tx_type()
        assert payment1.quarks == 10
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        payment2 = data.payments[1]
        assert payment2.sender.raw == acc2.ed25519
        assert payment2.dest.raw == acc1.ed25519
        assert payment2.payment_type == TransactionType.P2P
        assert payment2.quarks == 15
        assert (payment2.invoice.to_proto().SerializeToString() == il.invoices[1].SerializeToString())
        assert not payment2.memo
