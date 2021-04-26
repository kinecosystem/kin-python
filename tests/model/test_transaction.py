import base64

from agoraapi.common.v3 import model_pb2 as model_pb_v3
from agoraapi.common.v4 import model_pb2 as model_pb
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora.keys import PrivateKey
from agora.model.invoice import InvoiceList
from agora.model.memo import AgoraMemo
from agora.model.transaction import TransactionData, TransactionState
from agora.model.transaction_type import TransactionType
from agora.solana import Transaction, memo_instruction, transfer
from tests.utils import gen_account_id, gen_tx_envelope_xdr, gen_payment_op, \
    gen_payment_op_result, gen_result_xdr, gen_hash_memo, gen_text_memo, generate_keys


class TestTransaction:
    def test_from_proto_stellar_text_memo(self):
        op_result = gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED)
        result_xdr = gen_result_xdr(xdr_const.txFAILED, [op_result])

        tx_src = gen_account_id()
        dest = gen_account_id()
        operations = [gen_payment_op(dest, amount=20)]
        envelope_xdr = gen_tx_envelope_xdr(tx_src, 1, operations,
                                           gen_text_memo(b'somememo'))

        history_item = tx_pb.HistoryItem(
            transaction_id=model_pb.TransactionId(value=b'somehash'),
            cursor=tx_pb.Cursor(value=b'cursor1'),
            stellar_transaction=model_pb.StellarTransaction(
                result_xdr=result_xdr,
                envelope_xdr=envelope_xdr,
            ),
            payments=[
                tx_pb.HistoryItem.Payment(
                    source=model_pb.SolanaAccountId(value=tx_src.ed25519),
                    destination=model_pb.SolanaAccountId(value=dest.ed25519),
                    amount=20,
                ),
            ],
        )

        data = TransactionData.from_proto(history_item, tx_pb.GetTransactionResponse.State.SUCCESS)
        assert data.tx_id == b'somehash'
        assert data.transaction_state == TransactionState.SUCCESS
        assert len(data.payments) == 1

        payment = data.payments[0]
        assert payment.sender.raw == tx_src.ed25519
        assert payment.destination.raw == dest.ed25519
        assert payment.tx_type == TransactionType.UNKNOWN
        assert payment.quarks == 20
        assert not payment.invoice
        assert payment.memo == 'somememo'

    def test_from_proto_stellar_agora_memo(self):
        op_result = gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [op_result, op_result])

        il = model_pb_v3.InvoiceList(invoices=[
            model_pb_v3.Invoice(
                items=[
                    model_pb_v3.Invoice.LineItem(title='t1', amount=10),
                ]
            ),
            model_pb_v3.Invoice(
                items=[
                    model_pb_v3.Invoice.LineItem(title='t1', amount=15),
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
            transaction_id=model_pb.TransactionId(value=b'somehash'),
            cursor=tx_pb.Cursor(value=b'cursor1'),
            stellar_transaction=model_pb.StellarTransaction(
                result_xdr=result_xdr,
                envelope_xdr=envelope_xdr,
            ),
            payments=[
                tx_pb.HistoryItem.Payment(
                    source=model_pb.SolanaAccountId(value=acc1.ed25519),
                    destination=model_pb.SolanaAccountId(value=acc2.ed25519),
                    amount=10,
                ),
                tx_pb.HistoryItem.Payment(
                    source=model_pb.SolanaAccountId(value=acc2.ed25519),
                    destination=model_pb.SolanaAccountId(value=acc1.ed25519),
                    amount=15,
                ),
            ],
            invoice_list=il,
        )

        data = TransactionData.from_proto(history_item, tx_pb.GetTransactionResponse.State.SUCCESS)
        assert data.tx_id == b'somehash'
        assert data.transaction_state == TransactionState.SUCCESS
        assert len(data.payments) == 2

        payment1 = data.payments[0]
        assert payment1.sender.raw == acc1.ed25519
        assert payment1.destination.raw == acc2.ed25519
        assert payment1.tx_type == memo.tx_type()
        assert payment1.quarks == 10
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        payment2 = data.payments[1]
        assert payment2.sender.raw == acc2.ed25519
        assert payment2.destination.raw == acc1.ed25519
        assert payment2.tx_type == TransactionType.P2P
        assert payment2.quarks == 15
        assert (payment2.invoice.to_proto().SerializeToString() == il.invoices[1].SerializeToString())
        assert not payment2.memo

    def test_from_proto_solana_text_memo(self):
        source, dest, token_program = [key.public_key for key in generate_keys(3)]
        tx = Transaction.new(PrivateKey.random().public_key, [
            memo_instruction('somememo'),
            transfer(source, dest, PrivateKey.random().public_key, 20),
        ])

        history_item = tx_pb.HistoryItem(
            transaction_id=model_pb.TransactionId(value=b'somehash'),
            cursor=tx_pb.Cursor(value=b'cursor1'),
            solana_transaction=model_pb.Transaction(
                value=tx.marshal(),
            ),
            payments=[
                tx_pb.HistoryItem.Payment(
                    source=model_pb.SolanaAccountId(value=source.raw),
                    destination=model_pb.SolanaAccountId(value=dest.raw),
                    amount=20,
                ),
            ],
        )

        data = TransactionData.from_proto(history_item, tx_pb.GetTransactionResponse.State.SUCCESS)
        assert data.tx_id == b'somehash'
        assert data.transaction_state == TransactionState.SUCCESS
        assert len(data.payments) == 1

        payment = data.payments[0]
        assert payment.sender.raw == source.raw
        assert payment.destination.raw == dest.raw
        assert payment.tx_type == TransactionType.UNKNOWN
        assert payment.quarks == 20
        assert not payment.invoice
        assert payment.memo == 'somememo'

    def test_from_proto_solana_agora_memo(self):
        acc1, acc2, token_program = [key.public_key for key in generate_keys(3)]
        il = model_pb_v3.InvoiceList(invoices=[
            model_pb_v3.Invoice(
                items=[
                    model_pb_v3.Invoice.LineItem(title='t1', amount=10),
                ]
            ),
            model_pb_v3.Invoice(
                items=[
                    model_pb_v3.Invoice.LineItem(title='t1', amount=15),
                ]
            ),
        ])
        fk = InvoiceList.from_proto(il).get_sha_224_hash()
        agora_memo = AgoraMemo.new(1, TransactionType.P2P, 0, fk)

        tx = Transaction.new(PrivateKey.random().public_key, [
            memo_instruction(base64.b64encode(agora_memo.val).decode('utf-8')),
            transfer(acc1, acc2, PrivateKey.random().public_key, 10),
            transfer(acc2, acc1, PrivateKey.random().public_key, 15),
        ])

        history_item = tx_pb.HistoryItem(
            transaction_id=model_pb.TransactionId(value=b'somehash'),
            cursor=tx_pb.Cursor(value=b'cursor1'),
            solana_transaction=model_pb.Transaction(
                value=tx.marshal(),
            ),
            payments=[
                tx_pb.HistoryItem.Payment(
                    source=model_pb.SolanaAccountId(value=acc1.raw),
                    destination=model_pb.SolanaAccountId(value=acc2.raw),
                    amount=10,
                ),
                tx_pb.HistoryItem.Payment(
                    source=model_pb.SolanaAccountId(value=acc2.raw),
                    destination=model_pb.SolanaAccountId(value=acc1.raw),
                    amount=15,
                ),
            ],
            invoice_list=il,
        )

        data = TransactionData.from_proto(history_item, tx_pb.GetTransactionResponse.State.SUCCESS)
        assert data.tx_id == b'somehash'
        assert data.transaction_state == TransactionState.SUCCESS
        assert len(data.payments) == 2

        payment1 = data.payments[0]
        assert payment1.sender.raw == acc1.raw
        assert payment1.destination.raw == acc2.raw
        assert payment1.tx_type == TransactionType.P2P
        assert payment1.quarks == 10
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        payment2 = data.payments[1]
        assert payment2.sender.raw == acc2.raw
        assert payment2.destination.raw == acc1.raw
        assert payment2.tx_type == TransactionType.P2P
        assert payment2.quarks == 15
        assert (payment2.invoice.to_proto().SerializeToString() == il.invoices[1].SerializeToString())
        assert not payment2.memo
