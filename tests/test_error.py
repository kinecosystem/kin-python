import base64

import pytest
from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.common.v4 import model_pb2 as model_pbv4
from kin_base import transaction_envelope as te

from agora import solana
from agora.error import BadNonceError, InsufficientBalanceError, \
    InvalidSignatureError, InvoiceErrorReason, Error, TransactionErrors, AccountNotFoundError, error_from_proto, \
    AlreadyPaidError, \
    SkuNotFoundError, WrongDestinationError, invoice_error_from_proto
from agora.model import TransactionType, AgoraMemo
from agora.solana import memo, token
from tests.utils import gen_account_id, gen_payment_op, gen_tx_envelope_xdr, gen_create_op, gen_hash_memo
from tests.utils import generate_keys


class TestExceptions:
    @pytest.mark.parametrize(
        "proto_invoice_reason, expected",
        [
            (model_pb.InvoiceError.Reason.ALREADY_PAID,
             InvoiceErrorReason.ALREADY_PAID),
            (model_pb.InvoiceError.Reason.WRONG_DESTINATION,
             InvoiceErrorReason.WRONG_DESTINATION),
            (model_pb.InvoiceError.Reason.SKU_NOT_FOUND,
             InvoiceErrorReason.SKU_NOT_FOUND),
            (500, InvoiceErrorReason.UNKNOWN)
        ]
    )
    def test_invoice_error_reason_from_proto(
        self, proto_invoice_reason, expected
    ):
        actual = InvoiceErrorReason.from_proto(proto_invoice_reason)
        assert actual == expected


class TestTransactionError:
    @pytest.mark.parametrize(
        "reason, exception_type",
        [
            (model_pbv4.TransactionError.Reason.NONE, type(None)),
            (model_pbv4.TransactionError.Reason.UNAUTHORIZED, InvalidSignatureError),
            (model_pbv4.TransactionError.Reason.BAD_NONCE, BadNonceError),
            (model_pbv4.TransactionError.Reason.INSUFFICIENT_FUNDS, InsufficientBalanceError),
            (model_pbv4.TransactionError.Reason.INVALID_ACCOUNT, AccountNotFoundError),

        ]
    )
    def test_error_from_proto(self, reason, exception_type):
        tx_id = b'tx_sig'
        e = error_from_proto(model_pbv4.TransactionError(reason=reason), tx_id)
        assert isinstance(e, exception_type)
        assert e.tx_id == tx_id

    @pytest.mark.parametrize(
        "reason, exception_type",
        [
            (model_pb.InvoiceError.Reason.UNKNOWN, Error),
            (model_pb.InvoiceError.Reason.ALREADY_PAID, AlreadyPaidError),
            (model_pb.InvoiceError.Reason.WRONG_DESTINATION, WrongDestinationError),
            (model_pb.InvoiceError.Reason.SKU_NOT_FOUND, SkuNotFoundError),
        ]
    )
    def test_error_from_proto(self, reason, exception_type):
        e = invoice_error_from_proto(model_pb.InvoiceError(reason=reason))
        assert isinstance(e, exception_type)

    @pytest.mark.parametrize(
        "instruction_index, exp_op_index, exp_payment_index",
        [
            (1, 1, 0),
            (0, 0, -1),
        ]
    )
    def test_errors_from_solana_tx(self, instruction_index, exp_op_index, exp_payment_index):
        keys = [pk.public_key for pk in generate_keys(4)]
        tx = solana.Transaction.new(
            keys[0],
            [
                memo.memo_instruction('data'),
                token.transfer(keys[1], keys[2], keys[1], 100),
                token.set_authority(keys[1], keys[1], token.AuthorityType.CLOSE_ACCOUNT, keys[3])
            ]
        )
        tx_id = b'tx_sig'

        errors = TransactionErrors.from_solana_tx(tx, model_pbv4.TransactionError(
            reason=model_pbv4.TransactionError.Reason.INSUFFICIENT_FUNDS,
            instruction_index=instruction_index,
        ), tx_id)
        assert isinstance(errors.tx_error, InsufficientBalanceError)
        assert len(errors.op_errors) == 3
        for i in range(0, len(errors.op_errors)):
            if i == exp_op_index:
                assert isinstance(errors.op_errors[i], InsufficientBalanceError)
            else:
                assert not errors.op_errors[i]

        if exp_payment_index > -1:
            assert len(errors.payment_errors) == 1
            for i in range(0, len(errors.payment_errors)):
                if i == exp_payment_index:
                    assert isinstance(errors.payment_errors[i], InsufficientBalanceError)
                else:
                    assert not errors.payment_errors[i]
        else:
            assert not errors.payment_errors

    @pytest.mark.parametrize(
        "instruction_index, exp_op_index, exp_payment_index",
        [
            (2, 2, 1),
            (3, 3, -1),
        ]
    )
    def test_errors_from_stellar_tx(self, instruction_index, exp_op_index, exp_payment_index):
        acc1 = gen_account_id()
        acc2 = gen_account_id()
        operations = [
            gen_create_op(acc1, acc2),
            gen_payment_op(acc2, amount=15),
            gen_payment_op(acc1, amount=15),
            gen_create_op(acc1, acc2),
        ]
        memo = AgoraMemo.new(1, TransactionType.EARN, 1, b'')
        hash_memo = gen_hash_memo(memo.val)
        envelope_xdr = gen_tx_envelope_xdr(acc1, 1, operations, hash_memo)
        env = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))

        errors = TransactionErrors.from_stellar_tx(env, model_pbv4.TransactionError(
            reason=model_pbv4.TransactionError.Reason.INSUFFICIENT_FUNDS,
            instruction_index=instruction_index,
        ), b'tx_hash')
        assert isinstance(errors.tx_error, InsufficientBalanceError)
        assert len(errors.op_errors) == 4
        for i in range(0, len(errors.op_errors)):
            if i == exp_op_index:
                assert isinstance(errors.op_errors[i], InsufficientBalanceError)
            else:
                assert not errors.op_errors[i]

        if exp_payment_index > -1:
            assert len(errors.payment_errors) == 2
            for i in range(0, len(errors.payment_errors)):
                if i == exp_payment_index:
                    assert isinstance(errors.payment_errors[i], InsufficientBalanceError)
                else:
                    assert not errors.payment_errors[i]
        else:
            assert not errors.payment_errors
