import base64

import pytest
from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.common.v4 import model_pb2 as model_pbv4
from kin_base import transaction_envelope as te
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora import solana
from agora.error import AccountExistsError, BadNonceError, DestinationDoesNotExistError, InsufficientBalanceError, \
    InsufficientFeeError, InvalidSignatureError, SenderDoesNotExistError, TransactionMalformedError, \
    InvoiceErrorReason, Error, TransactionErrors, AccountNotFoundError, error_from_proto, AlreadyPaidError, \
    SkuNotFoundError, WrongDestinationError, invoice_error_from_proto
from agora.model import TransactionType, AgoraMemo
from agora.solana import memo, token
from tests.utils import gen_create_op_result, gen_payment_op_result, gen_merge_op_result, gen_result_xdr, generate_keys, \
    gen_account_id, gen_payment_op, gen_tx_envelope_xdr, gen_create_op, gen_hash_memo


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
    def test_from_result_success(self):
        op_result = gen_create_op_result(xdr_const.CREATE_ACCOUNT_SUCCESS)
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [op_result] if op_result else [])
        assert not TransactionErrors.from_result(result_xdr)

    @pytest.mark.parametrize(
        "tx_result_code, op_type, op_result_code, op_error_type",
        [
            # tx with failed result code with create account op failures
            (xdr_const.txFAILED, xdr_const.CREATE_ACCOUNT, xdr_const.CREATE_ACCOUNT_SUCCESS, type(None)),
            (xdr_const.txFAILED, xdr_const.CREATE_ACCOUNT, xdr_const.CREATE_ACCOUNT_MALFORMED,
             TransactionMalformedError),
            (xdr_const.txFAILED, xdr_const.CREATE_ACCOUNT, xdr_const.CREATE_ACCOUNT_UNDERFUNDED,
             InsufficientBalanceError),
            (xdr_const.txFAILED, xdr_const.CREATE_ACCOUNT, xdr_const.CREATE_ACCOUNT_ALREADY_EXIST, AccountExistsError),
            (xdr_const.txFAILED, xdr_const.CREATE_ACCOUNT, xdr_const.CREATE_ACCOUNT_LOW_RESERVE, Error),
            # tx with failed result code with payment op failures
            (xdr_const.txFAILED, xdr_const.PAYMENT, xdr_const.PAYMENT_SUCCESS, type(None)),
            (xdr_const.txFAILED, xdr_const.PAYMENT, xdr_const.PAYMENT_MALFORMED, TransactionMalformedError),
            (xdr_const.txFAILED, xdr_const.PAYMENT, xdr_const.PAYMENT_UNDERFUNDED, InsufficientBalanceError),
            (xdr_const.txFAILED, xdr_const.PAYMENT, xdr_const.PAYMENT_SRC_NOT_AUTHORIZED, InvalidSignatureError),
            (xdr_const.txFAILED, xdr_const.PAYMENT, xdr_const.PAYMENT_NO_DESTINATION, DestinationDoesNotExistError),
            (xdr_const.txFAILED, xdr_const.PAYMENT, xdr_const.PAYMENT_SRC_NO_TRUST, Error),
        ],
    )
    def test_from_result_tx_failed(
        self, tx_result_code: int, op_type: int, op_result_code: int, op_error_type: type
    ):
        """ Tests conversion of error types with transaction results containing only one operation result.
        """
        if op_type == xdr_const.CREATE_ACCOUNT:
            op_result = gen_create_op_result(op_result_code)
        elif op_type == xdr_const.PAYMENT:
            op_result = gen_payment_op_result(op_result_code)
        else:
            raise ValueError('invalid op_type')

        result_xdr = gen_result_xdr(tx_result_code, [op_result] if op_result else [])

        te = TransactionErrors.from_result(result_xdr)
        assert isinstance(te.tx_error, Error)
        assert isinstance(te.op_errors[0], op_error_type)

    @pytest.mark.parametrize(
        "tx_result_code, exception_type",
        [
            (xdr_const.txMISSING_OPERATION, TransactionMalformedError),
            (xdr_const.txBAD_SEQ, BadNonceError),
            (xdr_const.txBAD_AUTH, InvalidSignatureError),
            (xdr_const.txINSUFFICIENT_BALANCE, InsufficientBalanceError),
            (xdr_const.txNO_ACCOUNT, SenderDoesNotExistError),
            (xdr_const.txINSUFFICIENT_FEE, InsufficientFeeError),
            (xdr_const.txBAD_AUTH_EXTRA, InvalidSignatureError),
            (xdr_const.txTOO_EARLY, Error),
            (xdr_const.txTOO_LATE, Error),
            (xdr_const.txINTERNAL_ERROR, Error),
        ]
    )
    def test_error_from_result_no_op(
        self, tx_result_code: int, exception_type: type
    ):
        result_xdr = gen_result_xdr(tx_result_code, [])
        assert isinstance(TransactionErrors.from_result(result_xdr).tx_error, exception_type)

    def test_error_from_result_other_op(self):
        op_result = gen_merge_op_result(xdr_const.ACCOUNT_MERGE_MALFORMED)
        result_xdr = gen_result_xdr(xdr_const.txFAILED, [op_result])

        te = TransactionErrors.from_result(result_xdr)
        assert isinstance(te.tx_error, Error)
        assert isinstance(te.op_errors[0], Error)

    def test_error_from_result_multi_op(self):
        op_results = [
            gen_create_op_result(xdr_const.CREATE_ACCOUNT_SUCCESS),
            gen_create_op_result(xdr_const.CREATE_ACCOUNT_MALFORMED),
            gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED),
        ]

        result_xdr = gen_result_xdr(xdr_const.txFAILED, op_results)

        te = TransactionErrors.from_result(result_xdr)
        assert isinstance(te.tx_error, Error)
        assert not te.op_errors[0]
        assert isinstance(te.op_errors[1], TransactionMalformedError)
        assert isinstance(te.op_errors[2], InsufficientBalanceError)

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
        e = error_from_proto(model_pbv4.TransactionError(reason=reason))
        assert isinstance(e, exception_type)

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
                token.transfer(keys[1], keys[2], keys[1], 100, keys[3]),
                token.set_authority(keys[1], keys[1], token.AuthorityType.CloseAccount, keys[3], keys[2])
            ]
        )

        errors = TransactionErrors.from_solana_tx(tx, model_pbv4.TransactionError(
            reason=model_pbv4.TransactionError.Reason.INSUFFICIENT_FUNDS,
            instruction_index=instruction_index,
        ))
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
        ))
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
