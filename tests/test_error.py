import pytest
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora.error import AccountExistsError, BadNonceError, DestinationDoesNotExistError, InsufficientBalanceError, \
    InsufficientFeeError, InvalidSignatureError, SenderDoesNotExistError, TransactionMalformedError, \
    InvoiceErrorReason, Error, TransactionErrors
from tests.utils import gen_create_op_result, gen_payment_op_result, gen_merge_op_result, gen_result_xdr


class TestExceptions:
    @pytest.mark.parametrize(
        "proto_invoice_reason, expected",
        [
            (tx_pb.SubmitTransactionResponse.InvoiceError.Reason.ALREADY_PAID,
             InvoiceErrorReason.ALREADY_PAID),
            (tx_pb.SubmitTransactionResponse.InvoiceError.Reason.WRONG_DESTINATION,
             InvoiceErrorReason.WRONG_DESTINATION),
            (tx_pb.SubmitTransactionResponse.InvoiceError.Reason.SKU_NOT_FOUND,
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
