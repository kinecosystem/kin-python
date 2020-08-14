from enum import IntEnum
from typing import List, Optional

from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base import stellarxdr
from kin_base.stellarxdr import StellarXDR_const


class Error(Exception):
    """Base error for Agora SDK errors.
    """


class UnsupportedVersionError(Error):
    """Raised when an unsupported version of Kin is used
    """


class AccountExistsError(Error):
    """Raised when trying to create an account that already exists.
    """


class AccountNotFoundError(Error):
    """Raised when an account could not be found.
    """


class SenderDoesNotExistError(Error):
    """Raised when the source account of a transaction does not exist.
    """


class DestinationDoesNotExistError(Error):
    """Raised when the destination account of a transaction does not exis.
    """


class TransactionMalformedError(Error):
    """Raised when the provided transaction was malformed in some way.
    """


class TransactionNotFound(Error):
    """Raised when no transaction data for a specified transaction could be found.
    """


class InvalidSignatureError(Error):
    """Raised when the submitted transaction is either missing signatures or
    contains unused ones.
    """


class InsufficientBalanceError(Error):
    """Raised when an account has an insufficient balance for a submitted
    transaction.
    """


class InsufficientFeeError(Error):
    """Raised when the provided fee for a transaction was insufficient.
    """


class BadNonceError(Error):
    """Raised when a transaction contains an invalid nonce."""


class WebhookRequestError(Error):
    """Should be raised to return an error to Agora from a webhook.

    :param status_code: The status code to respond with.
    :param response_body: The response body to respond with.
    """

    def __init__(self, status_code: int, *args, response_body: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self.status_code = status_code
        self.response_body = response_body


class InvoiceErrorReason(IntEnum):
    UNKNOWN = 0
    ALREADY_PAID = 1
    WRONG_DESTINATION = 2
    SKU_NOT_FOUND = 3

    @classmethod
    def from_proto(
        cls, proto: tx_pb.SubmitTransactionResponse.InvoiceError.Reason
    ) -> 'InvoiceErrorReason':
        if proto == tx_pb.SubmitTransactionResponse.InvoiceError.Reason.ALREADY_PAID:
            return cls.ALREADY_PAID

        if proto == tx_pb.SubmitTransactionResponse.InvoiceError.Reason.WRONG_DESTINATION:
            return cls.WRONG_DESTINATION

        if proto == tx_pb.SubmitTransactionResponse.InvoiceError.Reason.SKU_NOT_FOUND:
            return cls.SKU_NOT_FOUND

        return cls.UNKNOWN

    def to_lowercase(self):
        return self.name.lower()


class OperationInvoiceError(Error):
    def __init__(self, op_index: int, reason: InvoiceErrorReason, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.op_index = op_index
        self.reason = reason

    def to_json(self) -> dict:
        return {
            'operation_index': self.op_index,
            'reason': self.reason.to_lowercase()
        }


class AlreadyPaidError(Error):
    """Raised when an invoice has already been paid.
    """


class WrongDestinationError(Error):
    """Raised when a transaction was rejected by the app webhook for having a wrong destination.
    """


class SkuNotFoundError(Error):
    """Raised when an invoice contains a SKU that could not be found.
    """


class TransactionRejectedError(Error):
    """Raised when the submitted transaction was rejected by a configured webhook.
    """


class InvoiceError(Error):
    """Raised when there was an issue with a provided invoice.
    """

    def __init__(self, errors: List[OperationInvoiceError], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors = errors


class TransactionErrors:
    """Contains the details of a failed transaction.

    :param tx_error: (optional) A :class:`Error <Error>` object. If present, the transaction failed. Otherwise, it was
        successful.
    :param op_errors: (optional) A list of optional :class:`Error <Error>` objects. Each error corresponds to an
        operation in the submitted transaction. If present, the length of this list will match the number of operations
        submitted. If the value corresponding to a specific operation is None, it does not indicate that the operation
        succeeded, only that it was not the reason that the transaction failed.
    """

    def __init__(self, *args, tx_error: Optional[Error] = None, op_errors: Optional[List[Optional[Error]]] = None,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.tx_error = tx_error
        self.op_errors = op_errors if op_errors else []

    @staticmethod
    def from_result(result_xdr: bytes) -> Optional['TransactionErrors']:
        """Returns a :class:`TransactionResultErrors <TransactionResultErrors>` object from a base64-encoded transaction
        result XDR from Agora.

        :param result_xdr: A decoded transaction result XDR, in bytes.
        :return: a :class:`Error <Error>` object or None
        """
        unpacker = stellarxdr.Xdr.StellarXDRUnpacker(result_xdr)
        result = unpacker.unpack_TransactionResult()
        tx_code = result.result.code

        if tx_code == StellarXDR_const.txSUCCESS:
            return None

        if tx_code == StellarXDR_const.txFAILED:
            op_errors = []

            for op_result in result.result.results:
                if op_result.tr.type == StellarXDR_const.CREATE_ACCOUNT:
                    op_code = op_result.tr.createAccountResult.code
                    if op_code == StellarXDR_const.CREATE_ACCOUNT_SUCCESS:
                        op_errors.append(None)
                    elif op_code == StellarXDR_const.CREATE_ACCOUNT_MALFORMED:
                        op_errors.append(TransactionMalformedError())
                    elif op_code == StellarXDR_const.CREATE_ACCOUNT_UNDERFUNDED:
                        op_errors.append(InsufficientBalanceError())
                    elif op_code == StellarXDR_const.CREATE_ACCOUNT_ALREADY_EXIST:
                        op_errors.append(AccountExistsError())
                    else:
                        op_errors.append(Error("create account op failed with code: {}".format(op_code)))

                elif op_result.tr.type == StellarXDR_const.PAYMENT:
                    op_code = op_result.tr.paymentResult.code
                    if op_code == StellarXDR_const.PAYMENT_SUCCESS:
                        op_errors.append(None)
                    elif op_code == StellarXDR_const.PAYMENT_MALFORMED:
                        op_errors.append(TransactionMalformedError())
                    elif op_code == StellarXDR_const.PAYMENT_UNDERFUNDED:
                        op_errors.append(InsufficientBalanceError())
                    elif op_code == StellarXDR_const.PAYMENT_SRC_NOT_AUTHORIZED:
                        op_errors.append(InvalidSignatureError())
                    elif op_code == StellarXDR_const.PAYMENT_NO_DESTINATION:
                        op_errors.append(DestinationDoesNotExistError())
                    else:
                        op_errors.append(Error("payment op failed with code: {}".format(op_code)))

                else:
                    op_errors.append(Error("op of type {} failed".format(op_result.tr.type)))

            return TransactionErrors(tx_error=Error("transaction failed"), op_errors=op_errors)

        if tx_code == StellarXDR_const.txMISSING_OPERATION:
            return TransactionErrors(tx_error=TransactionMalformedError("the transaction has no operations"))

        if tx_code == StellarXDR_const.txBAD_SEQ:
            return TransactionErrors(tx_error=BadNonceError())

        if tx_code == StellarXDR_const.txBAD_AUTH:
            return TransactionErrors(tx_error=InvalidSignatureError("missing signature or wrong network"))

        if tx_code == StellarXDR_const.txINSUFFICIENT_BALANCE:
            return TransactionErrors(tx_error=InsufficientBalanceError())

        if tx_code == StellarXDR_const.txNO_ACCOUNT:
            return TransactionErrors(tx_error=SenderDoesNotExistError())

        if tx_code == StellarXDR_const.txINSUFFICIENT_FEE:
            return TransactionErrors(tx_error=InsufficientFeeError())

        if tx_code == StellarXDR_const.txBAD_AUTH_EXTRA:
            return TransactionErrors(tx_error=InvalidSignatureError("unused signature attached"))

        return TransactionErrors(tx_error=Error("unknown result code: {}".format(tx_code)))
