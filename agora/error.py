from enum import IntEnum
from typing import List, Optional

from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.common.v4 import model_pb2 as model_pb_v4
from kin_base import stellarxdr
from kin_base.stellarxdr import StellarXDR_const


class Error(Exception):
    """Base error for Agora SDK errors.
    """

    def __repr__(self):
        return f'{self.__class__.__name__}({", ".join([f"{k}={v}" for k, v in self.__dict__.items()])})'

    def __str__(self):
        return repr(self)


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


class TransactionNotFoundError(Error):
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

    def __init__(self, status_code: int, response_body: str = ""):
        super().__init__()
        self.status_code = status_code
        self.response_body = response_body


class InvoiceErrorReason(IntEnum):
    UNKNOWN = 0
    ALREADY_PAID = 1
    WRONG_DESTINATION = 2
    SKU_NOT_FOUND = 3

    @classmethod
    def from_proto(
        cls, proto: model_pb.InvoiceError.Reason
    ) -> 'InvoiceErrorReason':
        if proto == model_pb.InvoiceError.Reason.ALREADY_PAID:
            return cls.ALREADY_PAID

        if proto == model_pb.InvoiceError.Reason.WRONG_DESTINATION:
            return cls.WRONG_DESTINATION

        if proto == model_pb.InvoiceError.Reason.SKU_NOT_FOUND:
            return cls.SKU_NOT_FOUND

        return cls.UNKNOWN

    def to_lowercase(self):
        return self.name.lower()


class OperationInvoiceError(Error):
    def __init__(self, op_index: int, reason: InvoiceErrorReason):
        super().__init__()
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


class BlockchainVersionError(Error):
    """Raised when Agora indicates that the current blockchain version is not supported.
    """


class InvoiceError(Error):
    """Raised when there was an issue with a provided invoice.
    """

    def __init__(self, errors: List[OperationInvoiceError], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors = errors


class PayerRequiredError(Error):
    """Raised when a transaction is missing a signature from its funder. This can occur if the service does not have a
    subsidizer configured, or if it refuses to subsidize this specific transaction. The latter case can occur during
    rate limiting situations. In this case, the client may either try at a later time, or attempt to fund the
    transaction using a different account."""


class NoSubsidizerError(Error):
    """Raised when no subsidizer was provided for a transaction. This occurs if no subsidizer was made available by the
    Agora service and none was provided by the method caller."""


class AlreadySubmittedError(Error):
    """Indicates that the transaction was already submitted.

    If the client is retrying a submission due to a transient failure, then this can occur if the submission in a
    previous attempt was successful. Otherwise, it may indicate that the transaction is indistinguishable from a
    previous transaction (i.e. same block hash, sender, dest, and amount), and the client should use a different recent
    blockhash and try again.
    """


class NoTokenAccountsError(Error):
    """Indicates that no token accounts were resolved for the requested account ID.
    """


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
                        op_errors.append(Error(f'create account op failed with code: {op_code}'))

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
                        op_errors.append(Error(f'payment op failed with code: {op_code}'))

                else:
                    op_errors.append(Error(f'op of type {op_result.tr.type} failed'))

            return TransactionErrors(tx_error=Error('transaction failed'), op_errors=op_errors)

        if tx_code == StellarXDR_const.txMISSING_OPERATION:
            return TransactionErrors(tx_error=TransactionMalformedError('the transaction has no operations'))

        if tx_code == StellarXDR_const.txBAD_SEQ:
            return TransactionErrors(tx_error=BadNonceError())

        if tx_code == StellarXDR_const.txBAD_AUTH:
            return TransactionErrors(tx_error=InvalidSignatureError('missing signature or wrong network'))

        if tx_code == StellarXDR_const.txINSUFFICIENT_BALANCE:
            return TransactionErrors(tx_error=InsufficientBalanceError())

        if tx_code == StellarXDR_const.txNO_ACCOUNT:
            return TransactionErrors(tx_error=SenderDoesNotExistError())

        if tx_code == StellarXDR_const.txINSUFFICIENT_FEE:
            return TransactionErrors(tx_error=InsufficientFeeError())

        if tx_code == StellarXDR_const.txBAD_AUTH_EXTRA:
            return TransactionErrors(tx_error=InvalidSignatureError('unused signature attached'))

        return TransactionErrors(tx_error=Error(f'unknown result code: {tx_code}'))

    @staticmethod
    def from_proto_error(tx_error: model_pb_v4.TransactionError) -> Optional['TransactionErrors']:
        if tx_error.reason == model_pb_v4.TransactionError.NONE:
            return None
        if tx_error.reason == model_pb_v4.TransactionError.UNAUTHORIZED:
            return TransactionErrors(tx_error=InvalidSignatureError('missing signature'))
        if tx_error.reason == model_pb_v4.TransactionError.BAD_NONCE:
            return TransactionErrors(tx_error=BadNonceError())
        if tx_error.reason == model_pb_v4.TransactionError.INSUFFICIENT_FUNDS:
            return TransactionErrors(tx_error=InsufficientBalanceError())
        if tx_error.reason == model_pb_v4.TransactionError.INVALID_ACCOUNT:
            return TransactionErrors(tx_error=AccountNotFoundError())
        return TransactionErrors(tx_error=Error(f'unknown error: {tx_error}'))
