from enum import IntEnum
from typing import List, Optional

from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.common.v4 import model_pb2 as model_pb_v4
from kin_base import transaction_envelope as te, operation

from agora import solana
from agora.solana import decompile_transfer


class Error(Exception):
    """Base error for Agora SDK errors.
    """

    def __init__(self, message: Optional[str] = ''):
        self.message = message
        super().__init__(self.message)


class TransactionError(Error):
    """Base error for transaction submission errors.

    :param tx_id: The id of the transaction, if available.
    """

    def __init__(self, message: Optional[str] = '', tx_id: Optional[bytes] = None):
        super().__init__(message)
        self.tx_id = tx_id


class UnsupportedVersionError(Error):
    """Raised when an unsupported version of Kin is used
    """


class UnsupportedMethodError(Error):
    """Raised when a method is not supported in the current environment.
    """


class AccountExistsError(Error):
    """Raised when trying to create an account that already exists.
    """


class TransactionNotFoundError(Error):
    """Raised when no transaction data for a specified transaction could be found.
    """


class AccountNotFoundError(TransactionError):
    """Raised when an account could not be found.
    """


class InvalidSignatureError(TransactionError):
    """Raised when the submitted transaction is either missing signatures or
    contains unused ones.
    """


class InsufficientBalanceError(TransactionError):
    """Raised when an account has an insufficient balance for a submitted
    transaction.
    """


class BadNonceError(TransactionError):
    """Raised when a transaction contains an invalid nonce."""


class AlreadySubmittedError(TransactionError):
    """Indicates that the transaction was already submitted.

    If the client is retrying a submission due to a transient failure, then this can occur if the submission in a
    previous attempt was successful. Otherwise, it may indicate that the transaction is indistinguishable from a
    previous transaction (i.e. same block hash, sender, dest, and amount), and the client should use a different recent
    blockhash and try again.
    """


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

    def __init__(self, tx_error: Optional[Error] = None, op_errors: Optional[List[Optional[Error]]] = None,
                 payment_errors: Optional[List[Optional[Error]]] = None):
        self.tx_error = tx_error
        self.op_errors = op_errors if op_errors else []
        self.payment_errors = payment_errors if payment_errors else []

    @staticmethod
    def from_solana_tx(
        tx: solana.Transaction, tx_error: model_pb_v4.TransactionError, tx_id: bytes
    ) -> Optional['TransactionErrors']:
        err = error_from_proto(tx_error, tx_id)
        if not err:
            return None

        errors = TransactionErrors(err)
        if tx_error.instruction_index >= 0:
            errors.op_errors = [None] * len(tx.message.instructions)
            errors.op_errors[tx_error.instruction_index] = err

            paymentIndex = tx_error.instruction_index
            paymentCount = 0

            for idx, instruction in enumerate(tx.message.instructions):
                try:
                    decompile_transfer(tx.message, idx)
                    paymentCount += 1
                except ValueError:
                    if idx < tx_error.instruction_index:
                        paymentIndex -= 1
                    elif idx == tx_error.instruction_index:
                        paymentIndex = -1

            if paymentIndex > -1:
                errors.payment_errors = [None] * paymentCount
                errors.payment_errors[paymentIndex] = err

        return errors

    @staticmethod
    def from_stellar_tx(env: te.TransactionEnvelope, tx_error: model_pb_v4.TransactionError, tx_id: bytes) -> Optional[
        'TransactionErrors']:
        err = error_from_proto(tx_error, tx_id)
        if not err:
            return None

        errors = TransactionErrors(err)
        if tx_error.instruction_index >= 0:
            errors.op_errors = [None] * len(env.tx.operations)
            errors.op_errors[tx_error.instruction_index] = err

            paymentIndex = tx_error.instruction_index
            paymentCount = 0

            for idx, op in enumerate(env.tx.operations):
                if isinstance(op, operation.Payment):
                    paymentCount += 1
                elif idx < tx_error.instruction_index:
                    paymentIndex -= 1
                elif idx == tx_error.instruction_index:
                    paymentIndex = -1

            if paymentIndex > -1:
                errors.payment_errors = [None] * paymentCount
                errors.payment_errors[paymentIndex] = err

        return errors


def error_from_proto(tx_error: model_pb_v4.TransactionError, tx_id: bytes) -> Optional[Error]:
    if tx_error.reason == model_pb_v4.TransactionError.NONE:
        return None
    if tx_error.reason == model_pb_v4.TransactionError.UNAUTHORIZED:
        return InvalidSignatureError(tx_id=tx_id)
    if tx_error.reason == model_pb_v4.TransactionError.BAD_NONCE:
        return BadNonceError(tx_id=tx_id)
    if tx_error.reason == model_pb_v4.TransactionError.INSUFFICIENT_FUNDS:
        return InsufficientBalanceError(tx_id=tx_id)
    if tx_error.reason == model_pb_v4.TransactionError.INVALID_ACCOUNT:
        return AccountNotFoundError(tx_id=tx_id)
    return Error(f'unknown tx error reason: {tx_error.reason}')


def invoice_error_from_proto(invoice_error: model_pb.InvoiceError) -> Error:
    if invoice_error.reason == model_pb.InvoiceError.Reason.ALREADY_PAID:
        return AlreadyPaidError()
    if invoice_error.reason == model_pb.InvoiceError.Reason.WRONG_DESTINATION:
        return WrongDestinationError()
    if invoice_error.reason == model_pb.InvoiceError.Reason.SKU_NOT_FOUND:
        return SkuNotFoundError()

    return Error(f'unknown invoice error reason: {invoice_error.reason}')
