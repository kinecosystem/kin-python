import asyncio
import base64
from typing import List, Optional

import grpc
import kin_base
from agoraapi.account.v3 import account_service_pb2 as account_pb, account_service_pb2_grpc as account_pb_grpc
from agoraapi.common.v3 import model_pb2
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb, transaction_service_pb2_grpc as tx_pb_grpc

from agora.client.environment import Environment
from agora.error import AccountExistsError, AccountNotFoundError, InvoiceError, InvoiceErrorReason, \
    UnsupportedVersionError, TransactionMalformedError, SenderDoesNotExistError, InsufficientBalanceError, \
    DestinationDoesNotExistError, InsufficientFeeError, BadNonceError, \
    TransactionRejectedError, TransactionErrors, TransactionNotFound, Error, AlreadyPaidError, \
    WrongDestinationError, SkuNotFoundError
from agora.model.earn import Earn
from agora.model.invoice import InvoiceList
from agora.model.keys import PrivateKey, PublicKey
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.result import BatchEarnResult, EarnResult
from agora.model.transaction import TransactionData
from agora.model.transaction_type import TransactionType
from agora.retry import retry, LimitStrategy, BackoffWithJitterStrategy, BinaryExponentialBackoff, \
    NonRetriableErrorsStrategy, RetriableErrorsStrategy
from agora.utils import partition, quarks_to_kin

_SUPPORTED_VERSIONS = [3]

_ENDPOINTS = {
    Environment.PRODUCTION: "api.agorainfra.net:443",
    Environment.TEST: "api.agorainfra.dev:443"
}

_NETWORK_NAMES = {
    Environment.PRODUCTION: "PUBLIC",
    Environment.TEST: "TESTNET",
}

_NON_RETRIABLE_ERRORS = [
    AccountExistsError,
    TransactionMalformedError,
    SenderDoesNotExistError,
    DestinationDoesNotExistError,
    InsufficientBalanceError,
    InsufficientFeeError,
    TransactionRejectedError,
    InvoiceError,
    BadNonceError,
]

_GRPC_TIMEOUT_SECONDS = 10


class RetryConfig:
    """A :class:`RetryConfig <RetryConfig>` for configuring retries for Agora requests.

    :param max_retries: (optional) The max number of times the client will retry a request, excluding the initial
        attempt. Defaults to 5 if value is not provided or value is below 0.
    :param max_nonce_refreshes: (optional) The max number of times the client will attempt to refresh a nonce, excluding
        the initial attempt. Defaults to 3 if value is not provided or value is below 0.
    :param min_delay: (optional) The minimum amount of time to delay between request retries, in seconds. Defaults to
        0.5 seconds if value is not provided or value is below 0.
    :param min_delay: (optional) The maximum amount of time to delay between request retries, in seconds. Defaults to
        5 seconds if value is not provided or value is below 0.
    """

    def __init__(
        self, max_retries: Optional[int] = None, min_delay: Optional[float] = None, max_delay: Optional[float] = None,
        max_nonce_refreshes: Optional[int] = None,
    ):
        self.max_retries = max_retries if max_retries is not None and max_retries >= 0 else 5
        self.min_delay = min_delay if min_delay is not None and min_delay >= 0 else 0.5
        self.max_delay = max_delay if max_delay is not None and max_delay >= 0 else 10
        self.max_nonce_refreshes = (max_nonce_refreshes if max_nonce_refreshes is not None and max_nonce_refreshes >= 0
                                    else 3)


class BaseClient:
    """An interface for accessing Agora features.
    """

    def create_account(self, private_key: PrivateKey):
        """Creates a new Kin account.

        :param private_key: The :class:`PrivateKey <agora.model.keys.PrivateKey` of the account to create
        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`AccountExistsError <agora.error.AccountExistsError>`
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement create_account")

    def get_transaction(self, tx_hash: bytes) -> TransactionData:
        """Retrieves a transaction.

        :param tx_hash: The hash of the transaction to retrieve
        :return: a :class:`TransactionData <agora.model.transaction.TransactionData>` object.
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement get_transaction")

    def get_balance(self, public_key: PublicKey) -> int:
        """Retrieves the balance of an account.

        :param public_key: The :class:`PublicKey <agora.model.keys.PublicKey` of the account to retrieve the balance for.
        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`AccountNotFoundError <agora.error.AccountNotFoundError>`
        :return: The balance of the account, in quarks.
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement get_balance")

    def submit_payment(self, payment: Payment) -> bytes:
        """Submits a payment to the Kin blockchain.

        :param payment: The :class:`Payment <agora.model.payment.Payment>` to submit.

        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`TransactionMalformedError <agora.error.TransactionMalformedError>`
        :raise: :exc:`InvalidSignatureError <agora.error.InvalidSignatureError>`
        :raise: :exc:`InsufficientBalanceError <agora.error.InsufficientBalanceError>`
        :raise: :exc:`InsufficientFeeError <agora.error.InsufficientFeeError>`
        :raise: :exc:`SenderDoesNotExistError <agora.error.SenderDoesNotExistError>`
        :raise: :exc:`DestinationDoesNotExistError <agora.error.DestinationDoesNotExistError>`
        :raise: :exc:`BadNonceError <agora.error.BadNonceError>`
        :raise: :exc:`TransactionError <agora.error.TransactionError>`
        :raise: :exc:`InvoiceError <agora.error.InvoiceError>`

        :return: The hash of the transaction.
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement submit_payment")

    def submit_earn_batch(
        self, sender: PrivateKey, earns: List[Earn], channel: Optional[PrivateKey] = None, memo: Optional[str] = None
    ) -> BatchEarnResult:
        """Submit multiple earn payments.

        :param sender: The :class:`PrivateKey <agora.model.keys.PrivateKey` of the sender
        :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
        :param channel: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey` of a channel account to use as
            the transaction source. If not set, the `sender` will be used as the source.
        :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
            will be applied.

        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`

        :return: a :class:`BatchEarnResult <agora.model.result.BatchEarnResult>`
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement submit_earn_batch")

    def close(self) -> None:
        """Closes the connection-related resources (e.g. the gRPC channel) used by the client. Subsequent requests to
        this client will cause an exception to be thrown.
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement close")


class SubmitStellarTransactionResult:
    def __init__(self, tx_hash: Optional[bytes] = None,
                 invoice_errors: Optional[List[tx_pb.SubmitTransactionResponse.InvoiceError]] = None,
                 tx_error: Optional[TransactionErrors] = None):
        self.tx_hash = tx_hash if tx_hash else bytes(32)
        self.invoice_errors = invoice_errors if invoice_errors else []
        self.tx_error = tx_error


class Client(BaseClient):
    """A :class:`Client <Client>` object for accessing Agora API features.

    :param env: The :class:`Environment <agora.environment.Environment>` to use.
    :param app_index: (optional) The Agora index of the app, used for all transactions and requests. Required to make
        use of invoices.
    :param whitelist_key: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey` of the account to whitelist
        submitted transactions with.
    :param grpc_channel: (optional) A GRPC :class:`Channel <grpc.Channel>` object to use for Agora requests. Only one of
        grpc_channel or endpoint should be set.
    :param endpoint: (optional) An endpoint to use instead of the default Agora endpoints. Only one of grpc_channel or
        endpoint should be set.
    :param retry_config: (optional): A :class:`RetryConfig <RetryConfig>` object to configure Agora retries. If not
        provided, a default configuration will be used.
    """

    def __init__(
        self, env: Environment, app_index: int = 0, whitelist_key: Optional[PrivateKey] = None,
        grpc_channel: Optional[grpc.Channel] = None, endpoint: Optional[str] = None,
        retry_config: Optional[RetryConfig] = None,
    ):
        self.network_name = _NETWORK_NAMES[env]
        self.app_index = app_index

        if grpc_channel and endpoint:
            raise ValueError("grpc_channel and endpoint cannot both be set")

        if not grpc_channel:
            endpoint = endpoint if endpoint else _ENDPOINTS[env]
            ssl_credentials = grpc.ssl_channel_credentials()
            self.grpc_channel = grpc.secure_channel(endpoint, ssl_credentials)
        else:
            self.grpc_channel = grpc_channel

        self.account_stub = account_pb_grpc.AccountStub(self.grpc_channel)
        self.transaction_stub = tx_pb_grpc.TransactionStub(self.grpc_channel)

        self.whitelist_key = whitelist_key

        self.retry_config = retry_config if retry_config else RetryConfig()
        self.retry_strategies = [
            NonRetriableErrorsStrategy(_NON_RETRIABLE_ERRORS),
            LimitStrategy(self.retry_config.max_retries + 1),
            BackoffWithJitterStrategy(BinaryExponentialBackoff(self.retry_config.min_delay),
                                      self.retry_config.max_delay, 0.1),
        ]
        self.nonce_retry_strategies = [
            RetriableErrorsStrategy([BadNonceError]),
            LimitStrategy(self.retry_config.max_nonce_refreshes + 1)
        ]

        self._kin_version = 3

        # This Horizon instance is necessary to use the kin_base.Builder object,
        # but it does not get used to submit transactions
        self._horizon = kin_base.Horizon()

        # Since we don't actually use Horizon for any requests, call `self._horizon.close()` to preemptively ensure that
        # any open aiohttp.ClientSessions get closed.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._horizon.close())

    def create_account(self, private_key: PrivateKey):
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        retry(self.retry_strategies, self._create_stellar_account, private_key=private_key)

    def get_transaction(self, tx_hash: bytes) -> TransactionData:
        resp = self.transaction_stub.GetTransaction(tx_pb.GetTransactionRequest(
            transaction_hash=model_pb2.TransactionHash(
                value=tx_hash
            )
        ), timeout=_GRPC_TIMEOUT_SECONDS)

        if resp.state is tx_pb.GetTransactionResponse.State.UNKNOWN:
            raise TransactionNotFound()
        if resp.state == tx_pb.GetTransactionResponse.State.SUCCESS:
            return TransactionData.from_proto(resp.item)

        raise Error("Unexpected transaction state from Agora: %d", resp.state)

    def get_balance(self, public_key: PublicKey) -> int:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        info = self._get_stellar_account_info(public_key)
        return info.balance

    def submit_payment(self, payment: Payment) -> bytes:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        if payment.invoice and self.app_index <= 0:
            raise ValueError("cannot submit a payment with an invoice without an app index")

        builder = self._get_stellar_builder(payment.channel if payment.channel else payment.sender)

        invoice_list = None
        if payment.memo:
            builder.add_text_memo(payment.memo)
        elif self.app_index > 0:
            if payment.invoice:
                invoice_list = InvoiceList(invoices=[payment.invoice])

            fk = invoice_list.get_sha_224_hash() if payment.invoice else b''
            memo = AgoraMemo.new(1, payment.tx_type, self.app_index, fk)
            builder.add_hash_memo(memo.val)

        builder.append_payment_op(
            payment.destination.stellar_address,
            quarks_to_kin(payment.quarks),
            source=payment.sender.public_key.stellar_address,
        )

        if payment.channel:
            signers = [payment.channel, payment.sender]
        else:
            signers = [payment.sender]

        if self.whitelist_key:
            signers.append(self.whitelist_key)

        result = self._sign_and_submit_builder(signers, builder, invoice_list)
        if result.tx_error:
            if len(result.tx_error.op_errors) > 0:
                if len(result.tx_error.op_errors) != 1:
                    raise Error("invalid number of operation errors, expected 0 or 1, got {}"
                                .format(len(result.tx_error.op_errors)))
                raise result.tx_error.op_errors[0]

            if result.tx_error.tx_error:
                raise result.tx_error.tx_error

        if result.invoice_errors:
            if len(result.invoice_errors) != 1:
                raise Error("invalid number of invoice errors, expected 0 or 1, got {}"
                            .format(len(result.invoice_errors)))

            if result.invoice_errors[0].reason == InvoiceErrorReason.ALREADY_PAID:
                raise AlreadyPaidError()
            if result.invoice_errors[0].reason == InvoiceErrorReason.WRONG_DESTINATION:
                raise WrongDestinationError()
            if result.invoice_errors[0].reason == InvoiceErrorReason.SKU_NOT_FOUND:
                raise SkuNotFoundError()
            raise Error("unknown invoice error: {}".format(result.invoice_errors[0].reason))

        return result.tx_hash

    def submit_earn_batch(
        self, sender: PrivateKey, earns: List[Earn], channel: Optional[bytes] = None, memo: Optional[str] = None
    ) -> BatchEarnResult:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError

        invoices = [earn.invoice for earn in earns if earn.invoice]
        if invoices:
            if self.app_index <= 0:
                raise ValueError("cannot submit a payment with an invoice without an app index")
            if len(invoices) != len(earns):
                raise ValueError("Either all or none of the earns must contain invoices")
            if memo:
                raise ValueError("Cannot use both text memo and invoices")

        succeeded = []
        failed = []
        for earn_batch in partition(earns, 100):
            try:
                result = self._submit_earn_batch_tx(sender, earn_batch, channel, memo)
            except Error as e:
                failed += [EarnResult(earn, error=e) for idx, earn in enumerate(earn_batch)]
                break

            if not result.tx_error:
                succeeded += [EarnResult(earn, tx_hash=result.tx_hash) for earn in earn_batch]
                continue

            # At this point, the batch is considered failed.
            err = result.tx_error

            if err.op_errors:
                failed += [EarnResult(earn, tx_hash=result.tx_hash, error=err.op_errors[idx])
                           for idx, earn in enumerate(earn_batch)]
            else:
                failed += [EarnResult(earn, tx_hash=result.tx_hash, error=err.tx_error)
                           for idx, earn in enumerate(earn_batch)]
            break

        for earn in earns[len(succeeded) + len(failed):]:
            failed.append(EarnResult(earn=earn))

        return BatchEarnResult(succeeded=succeeded, failed=failed)

    def close(self) -> None:
        self.grpc_channel.close()

    def _submit_earn_batch_tx(
        self, sender: PrivateKey, earns: List[Earn], channel: Optional[PrivateKey] = None, memo: Optional[str] = None
    ) -> SubmitStellarTransactionResult:
        """ Submits a single transaction for a batch of earns. An error will be raised if the number of earns exceeds
        the capacity of a single transaction.

        :param sender: The :class:`PrivateKey <agora.model.keys.PrivateKey` of the sender
        :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
        :param channel: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey` of the channel account to use
            as the transaction source. If not set, the sender will be used as the source.
        :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
            will be applied.

        :return: a list of :class:`BatchEarnResult <agora.model.result.EarnResult>` objects
        """
        if len(earns) > 100:
            raise ValueError("cannot send more than 100 earns")

        builder = self._get_stellar_builder(channel if channel else sender)

        invoices = [earn.invoice for earn in earns if earn.invoice]
        invoice_list = InvoiceList(invoices) if invoices else None
        if memo:
            builder.add_text_memo(memo)
        elif self.app_index > 0:
            fk = invoice_list.get_sha_224_hash() if invoice_list else b''
            memo = AgoraMemo.new(1, TransactionType.EARN, self.app_index, fk)
            builder.add_hash_memo(memo.val)

        for earn in earns:
            builder.append_payment_op(
                earn.destination.stellar_address,
                quarks_to_kin(earn.quarks),
                source=sender.public_key.stellar_address,
            )

        if channel:
            signers = [channel, sender]
        else:
            signers = [sender]

        if self.whitelist_key:
            signers.append(self.whitelist_key)

        result = self._sign_and_submit_builder(signers, builder, invoice_list)
        if result.invoice_errors:
            # Invoice errors should not be triggered on earns. This indicates there is something wrong with the service.
            raise Error("unexpected invoice errors present")

        return result

    def _sign_and_submit_builder(
        self, signers: List[PrivateKey], builder: kin_base.Builder, invoice_list: Optional[InvoiceList] = None
    ) -> SubmitStellarTransactionResult:
        source_info = self._get_stellar_account_info(signers[0].public_key)
        offset = 1

        def _sign_and_submit():
            nonlocal offset

            # reset generated tx and te
            builder.tx = None
            builder.te = None

            builder.sequence = source_info.sequence_number + offset
            for signer in signers:
                builder.sign(signer.stellar_seed)

            result = self._submit_stellar_transaction(base64.b64decode(builder.gen_xdr()), invoice_list)
            if result.tx_error and isinstance(result.tx_error.tx_error, BadNonceError):
                offset += 1
                raise result.tx_error.tx_error

            return result

        return retry(self.nonce_retry_strategies, _sign_and_submit)

    def _create_stellar_account(self, private_key: PrivateKey):
        """Submits a request to Agora to create a Stellar account.

        :param private_key: The :class:`PrivateKey <agora.model.keys.PrivateKey` of the account to create.
        """
        resp = self.account_stub.CreateAccount(account_pb.CreateAccountRequest(
            account_id=model_pb2.StellarAccountId(
                value=private_key.public_key.stellar_address
            )
        ), timeout=_GRPC_TIMEOUT_SECONDS)
        if resp.result == account_pb.CreateAccountResponse.Result.EXISTS:
            raise AccountExistsError()

    def _get_stellar_account_info(self, public_key: PublicKey) -> account_pb.AccountInfo:
        """Requests account info from Agora for a Stellar account.

        :param public_key: The :class:`PublicKey <agora.model.keys.PublicKey` of the account to request the info for.
        :return: :class:`StellarAccountInfo <agora.client.stellar.account.AccountInfo>
        """
        resp = self.account_stub.GetAccountInfo(account_pb.GetAccountInfoRequest(
            account_id=model_pb2.StellarAccountId(
                value=public_key.stellar_address
            )
        ), timeout=_GRPC_TIMEOUT_SECONDS)
        if resp.result == account_pb.GetAccountInfoResponse.Result.NOT_FOUND:
            raise AccountNotFoundError

        return resp.account_info

    def _get_stellar_builder(self, source: PrivateKey) -> kin_base.Builder:
        """Returns a Stellar transaction builder.

        :param source: The transaction source account.
        :return: a :class:`Builder` <kin_base.Builder> object.
        """
        return kin_base.Builder(self._horizon, self.network_name,
                                100,
                                source.stellar_seed)

    def _submit_stellar_transaction(
        self, tx_bytes: bytes, invoice_list: Optional[InvoiceList] = None
    ) -> SubmitStellarTransactionResult:
        """Submit a stellar transaction to Agora.
        :param tx_bytes: The transaction envelope xdr, in bytes
        :param invoice_list: (optional) An :class:`InvoiceList <agora.model.invoice.InvoiceList>` to associate with the
            transaction
        :raise: :exc:`TransactionRejectedError <agora.error.TransactionRejectedError>`: if the transaction was rejected
            by the configured app's webhook
        :raise: :exc:`InvoiceError <agora.error.InvoiceError>`: if the transaction failed for a invoice-related reason.
        :raise: :exc:`TransactionError <agora.error.TransactionError>`: if the transaction failed upon submission to the
            blockchain.
        :return: The transaction hash
        """

        def _submit():
            req = tx_pb.SubmitTransactionRequest(
                envelope_xdr=tx_bytes,
                invoice_list=invoice_list.to_proto() if invoice_list else None,
            )
            resp = self.transaction_stub.SubmitTransaction(req, timeout=_GRPC_TIMEOUT_SECONDS)

            result = SubmitStellarTransactionResult(tx_hash=resp.hash.value)
            if resp.result == tx_pb.SubmitTransactionResponse.Result.REJECTED:
                raise TransactionRejectedError()
            elif resp.result == tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR:
                result.invoice_errors = resp.invoice_errors
            elif resp.result == tx_pb.SubmitTransactionResponse.Result.FAILED:
                result.tx_error = TransactionErrors.from_result(resp.result_xdr)
            elif resp.result != tx_pb.SubmitTransactionResponse.Result.OK:
                raise Error("unexpected result from agora: {}".format(resp.result))

            return result

        return retry(self.retry_strategies, _submit)
