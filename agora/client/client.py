import asyncio
import base64
from typing import List, Tuple, Optional

import grpc
import kin_base
from agoraapi.account.v3 import account_service_pb2 as account_pb, account_service_pb2_grpc as account_pb_grpc
from agoraapi.common.v3 import model_pb2
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb, transaction_service_pb2_grpc as tx_pb_grpc

from agora.client.environment import Environment
from agora.client.stellar.account import StellarAccountInfo
from agora.client.stellar.error import StellarTransactionError
from agora.client.utils import public_key_to_address, quarks_to_kin_str
from agora.error import AccountExistsError, AccountNotFoundError, InvoiceError, InvoiceErrorReason, \
    UnsupportedVersionError, TransactionMalformedError, SenderDoesNotExistError, \
    DestinationDoesNotExistError, InsufficientBalanceError, InsufficientFeeError, BadNonceError, OperationInvoiceError, \
    TransactionRejectedError, TransactionResultErrors
from agora.model.earn import Earn
from agora.model.invoice import InvoiceList
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.result import BatchEarnResult, EarnResult, EarnTransactionResult
from agora.model.transaction import TransactionState, TransactionData
from agora.model.transaction_type import TransactionType
from agora.retry import retry, LimitStrategy, BackoffWithJitterStrategy, BinaryExponentialBackoff, \
    NonRetriableErrorsStrategy, RetriableErrorsStrategy, Strategy
from agora.utils import partition

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

_GRPC_TIMEOUT = 10


class RetryConfig(object):
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


class BaseClient(object):
    """An interface for accessing Agora features.
    """

    def create_account(self, private_key: bytes):
        """Creates a new Kin account.
        :param private_key: The private key, in raw bytes, of the account to create
        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`AccountExistsError <agora.error.AccountExistsError>`
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement create_account")

    def get_transaction(self, tx_hash: bytes) -> Tuple[TransactionState, Optional[TransactionData]]:
        """Retrieves a transaction.

        :param tx_hash: The hash of the transaction to retrieve
        :return: a tuple of :class:`TransactionState <agora.transaction.TransactionState>` and
            :class:`TransactionData <agora.transaction.TransactionData>` if transaction data is available.
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement get_transaction")

    def get_balance(self, public_key: bytes) -> int:
        """Retrieves the balance of an account.

        :param public_key: The public key, in raw bytes, of the account to retrieve the balance for.
        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`AccountNotFoundError <agora.error.AccountNotFoundError>`
        :return: The balance of the account, in quarks.
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement get_balance")

    def submit_payment(self, payment: Payment) -> bytes:
        """Submits a payment to the Kin blockchain.

        :param payment: The :class:`Payment <agora.payment.Payment>` to submit.

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
        self, sender: bytes, earns: List[Earn], source: Optional[bytes] = None, memo: Optional[str] = None
    ) -> BatchEarnResult:
        """Submit multiple earn payments.

        :param sender: The private key, in raw bytes, of the sender
        :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
        :param source: (optional) The private key, in raw bytes, of the transaction source account. If not set, the
            sender will be used as the source.
        :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
            will be applied.

        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`

        :return a :class:`BatchEarnResult <agora.results.BatchEarnResult>`
        """
        raise NotImplementedError("BaseClient is an abstract class. Subclasses must implement submit_earn_batch")


class Client(BaseClient):
    """A :class:`Client <Client>` object for accessing Agora API features.

    :param env: The :class:`Environment <agora.environment.Environment>` to use.
    :param app_index: The Agora index of the app, used for all transactions and requests.
    :param whitelist_key: (optional) The private key, in raw bytes, of the account to whitelist submitted transactions
        with.
    :param grpc_channel: (optional) A GRPC :class:`Channel <grpc.Channel>` object to use for Agora requests. Only one of
        grpc_channel or endpoint should be set.
    :param endpoint: (optional) An endpoint to use instead of the default Agora endpoints. Only one of grpc_channel or
        endpoint should be set.
    :param retry_config: (optional): A :class:`RetryConfig <RetryConfig>` object to configure Agora retries. If not
        provided, a default configuration will be used.
    """

    def __init__(
        self, env: Environment, app_index: int, whitelist_key: Optional[bytes] = None,
        grpc_channel: Optional[grpc.Channel] = None, endpoint: Optional[str] = None,
        retry_config: Optional[RetryConfig] = None
    ):
        self.network_name = _NETWORK_NAMES[env]
        self.app_index = app_index

        if grpc_channel and endpoint:
            raise ValueError("")

        if not grpc_channel:
            endpoint = endpoint if endpoint else _ENDPOINTS[env]
            ssl_credentials = grpc.ssl_channel_credentials()
            grpc_channel = grpc.secure_channel(endpoint, ssl_credentials)

        self.account_stub = account_pb_grpc.AccountStub(grpc_channel)
        self.transaction_stub = tx_pb_grpc.TransactionStub(grpc_channel)

        self.whitelist_kp = (kin_base.Keypair.from_raw_seed(whitelist_key) if whitelist_key else None)

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

    def create_account(self, private_key: bytes):
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        retry(self.retry_strategies, self._create_stellar_account, private_key=private_key)

    def get_transaction(self, tx_hash: bytes) -> Tuple[TransactionState, Optional[TransactionData]]:
        resp = self.transaction_stub.GetTransaction(tx_pb.GetTransactionRequest(
            transaction_hash=model_pb2.TransactionHash(
                value=tx_hash
            )
        ), timeout=_GRPC_TIMEOUT)
        return (TransactionState.from_proto(resp.state),
                TransactionData.from_proto(resp.item) if resp.item.hash.value else None)

    def get_balance(self, public_key: bytes) -> int:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        info = self._get_stellar_account_info(public_key)
        return info.balance

    def submit_payment(self, payment: Payment) -> bytes:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        return retry(self.nonce_retry_strategies, self._submit_payment_tx, payment=payment)

    def submit_earn_batch(
        self, sender: bytes, earns: List[Earn], source: Optional[bytes] = None, memo: Optional[str] = None
    ) -> BatchEarnResult:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError

        tx_results = []

        for earn_batch in partition(earns, 100):
            i = 1
            while True:
                result = self._submit_earn_batch_tx(sender=sender, earns=earn_batch, source=source, memo=memo)
                if not result.has_failed:
                    tx_results.append(result)
                    break

                if not self._should_retry_earn_results(self.nonce_retry_strategies, i, result.earn_results):
                    tx_results.append(result)
                    break

                i += 1

        return BatchEarnResult(tx_results)

    def _submit_payment_tx(self, payment: Payment) -> bytes:
        """ Submits a payment transaction.

        :param payment: The :class:`Payment <agora.payment.Payment>` to submit.
        :return: The transaction hash.
        """
        tx_source = payment.source if payment.source else payment.sender
        builder = self._get_stellar_builder(tx_source)

        if payment.invoice:
            fk = InvoiceList(invoices=[payment.invoice]).get_sha_224_hash()
            memo = AgoraMemo.new(1, payment.payment_type, self.app_index, fk)
            builder.add_hash_memo(memo.val)
        elif payment.memo:
            builder.add_text_memo(payment.memo)

        sender_kp = kin_base.Keypair.from_raw_seed(payment.sender)
        builder.append_payment_op(
            public_key_to_address(payment.destination),
            quarks_to_kin_str(payment.quarks),
            source=sender_kp.address().decode(),
        )

        builder.sign(sender_kp.seed().decode())

        if payment.source:
            builder.sign(kin_base.Keypair.from_raw_seed(tx_source).seed().decode())

        if self.whitelist_kp:
            builder.sign(self.whitelist_kp.seed().decode())

        def _submit_tx(encoded_xdr):
            try:
                return self._submit_stellar_transaction(
                    encoded_xdr,
                    InvoiceList([payment.invoice]) if payment.invoice else None
                )
            except StellarTransactionError as e:
                tre = TransactionResultErrors.from_result(e.result_xdr)
                for op_error in tre.op_errors:
                    if op_error:
                        raise op_error
                raise tre.tx_error if tre.tx_error else e

        return retry(self.retry_strategies, _submit_tx, encoded_xdr=base64.b64decode(builder.gen_xdr()))

    def _submit_earn_batch_tx(
        self, sender: bytes, earns: List[Earn], source: Optional[bytes] = None, memo: Optional[str] = None
    ) -> EarnTransactionResult:
        """ Submits a single transaction for a batch of earns. An error will be raised if the number of earns exceeds
        the capacity of a single transaction.

        :param sender: The private key, in raw bytes, of the sender
        :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
        :param source: (optional) The private key, in raw bytes, of the transaction source account. If not set, the
            sender will be used as the source.
        :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
            will be applied.

        :return a :class:`BatchEarnResult <agora.results.BatchEarnResult>`
        """
        if len(earns) > 100:
            raise ValueError("cannot send more than 100 earns")

        tx_source = source if source else sender
        builder = self._get_stellar_builder(tx_source)

        invoices = [earn.invoice for earn in earns if earn.invoice]
        if invoices:
            if len(invoices) != len(earns):
                raise ValueError("Either all or none of the earns must contain invoices")
            if memo:
                raise ValueError("Cannot use both text memo and invoices")
            fk = InvoiceList(invoices=invoices).get_sha_224_hash()
            memo = AgoraMemo.new(1, TransactionType.EARN, self.app_index, fk)
            builder.add_hash_memo(memo.val)
        elif memo:
            builder.add_text_memo(memo)

        sender_kp = kin_base.Keypair.from_raw_seed(sender)
        for earn in earns:
            builder.append_payment_op(
                public_key_to_address(earn.destination),
                quarks_to_kin_str(earn.quarks),
                source=sender_kp.address().decode(),
            )

        builder.sign(sender_kp.seed().decode())

        if source:
            builder.sign(kin_base.Keypair.from_raw_seed(tx_source).seed().decode())

        if self.whitelist_kp:
            builder.sign(self.whitelist_kp.seed().decode())

        tx_hash = builder.hash()

        i = 1
        while True:
            try:
                tx_hash = self._submit_stellar_transaction(
                    base64.b64decode(builder.gen_xdr()),
                    invoice_list=InvoiceList(invoices if invoices else []),
                )
                earn_results = [EarnResult(earn) for earn in earns]
            except StellarTransactionError as e:
                tre = TransactionResultErrors.from_result(e.result_xdr)

                earn_results = [EarnResult(earn, error=tre.op_errors[idx] if tre.op_errors else tre.tx_error)
                                for idx, earn in enumerate(earns)]
            except InvoiceError as e:
                earn_results = [EarnResult(earn, error=e.errors[idx]) for idx, earn in enumerate(earns)]
            except TransactionRejectedError as e:
                earn_results = [EarnResult(earn, error=e) for earn in earns]

            if all(earn_result.error is None for earn_result in earn_results):
                break

            if not self._should_retry_earn_results(self.retry_strategies, i, earn_results):
                break

            i += 1

        return EarnTransactionResult(tx_hash, earn_results=earn_results)

    @staticmethod
    def _should_retry_earn_results(
        retry_strategies: List[Strategy], attempt: int, earn_results: List[EarnResult]
    ) -> bool:
        """Indicates whether the calling function should retry the operation, based on the provided list of earn
        results.

        :param retry_strategies: The retry strategies to use
        :param attempt: The current attempt count.
        :param earn_results: The list of :class:`EarnResult <agora.model.result.EarnResult>` to evaluate.
        :return: A bool indicating whether the caller should retry.
        """
        for s in retry_strategies:
            if any(not s.should_retry(attempt, r.error) for r in earn_results):
                return False
        return True

    def _create_stellar_account(self, private_key: bytes):
        """Submits a request to Agora to create a Stellar account.

        :param private_key: The private key, in raw bytes, of the account to create.
        """
        kp = kin_base.Keypair.from_raw_seed(private_key)
        resp = self.account_stub.CreateAccount(account_pb.CreateAccountRequest(
            account_id=model_pb2.StellarAccountId(
                value=kp.address().decode()
            )
        ), timeout=_GRPC_TIMEOUT)
        if resp.result == account_pb.CreateAccountResponse.Result.EXISTS:
            raise AccountExistsError()

    def _get_stellar_account_info(self, public_key: bytes) -> StellarAccountInfo:
        """Requests account info from Agora for a Stellar account.

        :param public_key: The public key, in raw bytes, of the account to request the info for.
        :return: :class:`StellarAccountInfo <agora.client.stellar.account.AccountInfo>
        """
        resp = self.account_stub.GetAccountInfo(account_pb.GetAccountInfoRequest(
            account_id=model_pb2.StellarAccountId(
                value=public_key_to_address(public_key)
            )
        ), timeout=_GRPC_TIMEOUT)
        if resp.result == account_pb.GetAccountInfoResponse.Result.NOT_FOUND:
            raise AccountNotFoundError

        return StellarAccountInfo(
            balance=resp.account_info.balance,
            sequence=resp.account_info.sequence_number
        )

    def _get_stellar_builder(self, source: bytes) -> kin_base.Builder:
        """Returns a Stellar transaction builder.

        :param source: The transaction source account.
        :return: a :class:`Builder` <kin_base.Builder> object.
        """
        kp = kin_base.Keypair.from_raw_seed(source)
        source_info = self._get_stellar_account_info(kp.raw_public_key())

        return kin_base.Builder(self._horizon, self.network_name,
                                0 if self.whitelist_kp else 100,
                                kp.seed().decode(),
                                sequence=source_info.sequence + 1)

    def _submit_stellar_transaction(self, tx_body: bytes, invoice_list: Optional[InvoiceList] = None) -> bytes:
        """Submit a stellar transaction to Agora.
        :param tx_body: The transaction envelope xdr, in bytes
        :param invoice_list: (optional) An :class:`InvoiceList <agora.invoice.InvoiceList>` to associate with the
            transaction
        :raise: :exc:`InvoiceError <agora.error.InvoiceError>`: if the transaction failed for a invoice-related reason.
        :raise: :exc:`StellarTransactionError <agora.error.StellarTransactionError>`: if the transaction failed
            upon submission to the blockchain.
        :return: The transaction hash
        """
        resp = self.transaction_stub.SubmitTransaction(tx_pb.SubmitTransactionRequest(
            envelope_xdr=tx_body,
            invoice_list=invoice_list.to_proto() if invoice_list else None,
        ), timeout=_GRPC_TIMEOUT)

        if resp.result == tx_pb.SubmitTransactionResponse.Result.REJECTED:
            raise TransactionRejectedError()
        if resp.result == tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR:
            raise InvoiceError([
                OperationInvoiceError(
                    e.op_index,
                    InvoiceErrorReason.from_proto(e.reason))
                for e in resp.invoice_errors
            ])

        if resp.result != tx_pb.SubmitTransactionResponse.Result.OK:
            raise StellarTransactionError(resp.result_xdr)

        return resp.hash.value
