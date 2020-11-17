import base64
from typing import List, Optional

import grpc
import kin_base
from agoraapi.account.v4 import account_service_pb2_grpc as account_pb_grpc
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb

from agora import KIN_2_PROD_NETWORK, KIN_2_TEST_NETWORK, solana
from agora.client.account.resolution import AccountResolution
from agora.client.account.resolver import TokenAccountResolver
from agora.client.environment import Environment
from agora.client.internal import InternalClient, SubmitTransactionResult
from agora.error import AccountExistsError, InvoiceError, InvoiceErrorReason, \
    UnsupportedVersionError, TransactionMalformedError, SenderDoesNotExistError, InsufficientBalanceError, \
    DestinationDoesNotExistError, InsufficientFeeError, BadNonceError, \
    TransactionRejectedError, Error, AlreadyPaidError, \
    WrongDestinationError, SkuNotFoundError, BlockchainVersionError, AccountNotFoundError, NoSubsidizerError, \
    AlreadySubmittedError
from agora.keys import PrivateKey, PublicKey, ED25519_PUB_KEY_SIZE
from agora.model.earn import Earn, EarnBatch
from agora.model.invoice import InvoiceList
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.result import BatchEarnResult, EarnResult
from agora.model.transaction import TransactionData
from agora.model.transaction_type import TransactionType
from agora.retry import retry, LimitStrategy, BackoffWithJitterStrategy, BinaryExponentialBackoff, \
    NonRetriableErrorsStrategy, RetriableErrorsStrategy
from agora.solana import Commitment, memo_instruction, transfer
from agora.solana.transaction import MAX_TX_SIZE, SIGNATURE_LENGTH, HASH_LENGTH
from agora.utils import partition, quarks_to_kin

_SUPPORTED_VERSIONS = [2, 3, 4]

_ENDPOINTS = {
    Environment.PRODUCTION: 'api.agorainfra.net:443',
    Environment.TEST: 'api.agorainfra.dev:443',
}

# kin_base handles conversion of the network name to the appropriate passphrase if recognizes it, but otherwise will
# use the provided network name as the passphrase
_NETWORK_NAMES = {
    2: {
        Environment.PRODUCTION: KIN_2_PROD_NETWORK,
        Environment.TEST: KIN_2_TEST_NETWORK,
    },
    3: {
        Environment.PRODUCTION: 'PUBLIC',
        Environment.TEST: 'TESTNET',
    },
}

_KIN_2_ISSUERS = {
    Environment.PRODUCTION: 'GDF42M3IPERQCBLWFEZKQRK77JQ65SCKTU3CW36HZVCX7XX5A5QXZIVK',
    Environment.TEST: 'GBC3SG6NGTSZ2OMH3FFGB7UVRQWILW367U4GSOOF4TFSZONV42UJXUH7',
}

_KIN_2_ASSET_CODE = 'KIN'

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
    BlockchainVersionError,
    AlreadySubmittedError,
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

    def create_account(self, private_key: PrivateKey, commitment: Optional[Commitment] = None,
                       subsidizer: Optional[PrivateKey] = None):
        """Creates a new Kin account.

        :param private_key: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account to create
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
        :param subsidizer: (optional) The subsidizer to use for the create account transaction. The subsidizer will be
            used both as the payer of the transaction and will also be given the CloseAccount authority on the created
            account. Only applicable for Kin 4 transactions.

        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`AccountExistsError <agora.error.AccountExistsError>`
        """
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement create_account')

    def get_transaction(self, tx_id: bytes, commitment: Optional[Commitment] = None) -> TransactionData:
        """Retrieves a transaction.

        :param tx_id: The id of the transaction to retrieve. This can be either the 32-byte hash of a Stellar-based
            transaction (on Kin 2 or 3) or the 64-byte signature of a Solana-based transaction (on Kin 4).
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
        :return: a :class:`TransactionData <agora.model.transaction.TransactionData>` object.
        """
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement get_transaction')

    def get_balance(self, public_key: PublicKey, commitment: Optional[Commitment] = None) -> int:
        """Retrieves the balance of an account.

        :param public_key: The :class:`PublicKey <agora.model.keys.PublicKey>` of the account to retrieve the balance
            for.
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`
        :raise: :exc:`AccountNotFoundError <agora.error.AccountNotFoundError>`
        :return: The balance of the account, in quarks.
        """
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement get_balance')

    def resolve_token_accounts(self, public_key: PublicKey) -> List[PublicKey]:
        """Resolves the token accounts owned by the specified account on Kin 4.

        :param public_key: The public key of the owner account.
        :return: a List of token accounts owned by the account with the provided public key.
        """

    def submit_payment(
        self, payment: Payment, commitment: Optional[Commitment] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> bytes:
        """Submits a payment to the Kin blockchain.

        :param payment: The :class:`Payment <agora.model.payment.Payment>` to submit.
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
        :param sender_resolution:  (optional) The :class:`AccountResolution <agora.client.account.AccountResolution>` to
            use for the payment sender account if the transaction fails due to an account error. Only applies for Kin 4
            transactions. Defaults to AccountResolution.PREFERRED.
        :param dest_resolution: (optional) The :class:`AccountResolution <agora.client.account.AccountResolution>` to
            use for the payment destination account if the transaction fails due to an account error. Only applies for
            Kin 4 transactions. Defaults to AccountResolution.PREFERRED.

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
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement submit_payment')

    def submit_earn_batch(
        self, sender: PrivateKey, earns: List[Earn], channel: Optional[PrivateKey] = None, memo: Optional[str] = None,
        commitment: Optional[Commitment] = None, subsidizer: Optional[PrivateKey] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> BatchEarnResult:
        """Submit multiple earn payments.

        :param sender: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the sender
        :param earns: A list of :class:`Earn <agora.model.earn.Earn>` objects.
        :param channel: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey>` of a channel account to use as
            the transaction source. If not set, the `sender` will be used as the source.
        :param memo: (optional) The memo to include in the transaction. If set, none of the invoices included in earns
            will be applied.
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
        :param subsidizer: (optional) The subsidizer to use for the create account transaction. The subsidizer will be
            used both as the payer of the transaction. Only applicable for Kin 4 transactions.
        :param sender_resolution: (optional) The :class:`AccountResolution <agora.client.account.AccountResolution>` to
            use for the sender account if the transaction fails due to an account error. Only applies for Kin 4
            transactions. Defaults to AccountResolution.PREFERRED.
        :param dest_resolution: (optional) The :class:`AccountResolution <agora.client.account.AccountResolution>` to
            use for the earn destination accounts if the transaction fails due to an account error. Only applies for
            Kin 4 transactions. Defaults to AccountResolution.PREFERRED.

        :raise: :exc:`UnsupportedVersionError <agora.error.UnsupportedVersionError>`

        :return: a :class:`BatchEarnResult <agora.model.result.BatchEarnResult>`
        """
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement submit_earn_batch')

    def close(self) -> None:
        """Closes the connection-related resources (e.g. the gRPC channel) used by the client. Subsequent requests to
        this client will cause an exception to be thrown.
        """
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement close')


class Client(BaseClient):
    """A :class:`Client <Client>` object for accessing Agora API features.

    :param env: The :class:`Environment <agora.environment.Environment>` to use.
    :param app_index: (optional) The Agora index of the app, used for all transactions and requests. Required to make
        use of invoices.
    :param whitelist_key: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account to whitelist
        submitted transactions with.
    :param grpc_channel: (optional) A GRPC :class:`Channel <grpc.Channel>` object to use for Agora requests. Only one of
        grpc_channel or endpoint should be set.
    :param endpoint: (optional) An endpoint to use instead of the default Agora endpoints. Only one of grpc_channel or
        endpoint should be set.
    :param retry_config: (optional): A :class:`RetryConfig <RetryConfig>` object to configure Agora retries. If not
        provided, a default configuration will be used.
    :param kin_version: (optional) The version of Kin to use. Defaults to using Kin 3.
    :param default_commitment: (optional) The commitment requirement to use by default for Kin 4 Agora requests.
        Defaults to using Commitment.SINGLE.
    :param desired_kin_version: (optional) A debugging parameter to force Agora to use a minimum kin version. Defaults
        to None.
    """

    def __init__(
        self, env: Environment, app_index: int = 0, whitelist_key: Optional[PrivateKey] = None,
        grpc_channel: Optional[grpc.Channel] = None, endpoint: Optional[str] = None,
        retry_config: Optional[RetryConfig] = None, kin_version: Optional[int] = 3,
        default_commitment: Optional[Commitment] = Commitment.SINGLE, desired_kin_version: Optional[int] = None,
    ):
        if kin_version not in _SUPPORTED_VERSIONS:
            raise ValueError(f'`kin_version` {kin_version} is not a supported version of Kin')
        if desired_kin_version and desired_kin_version not in _SUPPORTED_VERSIONS:
            raise ValueError(f'`desired_kin_version {desired_kin_version} is not a supported version of Kin')

        self.app_index = app_index

        if grpc_channel and endpoint:
            raise ValueError('`grpc_channel` and `endpoint` cannot both be set')

        if not grpc_channel:
            endpoint = endpoint if endpoint else _ENDPOINTS[env]
            ssl_credentials = grpc.ssl_channel_credentials()
            self._grpc_channel = grpc.secure_channel(endpoint, ssl_credentials)
        else:
            self._grpc_channel = grpc_channel

        retry_config = retry_config if retry_config else RetryConfig()
        self._internal_retry_strategies = [
            NonRetriableErrorsStrategy(_NON_RETRIABLE_ERRORS),
            LimitStrategy(retry_config.max_retries + 1),
            BackoffWithJitterStrategy(BinaryExponentialBackoff(retry_config.min_delay),
                                      retry_config.max_delay, 0.1),
        ]
        self._nonce_retry_strategies = [
            RetriableErrorsStrategy([BadNonceError]),
            LimitStrategy(retry_config.max_nonce_refreshes + 1)
        ]

        self._kin_version = kin_version
        if kin_version == 2:
            self._asset_issuer = _KIN_2_ISSUERS[env]
        else:
            self._asset_issuer = None

        if kin_version in [2, 3]:
            self.network_name = _NETWORK_NAMES[kin_version][env]
            self.whitelist_key = whitelist_key

        self._internal_client = InternalClient(self._grpc_channel, self._internal_retry_strategies, self._kin_version,
                                               desired_kin_version=desired_kin_version)

        self._default_commitment = default_commitment

        self._token_account_resolver = TokenAccountResolver(
            account_pb_grpc.AccountStub(self._grpc_channel),
            retry_strategies=[
                LimitStrategy(retry_config.max_retries + 1),
                BackoffWithJitterStrategy(BinaryExponentialBackoff(retry_config.min_delay),
                                          retry_config.max_delay, 0.1),
            ]
        )

    def create_account(self, private_key: PrivateKey, commitment: Optional[Commitment] = None,
                       subsidizer: Optional[PrivateKey] = None):
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        commitment = commitment if commitment else self._default_commitment
        if self._kin_version < 4:
            try:
                return self._internal_client.create_stellar_account(private_key)
            except BlockchainVersionError:
                self._set_kin_version(4)

        def _submit_create_solana_account():
            self._internal_client.create_solana_account(private_key, commitment=commitment, subsidizer=subsidizer)

        return retry(self._nonce_retry_strategies, _submit_create_solana_account)

    def get_transaction(self, tx_id: bytes, commitment: Optional[Commitment] = None) -> TransactionData:
        if self._kin_version < 4:
            return self._internal_client.get_stellar_transaction(tx_id)

        commitment = commitment if commitment else self._default_commitment
        return self._internal_client.get_transaction(tx_id, commitment)

    def get_balance(self, public_key: PublicKey, commitment: Optional[Commitment] = None) -> int:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        commitment = commitment if commitment else self._default_commitment
        if self._kin_version < 4:
            try:
                return self._internal_client.get_stellar_account_info(public_key).balance
            except BlockchainVersionError:
                self._set_kin_version(4)

        return self._internal_client.get_solana_account_info(public_key, commitment=commitment).balance

    def resolve_token_accounts(self, public_key: PublicKey) -> List[PublicKey]:
        if self._kin_version != 4:
            raise UnsupportedVersionError("`resolve_token_accounts` is only available on Kin 4")

        return self._internal_client.resolve_token_accounts(public_key)

    def submit_payment(
        self, payment: Payment, commitment: Optional[Commitment] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> bytes:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError()

        if payment.invoice and self.app_index <= 0:
            raise ValueError('cannot submit a payment with an invoice without an app index')

        commitment = commitment if commitment else self._default_commitment
        if self._kin_version not in [2, 3]:
            result = self._resolve_and_submit_solana_payment(
                payment, commitment, sender_resolution=sender_resolution,
                dest_resolution=dest_resolution
            )
        else:
            try:
                result = self._submit_stellar_payment_tx(payment)
            except BlockchainVersionError:
                self._set_kin_version(4)
                result = self._resolve_and_submit_solana_payment(
                    payment, commitment, sender_resolution=sender_resolution,
                    dest_resolution=dest_resolution
                )

        if result.tx_error:
            if len(result.tx_error.op_errors) > 0:
                if len(result.tx_error.op_errors) != 1:
                    raise Error(f'invalid number of operation errors, expected 0 or 1, got '
                                f'{len(result.tx_error.op_errors)}')
                raise result.tx_error.op_errors[0]

            if result.tx_error.tx_error:
                raise result.tx_error.tx_error

        if result.invoice_errors:
            if len(result.invoice_errors) != 1:
                raise Error(f'invalid number of invoice errors, expected 0 or 1, got {len(result.invoice_errors)}')

            if result.invoice_errors[0].reason == InvoiceErrorReason.ALREADY_PAID:
                raise AlreadyPaidError()
            if result.invoice_errors[0].reason == InvoiceErrorReason.WRONG_DESTINATION:
                raise WrongDestinationError()
            if result.invoice_errors[0].reason == InvoiceErrorReason.SKU_NOT_FOUND:
                raise SkuNotFoundError()
            raise Error(f'unknown invoice error: {result.invoice_errors[0].reason}')

        return result.tx_id

    def submit_earn_batch(
        self, sender: PrivateKey, earns: List[Earn], channel: Optional[bytes] = None, memo: Optional[str] = None,
        commitment: Optional[Commitment] = None, subsidizer: Optional[PrivateKey] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> BatchEarnResult:
        if self._kin_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError

        invoices = [earn.invoice for earn in earns if earn.invoice]
        if invoices:
            if self.app_index <= 0:
                raise ValueError('cannot submit a payment with an invoice without an app index')
            if len(invoices) != len(earns):
                raise ValueError('Either all or none of the earns must contain invoices')
            if memo:
                raise ValueError('Cannot use both text memo and invoices')

        succeeded = []
        failed = []

        if self._kin_version in [2, 3]:
            use_stellar = True
            earn_batches = partition(earns, 100)

            service_config = None
            commitment = None
        else:
            service_config = self._internal_client.get_service_config()
            if not service_config.subsidizer_account.value and not subsidizer:
                raise NoSubsidizerError()

            commitment = commitment if commitment else self._default_commitment
            use_stellar = False
            earn_batches = self._partition_earns_for_solana(earns, sender_resolution, memo=memo)

        for earn_batch in earn_batches:
            batch = EarnBatch(sender, earn_batch, channel=channel, memo=memo, subsidizer=subsidizer)
            try:
                if use_stellar:
                    result = self._submit_stellar_earn_batch_tx(batch)
                else:
                    result = self._resolve_and_submit_solana_earn_batch(batch, service_config, commitment=commitment,
                                                                        sender_resolution=sender_resolution,
                                                                        dest_resolution=dest_resolution)
            except Error as e:
                failed += [EarnResult(earn, error=e) for idx, earn in enumerate(earn_batch)]
                break

            if not result.tx_error:
                succeeded += [EarnResult(earn, tx_id=result.tx_id) for earn in earn_batch]
                continue

            # At this point, the batch is considered failed
            err = result.tx_error

            if err.op_errors:
                failed += [EarnResult(earn, tx_id=result.tx_id, error=err.op_errors[idx])
                           for idx, earn in enumerate(earn_batch)]
            else:
                failed += [EarnResult(earn, tx_id=result.tx_id, error=err.tx_error)
                           for idx, earn in enumerate(earn_batch)]
            break

        for earn in earns[len(succeeded) + len(failed):]:
            failed.append(EarnResult(earn=earn))

        return BatchEarnResult(succeeded=succeeded, failed=failed)

    def close(self) -> None:
        self._grpc_channel.close()

    def _partition_earns_for_solana(
        self, earns: List[Earn], sender_resolution: AccountResolution, memo: Optional[str] = None,
    ) -> List[List[Earn]]:
        include_agora_memo = memo is None and self.app_index > 0
        batches = []

        offset = 0
        for i in range(1, len(earns) + 1):
            # To avoid having to re-partition earns in the case that the sender account needs to be resolved, if sender
            # resolution is PREFERRED, include it in the estimation of the transaction size
            tx_size = self._estimate_earn_batch_tx_size(
                earns[offset:i],
                has_separate_sender=sender_resolution == AccountResolution.PREFERRED,
                has_agora_memo=include_agora_memo,
                memo=memo
            )
            if tx_size > MAX_TX_SIZE:
                batches.append(earns[offset:i - 1])
                offset = i - 1
            elif tx_size == MAX_TX_SIZE or i == len(earns):
                batches.append(earns[offset:i])
                offset = i

        return batches

    @staticmethod
    def _estimate_earn_batch_tx_size(
        earns: List[Earn], has_separate_sender: bool = False, has_agora_memo: bool = False, memo: Optional[str] = None,
    ):
        """
        Estimates the size of a transaction by adding following components:
        - Signatures: 1 (shortvec) + sig_count * SIGNATURE_LENGTH
        - Header bytes: 3
        - Accounts: 1 (shortvec) + account_count * ED25519_PUB_KEY_SIZE
        - Hash Length
        - For instructions:
            - 1 byte (shortvec)
            - (optional, if Agora memo included) Agora memo: ED25519_PUB_KEY_SIZE + 1 (program index) + 1 (account
              shortvec) + 1 (data shortvec) + 44 (length of a base64-encoded Agora memo) = 79
            - (optional) memo: ED25519_PUB_KEY_SIZE + 1 (program index) + 1 (account shortvec) + data shortvec +
              len(data) = 34 + data shortvec + len(data)
            - Each transfer: 1 (program index) + 1 (account shortvec) + 3 (3 account indices) + 1 (data shortvec) +
              9 (transfer data length) = 15

        :return:
        """
        # unique destinations + subsidizer + owner + program + (optional) resolved transfer sender
        account_count = len({earn.destination.raw for earn in earns}) + 3 + (1 if has_separate_sender else 0)
        # owner, subsidizer
        sig_count = 2

        return (1 + sig_count * SIGNATURE_LENGTH +
                3 +
                Client._estimate_shortvec_size(account_count) + account_count * ED25519_PUB_KEY_SIZE +
                HASH_LENGTH +
                1 +
                (79 if has_agora_memo else 0) +
                ((34 + Client._estimate_shortvec_size(len(memo)) + len(memo)) if memo else 0) +
                len(earns) * 15)

    @staticmethod
    def _estimate_shortvec_size(length: int) -> int:
        return 1 if length < 128 else 2 if length < 16384 else 3

    def _resolve_and_submit_solana_payment(
        self, payment: Payment, commitment: Commitment,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> SubmitTransactionResult:
        if payment.channel:
            raise ValueError('cannot set `channel` on Kin 4 payments.')

        service_config = self._internal_client.get_service_config()
        if not service_config.subsidizer_account.value and not payment.subsidizer:
            raise NoSubsidizerError()

        result = self._submit_solana_payment_tx(payment, service_config, commitment)
        if result.tx_error and isinstance(result.tx_error.tx_error, AccountNotFoundError):
            transfer_sender = None
            resubmit = False

            if sender_resolution == AccountResolution.PREFERRED:
                sender_token_accounts = self._token_account_resolver.resolve_token_accounts(payment.sender.public_key)
                if sender_token_accounts:
                    transfer_sender = sender_token_accounts[0]
                    resubmit = True

            if dest_resolution == AccountResolution.PREFERRED:
                dest_token_accounts = self._token_account_resolver.resolve_token_accounts(payment.destination)
                if dest_token_accounts:
                    payment.destination = dest_token_accounts[0]
                    resubmit = True

            if resubmit:
                result = self._submit_solana_payment_tx(payment, service_config, commitment,
                                                        transfer_sender=transfer_sender)

        return result

    def _resolve_and_submit_solana_earn_batch(
        self, batch: EarnBatch, service_config: tx_pb.GetServiceConfigResponse, commitment: Commitment,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> SubmitTransactionResult:
        result = self._submit_solana_earn_batch_tx(batch, service_config, commitment)

        if result.tx_error and isinstance(result.tx_error.tx_error, AccountNotFoundError):
            transfer_sender = None
            resubmit = False

            if sender_resolution == AccountResolution.PREFERRED:
                sender_token_accounts = self._token_account_resolver.resolve_token_accounts(batch.sender.public_key)
                if sender_token_accounts:
                    transfer_sender = sender_token_accounts[0]
                    resubmit = True

            if dest_resolution == AccountResolution.PREFERRED:
                for earn in batch.earns:
                    dest_token_accounts = self._token_account_resolver.resolve_token_accounts(earn.destination)
                    if dest_token_accounts:
                        earn.destination = dest_token_accounts[0]
                        resubmit = True

            if resubmit:
                result = self._submit_solana_earn_batch_tx(batch, service_config, commitment,
                                                           transfer_sender=transfer_sender)

        return result

    def _submit_solana_payment_tx(
        self, payment: Payment, service_config: tx_pb.GetServiceConfigResponse, commitment: Commitment,
        transfer_sender: Optional[PublicKey] = None
    ) -> SubmitTransactionResult:
        token_program = PublicKey(service_config.token_program.value)
        subsidizer_id = (payment.subsidizer.public_key if payment.subsidizer
                         else PublicKey(service_config.subsidizer_account.value))

        instructions = []
        invoice_list = None
        if payment.memo:
            instructions = [memo_instruction(payment.memo)]
        elif self.app_index > 0:
            if payment.invoice:
                invoice_list = InvoiceList(invoices=[payment.invoice])
            fk = invoice_list.get_sha_224_hash() if payment.invoice else b''
            memo = AgoraMemo.new(1, payment.tx_type, self.app_index, fk)
            instructions = [memo_instruction(base64.b64encode(memo.val).decode('utf-8'))]

        sender = transfer_sender if transfer_sender else payment.sender.public_key
        instructions.append(transfer(sender, payment.destination, payment.sender.public_key,
                                     payment.quarks, token_program))

        tx = solana.Transaction.new(subsidizer_id, instructions)
        if payment.subsidizer:
            signers = [payment.subsidizer, payment.sender]
        else:
            signers = [payment.sender]

        return self._sign_and_submit_solana_tx(signers, tx, commitment, invoice_list)

    def _submit_solana_earn_batch_tx(
        self, batch: EarnBatch, service_config: tx_pb.GetServiceConfigResponse, commitment: Commitment,
        transfer_sender: Optional[PublicKey] = None,
    ) -> SubmitTransactionResult:
        token_program = PublicKey(service_config.token_program.value)
        subsidizer_id = (batch.subsidizer.public_key if batch.subsidizer
                         else PublicKey(service_config.subsidizer_account.value))

        transfer_sender = transfer_sender if transfer_sender else batch.sender.public_key
        instructions = [
            transfer(transfer_sender, earn.destination, batch.sender.public_key, earn.quarks, token_program)
            for earn in batch.earns]

        invoices = [earn.invoice for earn in batch.earns if earn.invoice]
        invoice_list = InvoiceList(invoices) if invoices else None
        if batch.memo:
            instructions = [memo_instruction(batch.memo)] + instructions
        elif self.app_index > 0:
            fk = invoice_list.get_sha_224_hash() if invoice_list else b''
            agora_memo = AgoraMemo.new(1, TransactionType.EARN, self.app_index, fk)
            instructions = [memo_instruction(base64.b64encode(agora_memo.val).decode('utf-8'))] + instructions

        tx = solana.Transaction.new(subsidizer_id, instructions)
        if batch.subsidizer:
            signers = [batch.subsidizer, batch.sender]
        else:
            signers = [batch.sender]

        return self._sign_and_submit_solana_tx(signers, tx, commitment, invoice_list=invoice_list)

    def _sign_and_submit_solana_tx(
        self, signers: List[PrivateKey], tx: solana.Transaction, commitment: Commitment,
        invoice_list: Optional[InvoiceList] = None
    ):
        def _get_blockhash_and_submit():
            recent_blockhash = self._internal_client.get_recent_blockhash().blockhash.value
            tx.set_blockhash(recent_blockhash)
            tx.sign(signers)

            result = self._internal_client.submit_solana_transaction(tx.marshal(), invoice_list=invoice_list,
                                                                     commitment=commitment)
            if result.tx_error and isinstance(result.tx_error.tx_error, BadNonceError):
                raise result.tx_error.tx_error

            return result

        return retry(self._nonce_retry_strategies, _get_blockhash_and_submit)

    def _submit_stellar_payment_tx(self, payment: Payment) -> SubmitTransactionResult:
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

        # Inside the kin_base module, the base currency has been 'scaled' by a factor of 100 from
        # Stellar (i.e., the smallest denomination used is 1e-5 instead of 1e-7). However, Kin 2 uses the minimum
        # Stellar denomination of 1e-7.
        #
        # The Kin amounts provided to `append_payment_op` get converted to the smallest denomination inside the
        # submitted transaction and the conversion occurs assuming a smallest denomination of 1e-5. Therefore, for
        # Kin 2 transactions, we must multiple by 100 to account for the scaling factor.
        builder.append_payment_op(
            payment.destination.stellar_address,
            quarks_to_kin(payment.quarks * 100 if self._kin_version == 2 else payment.quarks),
            source=payment.sender.public_key.stellar_address,
            asset_issuer=self._asset_issuer if self._kin_version == 2 else None,
        )

        if payment.channel:
            signers = [payment.channel, payment.sender]
        else:
            signers = [payment.sender]

        if self.whitelist_key:
            signers.append(self.whitelist_key)

        return self._sign_and_submit_builder(signers, builder, invoice_list)

    def _submit_stellar_earn_batch_tx(self, batch: EarnBatch) -> SubmitTransactionResult:
        if len(batch.earns) > 100:
            raise ValueError('cannot send more than 100 earns')

        builder = self._get_stellar_builder(batch.channel if batch.channel else batch.sender)

        invoices = [earn.invoice for earn in batch.earns if earn.invoice]
        invoice_list = InvoiceList(invoices) if invoices else None
        if batch.memo:
            builder.add_text_memo(batch.memo)
        elif self.app_index > 0:
            fk = invoice_list.get_sha_224_hash() if invoice_list else b''
            memo = AgoraMemo.new(1, TransactionType.EARN, self.app_index, fk)
            builder.add_hash_memo(memo.val)

        for earn in batch.earns:
            # Inside the kin_base module, the base currency has been 'scaled' by a factor of 100 from
            # Stellar (i.e., the smallest denomination used is 1e-5 instead of 1e-7). However, Kin 2 uses the minimum
            # Stellar denomination of 1e-7.
            #
            # The Kin amounts provided to `append_payment_op` get converted to the smallest denomination inside the
            # submitted transaction and the conversion occurs assuming a smallest denomination of 1e-5. Therefore, for
            # Kin 2 transactions, we must multiple by 100 to account for the scaling factor.
            builder.append_payment_op(
                earn.destination.stellar_address,
                quarks_to_kin(earn.quarks * 100 if self._kin_version == 2 else earn.quarks),
                source=batch.sender.public_key.stellar_address,
                asset_issuer=self._asset_issuer if self._kin_version == 2 else None,
            )

        if batch.channel:
            signers = [batch.channel, batch.sender]
        else:
            signers = [batch.sender]

        if self.whitelist_key:
            signers.append(self.whitelist_key)

        result = self._sign_and_submit_builder(signers, builder, invoice_list)
        if result.invoice_errors:
            # Invoice errors should not be triggered on earns. This indicates there is something wrong with the service.
            raise Error('unexpected invoice errors present')

        return result

    def _sign_and_submit_builder(
        self, signers: List[PrivateKey], builder: kin_base.Builder, invoice_list: Optional[InvoiceList] = None
    ) -> SubmitTransactionResult:
        source_info = self._internal_client.get_stellar_account_info(signers[0].public_key)
        offset = 1

        def _sign_and_submit():
            nonlocal offset

            # reset generated tx and te
            builder.tx = None
            builder.te = None

            builder.sequence = source_info.sequence_number + offset
            for signer in signers:
                builder.sign(signer.stellar_seed)

            result = self._internal_client.submit_stellar_transaction(base64.b64decode(builder.gen_xdr()), invoice_list)

            if result.tx_error and isinstance(result.tx_error.tx_error, BadNonceError):
                offset += 1
                raise result.tx_error.tx_error

            return result

        return retry(self._nonce_retry_strategies, _sign_and_submit)

    def _get_stellar_builder(self, source: PrivateKey) -> kin_base.Builder:
        """Returns a Stellar transaction builder.

        :param source: The transaction source account.
        :return: a :class:`Builder` <kin_base.Builder> object.
        """
        # A Horizon instance is expected as the first argument, but it isn't used, so pass None instead to avoid
        # unnecessary aiohttp.ClientSessions getting opened.
        return kin_base.Builder(None, self.network_name,
                                100,
                                source.stellar_seed)

    def _set_kin_version(self, kin_version):
        self._kin_version = kin_version
        self._internal_client.set_kin_version(kin_version)
