import base64
from typing import List, Optional

import grpc
from agoraapi.account.v4 import account_service_pb2_grpc as account_pb_grpc
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb

from agora import solana
from agora.client.account.resolution import AccountResolution
from agora.client.account.resolver import TokenAccountResolver
from agora.client.environment import Environment
from agora.client.internal import InternalClient, SubmitTransactionResult
from agora.client.utils import _generate_token_account
from agora.error import AccountExistsError, InvoiceError, TransactionMalformedError, SenderDoesNotExistError, \
    InsufficientBalanceError, DestinationDoesNotExistError, InsufficientFeeError, BadNonceError, \
    TransactionRejectedError, Error, BlockchainVersionError, AccountNotFoundError, NoSubsidizerError, \
    AlreadySubmittedError, invoice_error_from_proto, UnsupportedMethodError
from agora.keys import PrivateKey, PublicKey
from agora.model.earn import EarnBatch
from agora.model.invoice import InvoiceList
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.result import EarnBatchResult, EarnError
from agora.model.transaction import TransactionData
from agora.model.transaction_type import TransactionType
from agora.retry import retry, LimitStrategy, BackoffWithJitterStrategy, BinaryExponentialBackoff, \
    NonRetriableErrorsStrategy, RetriableErrorsStrategy
from agora.solana import Commitment, system, token, memo

_MIN_VERSION = 4
_MAX_VERSION = 4

_ENDPOINTS = {
    Environment.PRODUCTION: 'api.agorainfra.net:443',
    Environment.TEST: 'api.agorainfra.dev:443',
}

_NON_RETRIABLE_ERRORS = [
    AccountExistsError,
    AccountNotFoundError,
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

        :param private_key: The :class:`PrivateKey <agora.keys.PrivateKey>` of the account to create
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

    def get_balance(
        self, public_key: PublicKey, commitment: Optional[Commitment] = None,
        account_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> int:
        """Retrieves the balance of an account.

        :param public_key: The :class:`PublicKey <agora.keys.PublicKey>` of the account to retrieve the balance
            for.
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
        :param account_resolution: (optional) The :class:`AccountResolution <agora.client.account.AccountResolution>` to
            use if the original account was not found. Only applies for Kin 4. Defaults to AccountResolution.PREFERRED.

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
        :param sender_resolution: (optional) The :class:`AccountResolution <agora.client.account.AccountResolution>` to
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
        self, batch: EarnBatch, commitment: Optional[Commitment] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> EarnBatchResult:
        """Submit multiple earn payments.

        :param batch: The :class:`EarnBatch <agora.model.earn.EarnBatch>` to submit. The number of earns in the
            batch is limited to 15, which is roughly the max number of transfers that can fit inside a Solana
            transaction.
        :param commitment: (optional) The commitment to use. Only applicable for Kin 4 transactions.
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

    def request_airdrop(
        self, public_key: PublicKey, quarks: int, commitment: Optional[Commitment] = None,
    ) -> bytes:
        """Requests an airdrop of Kin to a Kin account. Only available on Kin 4 on the test environment.

        :param public_key: the public key of the Kin token account to airdrop to. To get all the token accounts owned by
            an owner, use Client.resolve_token_accounts.
        :param quarks: The amount, in quarks, to request.
        :param commitment: (optional) The commitment to use.

        :raise: :exc:`UnsupportedMethodError <agora.error.UnsupportedMethodError>`

        :return: The transaction ID of the airdrop transaction submitted by Agora.
        """
        raise NotImplementedError('BaseClient is an abstract class. Subclasses must implement request_airdrop')

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
    :param kin_version: (optional) The version of Kin to use. Defaults to using Kin 4.
    :param grpc_channel: (optional) A GRPC :class:`Channel <grpc.Channel>` object to use for Agora requests. Only one of
        grpc_channel or endpoint should be set.
    :param endpoint: (optional) An endpoint to use instead of the default Agora endpoints. Only one of grpc_channel or
        endpoint should be set.
    :param retry_config: (optional): A :class:`RetryConfig <RetryConfig>` object to configure Agora retries. If not
        provided, a default configuration will be used.
    :param default_commitment: (optional) The commitment requirement to use by default for Kin 4 Agora requests.
        Defaults to using Commitment.SINGLE.
    """

    def __init__(
        self, env: Environment, app_index: int = 0,
        grpc_channel: Optional[grpc.Channel] = None, endpoint: Optional[str] = None,
        retry_config: Optional[RetryConfig] = None,
        default_commitment: Optional[Commitment] = Commitment.SINGLE,
    ):
        if grpc_channel and endpoint:
            raise ValueError('`grpc_channel` and `endpoint` cannot both be set')

        self._env = env
        self._app_index = app_index

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

        self._internal_client = InternalClient(self._grpc_channel, self._internal_retry_strategies)

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
        commitment = commitment if commitment else self._default_commitment
        min_balance_resp = self._internal_client.get_minimum_balance_for_rent_exception()
        return retry(self._nonce_retry_strategies, self._create_solana_account, private_key, commitment,
                     min_balance_resp.lamports, subsidizer)

    def get_transaction(self, tx_id: bytes, commitment: Optional[Commitment] = None) -> TransactionData:
        commitment = commitment if commitment else self._default_commitment
        return self._internal_client.get_transaction(tx_id, commitment)

    def get_balance(
        self, public_key: PublicKey, commitment: Optional[Commitment] = None,
        account_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> int:
        commitment = commitment if commitment else self._default_commitment
        try:
            return self._internal_client.get_solana_account_info(public_key, commitment=commitment).balance
        except AccountNotFoundError as e:
            if account_resolution == AccountResolution.PREFERRED:
                token_accounts = self._token_account_resolver.resolve_token_accounts(public_key)
                if token_accounts:
                    return self._internal_client.get_solana_account_info(token_accounts[0],
                                                                         commitment=commitment).balance
            raise e

    def resolve_token_accounts(self, public_key: PublicKey) -> List[PublicKey]:
        return self._token_account_resolver.resolve_token_accounts(public_key)

    def submit_payment(
        self, payment: Payment, commitment: Optional[Commitment] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> bytes:
        if payment.invoice and self._app_index <= 0:
            raise ValueError('cannot submit a payment with an invoice without an app index')

        commitment = commitment if commitment else self._default_commitment
        result = self._resolve_and_submit_solana_payment(
            payment, commitment, sender_resolution=sender_resolution,
            dest_resolution=dest_resolution
        )

        if result.errors:
            if len(result.errors.op_errors) > 0:
                if len(result.errors.op_errors) != 1:
                    raise Error(f'invalid number of operation errors, expected 0 or 1, got '
                                f'{len(result.errors.op_errors)}')
                raise result.errors.op_errors[0]

            if result.errors.tx_error:
                raise result.errors.tx_error

        if result.invoice_errors:
            if len(result.invoice_errors) != 1:
                raise Error(f'invalid number of invoice errors, expected 0 or 1, got {len(result.invoice_errors)}')

            raise invoice_error_from_proto(result.invoice_errors[0])

        return result.tx_id

    def submit_earn_batch(
        self, batch: EarnBatch, commitment: Optional[Commitment] = None,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> EarnBatchResult:
        if len(batch.earns) == 0:
            raise ValueError('earn batch must contain at least 1 earn')
        if len(batch.earns) > 15:
            raise ValueError('earn batch must not contain more than 15 earns')

        invoices = [earn.invoice for earn in batch.earns if earn.invoice]
        if invoices:
            if self._app_index <= 0:
                raise ValueError('cannot submit a payment with an invoice without an app index')
            if len(invoices) != len(batch.earns):
                raise ValueError('Either all or none of the earns must contain invoices')
            if batch.memo:
                raise ValueError('Cannot use both text memo and invoices')

        service_config = self._internal_client.get_service_config()
        if not service_config.subsidizer_account.value and not batch.subsidizer:
            raise NoSubsidizerError()

        commitment = commitment if commitment else self._default_commitment
        submit_result = self._resolve_and_submit_solana_earn_batch(batch, service_config, commitment=commitment,
                                                                   sender_resolution=sender_resolution,
                                                                   dest_resolution=dest_resolution)

        result = EarnBatchResult(submit_result.tx_id)
        if submit_result.errors:
            result.tx_error = submit_result.errors.tx_error

            if submit_result.errors.payment_errors:
                result.earn_errors = []
                for idx, e in enumerate(submit_result.errors.payment_errors):
                    if e:
                        result.earn_errors.append(EarnError(idx, e))
        elif submit_result.invoice_errors:
            result.tx_error = TransactionRejectedError()
            result.earn_errors = []
            for invoice_error in submit_result.invoice_errors:
                result.earn_errors.append(EarnError(invoice_error.op_index, invoice_error_from_proto(invoice_error)))

        return result

    def request_airdrop(
        self, public_key: PublicKey, quarks: int, commitment: Optional[Commitment] = None,
    ) -> bytes:
        if self._env != Environment.TEST:
            raise UnsupportedMethodError()

        commitment = commitment if commitment else self._default_commitment
        return self._internal_client.request_airdrop(public_key, quarks, commitment)

    def close(self) -> None:
        self._grpc_channel.close()

    def _create_solana_account(
        self, private_key: PrivateKey, commitment: Commitment, min_balance: int, subsidizer: Optional[PrivateKey] = None
    ):
        token_account_key = _generate_token_account(private_key)

        service_config_resp = self._internal_client.get_service_config()
        if not service_config_resp.subsidizer_account.value and not subsidizer:
            raise NoSubsidizerError()

        subsidizer_id = (subsidizer.public_key if subsidizer else
                         PublicKey(service_config_resp.subsidizer_account.value))

        recent_blockhash_resp = self._internal_client.get_recent_blockhash()
        token_program = PublicKey(service_config_resp.token_program.value)
        transaction = solana.Transaction.new(
            subsidizer_id,
            [
                system.create_account(
                    subsidizer_id,
                    token_account_key.public_key,
                    token_program,
                    min_balance,
                    token.ACCOUNT_SIZE,
                ),
                token.initialize_account(
                    token_account_key.public_key,
                    PublicKey(service_config_resp.token.value),
                    private_key.public_key,
                    token_program,
                ),
                token.set_authority(
                    token_account_key.public_key,
                    private_key.public_key,
                    token.AuthorityType.CloseAccount,
                    token_program,
                    new_authority=subsidizer_id,
                )
            ]
        )
        transaction.set_blockhash(recent_blockhash_resp.blockhash.value)
        transaction.sign([private_key, token_account_key])
        if subsidizer:
            transaction.sign([subsidizer])

        self._internal_client.create_solana_account(transaction, commitment)

    def _resolve_and_submit_solana_payment(
        self, payment: Payment, commitment: Commitment,
        sender_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
        dest_resolution: Optional[AccountResolution] = AccountResolution.PREFERRED,
    ) -> SubmitTransactionResult:
        service_config = self._internal_client.get_service_config()
        if not service_config.subsidizer_account.value and not payment.subsidizer:
            raise NoSubsidizerError()

        result = self._submit_solana_payment_tx(payment, service_config, commitment)
        if result.errors and isinstance(result.errors.tx_error, AccountNotFoundError):
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

        if result.errors and isinstance(result.errors.tx_error, AccountNotFoundError):
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
            instructions = [memo.memo_instruction(payment.memo)]
        elif self._app_index > 0:
            if payment.invoice:
                invoice_list = InvoiceList(invoices=[payment.invoice])
            fk = invoice_list.get_sha_224_hash() if payment.invoice else b''
            m = AgoraMemo.new(1, payment.tx_type, self._app_index, fk)
            instructions = [memo.memo_instruction(base64.b64encode(m.val).decode('utf-8'))]

        sender = transfer_sender if transfer_sender else payment.sender.public_key
        instructions.append(token.transfer(sender, payment.destination, payment.sender.public_key,
                                           payment.quarks, token_program))

        tx = solana.Transaction.new(subsidizer_id, instructions)
        if payment.subsidizer:
            signers = [payment.subsidizer, payment.sender]
        else:
            signers = [payment.sender]

        return self._sign_and_submit_solana_tx(signers, tx, commitment, invoice_list=invoice_list,
                                               dedupe_id=payment.dedupe_id)

    def _submit_solana_earn_batch_tx(
        self, batch: EarnBatch, service_config: tx_pb.GetServiceConfigResponse, commitment: Commitment,
        transfer_sender: Optional[PublicKey] = None,
    ) -> SubmitTransactionResult:
        token_program = PublicKey(service_config.token_program.value)
        subsidizer_id = (batch.subsidizer.public_key if batch.subsidizer
                         else PublicKey(service_config.subsidizer_account.value))

        transfer_sender = transfer_sender if transfer_sender else batch.sender.public_key
        instructions = [
            token.transfer(transfer_sender, earn.destination, batch.sender.public_key, earn.quarks, token_program)
            for earn in batch.earns]

        invoices = [earn.invoice for earn in batch.earns if earn.invoice]
        invoice_list = InvoiceList(invoices) if invoices else None
        if batch.memo:
            instructions = [memo.memo_instruction(batch.memo)] + instructions
        elif self._app_index > 0:
            fk = invoice_list.get_sha_224_hash() if invoice_list else b''
            agora_memo = AgoraMemo.new(1, TransactionType.EARN, self._app_index, fk)
            instructions = [memo.memo_instruction(base64.b64encode(agora_memo.val).decode('utf-8'))] + instructions

        tx = solana.Transaction.new(subsidizer_id, instructions)
        if batch.subsidizer:
            signers = [batch.subsidizer, batch.sender]
        else:
            signers = [batch.sender]

        return self._sign_and_submit_solana_tx(signers, tx, commitment, invoice_list=invoice_list,
                                               dedupe_id=batch.dedupe_id)

    def _sign_and_submit_solana_tx(
        self, signers: List[PrivateKey], tx: solana.Transaction, commitment: Commitment,
        invoice_list: Optional[InvoiceList] = None, dedupe_id: Optional[bytes] = None,
    ):
        def _get_blockhash_and_submit():
            recent_blockhash = self._internal_client.get_recent_blockhash().blockhash.value
            tx.set_blockhash(recent_blockhash)
            tx.sign(signers)

            result = self._internal_client.submit_solana_transaction(tx, invoice_list=invoice_list,
                                                                     commitment=commitment, dedupe_id=dedupe_id)
            if result.errors and isinstance(result.errors.tx_error, BadNonceError):
                raise result.errors.tx_error

            return result

        return retry(self._nonce_retry_strategies, _get_blockhash_and_submit)
