from typing import List, Optional

import grpc
from agoraapi.account.v3 import account_service_pb2 as account_pb_v3, account_service_pb2_grpc as account_pb_grpc_v3
from agoraapi.account.v4 import account_service_pb2 as account_pb_v4, account_service_pb2_grpc as account_pb_grpc_v4
from agoraapi.airdrop.v4 import airdrop_service_pb2 as airdrop_pb_v4, airdrop_service_pb2_grpc as airdrop_pb_grpc_v4
from agoraapi.common.v3 import model_pb2 as model_pb_v3
from agoraapi.common.v4 import model_pb2 as model_pb_v4
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb_v3, transaction_service_pb2_grpc as tx_pb_grpc_v3
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb_v4, transaction_service_pb2_grpc as tx_pb_grpc_v4

from agora.cache.cache import LRUCache
from agora.error import BlockchainVersionError, AccountExistsError, AccountNotFoundError, TransactionRejectedError, \
    TransactionErrors, Error, InsufficientBalanceError, PayerRequiredError, NoSubsidizerError, AlreadySubmittedError, \
    BadNonceError
from agora.keys import PrivateKey, PublicKey
from agora.model import AccountInfo, TransactionData, TransactionState, InvoiceList
from agora.retry import Strategy, retry
from agora.solana import Transaction, token, system
from agora.solana.commitment import Commitment
from agora.utils import user_agent
from agora.version import VERSION

_GRPC_TIMEOUT_SECONDS = 10
_SERVICE_CONFIG_CACHE_KEY = b'GetServiceConfig'


class SubmitTransactionResult:
    def __init__(self, tx_id: Optional[bytes] = None,
                 invoice_errors: Optional[List[model_pb_v3.InvoiceError]] = None,
                 tx_error: Optional[TransactionErrors] = None):
        self.tx_id = tx_id if tx_id else bytes(32)
        self.invoice_errors = invoice_errors if invoice_errors else []
        self.tx_error = tx_error


class InternalClient:
    """A low level client used for interacting with Agora APIs directly. The API for this client is _not_ stable and is
        not intended for general use. It is only exposed in case there needs to be low level access to Agora (beyond the
        gRPC directly). However, there is no stability guarantees between releases, or during a migration event.
        """

    def __init__(
        self, grpc_channel: grpc.Channel, retry_strategies: List[Strategy], kin_version: int,
        desired_kin_version: Optional[int] = None,
    ):
        self._account_stub_v3 = account_pb_grpc_v3.AccountStub(grpc_channel)
        self._transaction_stub_v3 = tx_pb_grpc_v3.TransactionStub(grpc_channel)

        self._account_stub_v4 = account_pb_grpc_v4.AccountStub(grpc_channel)
        self._transaction_stub_v4 = tx_pb_grpc_v4.TransactionStub(grpc_channel)
        self._airdrop_stub_v4 = airdrop_pb_grpc_v4.AirdropStub(grpc_channel)

        self._retry_strategies = retry_strategies
        self._kin_version = kin_version
        self._desired_kin_version = desired_kin_version

        if self._desired_kin_version:
            self._metadata = (
                user_agent(VERSION),
                ('kin-version', str(self._kin_version)),
                ('desired-kin-version', str(self._desired_kin_version)),
            )
        else:
            self._metadata = (
                user_agent(VERSION),
                ('kin-version', str(self._kin_version)),
            )

        # Currently only service config is cached, so limit to 1 entry
        self._response_cache = LRUCache(300, 1)

    def set_kin_version(self, kin_version: int):
        self._kin_version = kin_version

        if self._desired_kin_version:
            self._metadata = (
                user_agent(VERSION),
                ('kin-version', str(self._kin_version)),
                ('desired-kin-version', str(self._desired_kin_version)),
            )
        else:
            self._metadata = (
                user_agent(VERSION),
                ('kin-version', str(self._kin_version)),
            )

    def get_blockchain_version(self) -> int:
        """Get the blockchain version to use.

        :return: the blockchain version
        """

        def _get_blockchain_version():
            return self._transaction_stub_v4.GetMinimumKinVersion(
                tx_pb_v4.GetMinimumKinVersionRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp = retry(self._retry_strategies, _get_blockchain_version)
        return resp.version

    def create_stellar_account(self, private_key: PrivateKey):
        """Submit a request to Agora to create a Stellar account.

        :param private_key: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account to create
        """

        def _create():
            try:
                resp = self._account_stub_v3.CreateAccount(account_pb_v3.CreateAccountRequest(
                    account_id=model_pb_v3.StellarAccountId(
                        value=private_key.public_key.stellar_address
                    ),
                ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
            except grpc.RpcError as e:
                raise BlockchainVersionError() if self._is_migration_error(e) else e

            if resp.result == account_pb_v3.CreateAccountResponse.Result.EXISTS:
                raise AccountExistsError()

        retry(self._retry_strategies, _create)

    def get_stellar_account_info(self, public_key: PublicKey) -> AccountInfo:
        """Get the info of a Stellar account from Agora.

        :param public_key: The :class:`PublicKey <agora.model.keys.PublicKey>` of the account to request the info for.
        :return: A :class:`AccountInfo <agora.model.account.AccountInfo>` object.
        """

        def _get_account():
            try:
                resp = self._account_stub_v3.GetAccountInfo(account_pb_v3.GetAccountInfoRequest(
                    account_id=model_pb_v3.StellarAccountId(
                        value=public_key.stellar_address
                    ),
                ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
            except grpc.RpcError as e:
                raise BlockchainVersionError() if self._is_migration_error(e) else e

            if resp.result == account_pb_v3.GetAccountInfoResponse.Result.NOT_FOUND:
                raise AccountNotFoundError

            return resp

        resp = retry(self._retry_strategies, _get_account)
        return AccountInfo.from_proto(resp.account_info)

    def get_transaction(
        self, tx_id: bytes, commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> TransactionData:
        """Get a transaction from Agora.

        :param tx_id: The id of the transaction, in bytes.
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use. Only applicable for
            Solana transactions.
        :return: A :class:`TransactionData <agora.model.transaction.TransactionData>` object.
        """

        def _get_transaction():
            req = tx_pb_v4.GetTransactionRequest(
                transaction_id=model_pb_v4.TransactionId(value=tx_id),
                commitment=commitment.to_proto(),
            )
            return self._transaction_stub_v4.GetTransaction(req, metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp = retry(self._retry_strategies, _get_transaction)

        if resp.item.transaction_id.value:
            return TransactionData.from_proto(resp.item, resp.state)

        return TransactionData(tx_id, TransactionState.from_proto_v4(resp.state))

    def submit_stellar_transaction(
        self, tx_bytes: bytes, invoice_list: Optional[InvoiceList] = None
    ) -> SubmitTransactionResult:
        """Submit a Stellar transaction to Agora.

        :param tx_bytes: The transaction envelope xdr, in bytes.
        :param invoice_list: (optional) An :class:`InvoiceList <agora.model.invoice.InvoiceList>` to associate with the
            transaction
        :return: A :class:`SubmitTransactionResult <agora.client.internal.SubmitTransactionResult>` object.
        """

        def _submit():
            req = tx_pb_v3.SubmitTransactionRequest(
                envelope_xdr=tx_bytes,
                invoice_list=invoice_list.to_proto() if invoice_list else None,
            )
            try:
                resp = self._transaction_stub_v3.SubmitTransaction(req, metadata=self._metadata,
                                                                   timeout=_GRPC_TIMEOUT_SECONDS)
            except grpc.RpcError as e:
                raise BlockchainVersionError() if self._is_migration_error(e) else e

            result = SubmitTransactionResult(tx_id=resp.hash.value)
            if resp.result == tx_pb_v3.SubmitTransactionResponse.Result.REJECTED:
                raise TransactionRejectedError()
            elif resp.result == tx_pb_v3.SubmitTransactionResponse.Result.INVOICE_ERROR:
                result.invoice_errors = resp.invoice_errors
            elif resp.result == tx_pb_v3.SubmitTransactionResponse.Result.FAILED:
                result.tx_error = TransactionErrors.from_result(resp.result_xdr)
            elif resp.result != tx_pb_v3.SubmitTransactionResponse.Result.OK:
                raise Error(f'unexpected result from agora: {resp.result}')

            return result

        return retry(self._retry_strategies, _submit)

    def create_solana_account(self, private_key: PrivateKey, commitment: Optional[Commitment] = Commitment.SINGLE,
                              subsidizer: Optional[PrivateKey] = None):
        """Submit a request to Agora to create a Solana account.

        :param private_key: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account to create
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use.
        :param subsidizer: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account to use as the
            transaction payer.
        """

        def _create():
            nonlocal subsidizer

            service_config_resp = self.get_service_config()
            if not service_config_resp.subsidizer_account.value and not subsidizer:
                raise NoSubsidizerError()

            subsidizer_id = (subsidizer.public_key if subsidizer else
                             PublicKey(service_config_resp.subsidizer_account.value))

            recent_blockhash_future = self._transaction_stub_v4.GetRecentBlockhash.future(
                tx_pb_v4.GetRecentBlockhashRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
            min_balance_future = self._transaction_stub_v4.GetMinimumBalanceForRentExemption.future(
                tx_pb_v4.GetMinimumBalanceForRentExemptionRequest(size=token.ACCOUNT_SIZE), metadata=self._metadata,
                timeout=_GRPC_TIMEOUT_SECONDS)
            recent_blockhash_resp = recent_blockhash_future.result()
            min_balance_resp = min_balance_future.result()

            token_program = PublicKey(service_config_resp.token_program.value)
            transaction = Transaction.new(
                subsidizer_id,
                [
                    system.create_account(
                        subsidizer_id,
                        private_key.public_key,
                        token_program,
                        min_balance_resp.lamports,
                        token.ACCOUNT_SIZE,
                    ),
                    token.initialize_account(
                        private_key.public_key,
                        PublicKey(service_config_resp.token.value),
                        private_key.public_key,
                        token_program,
                    ),
                    token.set_authority(
                        private_key.public_key,
                        private_key.public_key,
                        token.AuthorityType.CloseAccount,
                        token_program,
                        new_authority=subsidizer_id,
                    )
                ]
            )
            transaction.set_blockhash(recent_blockhash_resp.blockhash.value)
            transaction.sign([private_key])
            if subsidizer:
                transaction.sign([subsidizer])

            req = account_pb_v4.CreateAccountRequest(
                transaction=model_pb_v4.Transaction(value=transaction.marshal()),
                commitment=commitment.to_proto(),
            )
            resp = self._account_stub_v4.CreateAccount(req, metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

            if resp.result == account_pb_v4.CreateAccountResponse.Result.EXISTS:
                raise AccountExistsError()
            if resp.result == account_pb_v4.CreateAccountResponse.Result.PAYER_REQUIRED:
                raise PayerRequiredError()
            if resp.result == account_pb_v4.CreateAccountResponse.Result.BAD_NONCE:
                raise BadNonceError()
            if resp.result != account_pb_v4.CreateAccountResponse.Result.OK:
                raise Error(f'unexpected result from agora: {resp.result}')

        retry(self._retry_strategies, _create)

    def get_solana_account_info(
        self, public_key: PublicKey, commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> AccountInfo:
        """Get the info of a Solana account from Agora.

        :param public_key: The :class:`PublicKey <agora.model.keys.PublicKey>` of the account to request the info for.
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use.
        :return: A :class:`AccountInfo <agora.model.account.AccountInfo>` object.
        """

        def _get():
            resp = self._account_stub_v4.GetAccountInfo(account_pb_v4.GetAccountInfoRequest(
                account_id=model_pb_v4.SolanaAccountId(
                    value=public_key.raw
                ),
                commitment=commitment.to_proto(),
            ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
            if resp.result == account_pb_v4.GetAccountInfoResponse.Result.NOT_FOUND:
                raise AccountNotFoundError

            return AccountInfo.from_proto_v4(resp.account_info)

        return retry(self._retry_strategies, _get)

    def submit_solana_transaction(
        self, tx_bytes: bytes, invoice_list: Optional[InvoiceList] = None,
        commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> SubmitTransactionResult:
        """Submit a Solana transaction to Agora.

        :param tx_bytes: The transaction, in bytes.
        :param invoice_list: (optional) An :class:`InvoiceList <agora.model.invoice.InvoiceList>` to associate with the
            transaction
        :return: A :class:`SubmitTransactionResult <agora.client.internal.SubmitTransactionResult>` object.
        """

        attempt = 0

        def _submit():
            nonlocal attempt

            attempt += 1
            req = tx_pb_v4.SubmitTransactionRequest(
                transaction=model_pb_v4.Transaction(
                    value=tx_bytes,
                ),
                invoice_list=invoice_list.to_proto() if invoice_list else None,
                commitment=commitment.to_proto(),
            )
            resp = self._transaction_stub_v4.SubmitTransaction(req, metadata=self._metadata,
                                                               timeout=_GRPC_TIMEOUT_SECONDS)

            if resp.result == tx_pb_v4.SubmitTransactionResponse.Result.REJECTED:
                raise TransactionRejectedError()
            if resp.result == tx_pb_v4.SubmitTransactionResponse.Result.PAYER_REQUIRED:
                raise PayerRequiredError()

            result = SubmitTransactionResult(tx_id=resp.signature.value)
            if resp.result == tx_pb_v4.SubmitTransactionResponse.Result.ALREADY_SUBMITTED:
                # If this occurs on the first attempt, it's likely due to the submission of two identical transactions
                # in quick succession and we should raise the error to the caller. Otherwise, it's likely that the
                # transaction completed successfully on a previous attempt that failed due to a transient error.
                if attempt == 1:
                    raise AlreadySubmittedError()
            elif resp.result == tx_pb_v4.SubmitTransactionResponse.Result.FAILED:
                result.tx_error = TransactionErrors.from_proto_error(resp.transaction_error)
            elif resp.result == tx_pb_v4.SubmitTransactionResponse.Result.INVOICE_ERROR:
                result.invoice_errors = resp.invoice_errors
            elif resp.result != tx_pb_v4.SubmitTransactionResponse.Result.OK:
                raise Error(f'unexpected result from agora: {resp.result}')

            return result

        return retry(self._retry_strategies, _submit)

    def get_service_config(self) -> tx_pb_v4.GetServiceConfigResponse:
        resp_bytes = self._response_cache.get(_SERVICE_CONFIG_CACHE_KEY)
        if resp_bytes:
            resp = tx_pb_v4.GetServiceConfigResponse()
            resp.ParseFromString(resp_bytes)
            return resp

        def _get_config():
            return self._transaction_stub_v4.GetServiceConfig(
                tx_pb_v4.GetServiceConfigRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp = retry(self._retry_strategies, _get_config)
        self._response_cache.set(_SERVICE_CONFIG_CACHE_KEY, resp.SerializeToString(), 1800)  # cache for 30 min
        return resp

    def get_recent_blockhash(self) -> tx_pb_v4.GetRecentBlockhashResponse:
        def _get_recent_blockhash():
            return self._transaction_stub_v4.GetRecentBlockhash(
                tx_pb_v4.GetRecentBlockhashRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        return retry(self._retry_strategies, _get_recent_blockhash)

    def request_airdrop(
        self, public_key: PublicKey, quarks: int, commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> bytes:
        def _request_airdrop():
            resp = self._airdrop_stub_v4.RequestAirdrop(
                airdrop_pb_v4.RequestAirdropRequest(
                    account_id=model_pb_v4.SolanaAccountId(
                        value=public_key.raw
                    ),
                    quarks=quarks,
                    commitment=commitment.to_proto(),
                ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS
            )
            if resp.result == airdrop_pb_v4.RequestAirdropResponse.Result.OK:
                return resp.signature.value
            if resp.result == airdrop_pb_v4.RequestAirdropResponse.Result.NOT_FOUND:
                raise AccountNotFoundError()
            if resp.result == airdrop_pb_v4.RequestAirdropResponse.INSUFFICIENT_KIN:
                raise InsufficientBalanceError()

            raise Error(f'unexpected response from airdrop service: {resp.result}')

        return retry(self._retry_strategies, _request_airdrop)

    def resolve_token_accounts(self, public_key: PublicKey) -> List[PublicKey]:
        def _resolve():
            return self._account_stub_v4.ResolveTokenAccounts(account_pb_v4.ResolveTokenAccountsRequest(
                account_id=model_pb_v4.SolanaAccountId(value=public_key.raw)
            ))

        resp = retry(self._retry_strategies, _resolve)
        return [PublicKey(token_account.value) for token_account in resp.token_accounts]

    def _is_migration_error(self, e: grpc.RpcError) -> bool:
        if e.code() == grpc.StatusCode.FAILED_PRECONDITION and self.get_blockchain_version() > self._kin_version:
            return True

        return False
