from typing import List, Optional

import grpc
from agoraapi.account.v4 import account_service_pb2 as account_pb, account_service_pb2_grpc as account_pb_grpc
from agoraapi.airdrop.v4 import airdrop_service_pb2 as airdrop_pb, airdrop_service_pb2_grpc as airdrop_pb_grpc
from agoraapi.common.v3 import model_pb2 as model_pb_v3
from agoraapi.common.v4 import model_pb2 as model_pb
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb, transaction_service_pb2_grpc as tx_pb_grpc

from agora import solana
from agora.cache.cache import LRUCache
from agora.error import AccountExistsError, AccountNotFoundError, TransactionRejectedError, \
    TransactionErrors, Error, InsufficientBalanceError, PayerRequiredError, AlreadySubmittedError, \
    BadNonceError, TransactionError
from agora.keys import PublicKey
from agora.model import AccountInfo, TransactionData, TransactionState, InvoiceList
from agora.retry import Strategy, retry
from agora.solana import token
from agora.solana.commitment import Commitment
from agora.utils import user_agent
from agora.version import VERSION

_GRPC_TIMEOUT_SECONDS = 10
_SERVICE_CONFIG_CACHE_KEY = b'GetServiceConfig'


class SignTransactionResult:
    def __init__(self, tx_id: Optional[bytes] = None, invoice_errors: Optional[List[model_pb_v3.InvoiceError]] = None):
        self.tx_id = tx_id
        self.invoice_errors = invoice_errors if invoice_errors else []


class SubmitTransactionResult:
    def __init__(self, tx_id: Optional[bytes] = None,
                 invoice_errors: Optional[List[model_pb_v3.InvoiceError]] = None,
                 errors: Optional[TransactionErrors] = None):
        self.tx_id = tx_id if tx_id else bytes(32)
        self.invoice_errors = invoice_errors if invoice_errors else []
        self.errors = errors


class InternalClient:
    """A low level client used for interacting with Agora APIs directly. The API for this client is _not_ stable and is
        not intended for general use. It is only exposed in case there needs to be low level access to Agora (beyond the
        gRPC directly). However, there is no stability guarantees between releases, or during a migration event.
        """

    def __init__(
        self, grpc_channel: grpc.Channel, retry_strategies: List[Strategy], app_index: int = 0,
    ):
        self._account_stub_v4 = account_pb_grpc.AccountStub(grpc_channel)
        self._transaction_stub_v4 = tx_pb_grpc.TransactionStub(grpc_channel)
        self._airdrop_stub_v4 = airdrop_pb_grpc.AirdropStub(grpc_channel)

        self._retry_strategies = retry_strategies

        if app_index > 0:
            self._metadata = (
                user_agent(VERSION),
                ('kin-version', "4"),
                ('app-index', str(app_index)),
            )
        else:
            self._metadata = (
                user_agent(VERSION),
                ('kin-version', "4"),
            )

        # Currently only service config is cached, so limit to 1 entry
        self._response_cache = LRUCache(300, 1)

    def get_blockchain_version(self) -> int:
        """Get the blockchain version to use.

        :return: the blockchain version
        """

        def _get_blockchain_version():
            return self._transaction_stub_v4.GetMinimumKinVersion(
                tx_pb.GetMinimumKinVersionRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp = retry(self._retry_strategies, _get_blockchain_version)
        return resp.version

    def create_solana_account(self, tx: solana.Transaction, commitment: Optional[Commitment] = Commitment.SINGLE):
        """Submit a request to Agora to create a Solana account.

        :param tx: The Solana transaction to create an account.
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use.
        """

        def _submit_request():
            req = account_pb.CreateAccountRequest(
                transaction=model_pb.Transaction(value=tx.marshal()),
                commitment=commitment.to_proto(),
            )
            resp = self._account_stub_v4.CreateAccount(req, metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

            if resp.result == account_pb.CreateAccountResponse.Result.EXISTS:
                raise AccountExistsError()
            if resp.result == account_pb.CreateAccountResponse.Result.PAYER_REQUIRED:
                raise PayerRequiredError()
            if resp.result == account_pb.CreateAccountResponse.Result.BAD_NONCE:
                raise BadNonceError()
            if resp.result != account_pb.CreateAccountResponse.Result.OK:
                raise Error(f'unexpected result from agora: {resp.result}')

        retry(self._retry_strategies, _submit_request)

    def get_solana_account_info(
        self, public_key: PublicKey, commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> AccountInfo:
        """Get the info of a Solana account from Agora.

        :param public_key: The :class:`PublicKey <agora.keys.PublicKey>` of the account to request the info for.
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use.
        :return: A :class:`AccountInfo <agora.model.account.AccountInfo>` object.
        """

        def _submit_request():
            resp = self._account_stub_v4.GetAccountInfo(account_pb.GetAccountInfoRequest(
                account_id=model_pb.SolanaAccountId(
                    value=public_key.raw
                ),
                commitment=commitment.to_proto(),
            ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
            if resp.result == account_pb.GetAccountInfoResponse.Result.NOT_FOUND:
                raise AccountNotFoundError

            return AccountInfo.from_proto(resp.account_info)

        return retry(self._retry_strategies, _submit_request)

    def resolve_token_accounts(self, public_key: PublicKey, include_account_info: bool) -> List[AccountInfo]:
        """Resolves token accounts using Agora.

        :param public_key: the public key of the account to resolve token accounts for.
        :param include_account_info: indicates whether to include token account info in the response
        :return: A list of :class:`AccountInfo <agora.model.account.AccountInfo>` objects each representing a token
            account. Information other than AccountInfo.account_id will only be populated if `include_account_info` is
            True.
        """

        def _resolve():
            return self._account_stub_v4.ResolveTokenAccounts(account_pb.ResolveTokenAccountsRequest(
                account_id=model_pb.SolanaAccountId(value=public_key.raw),
                include_account_info=include_account_info,
            ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp = retry(self._retry_strategies, _resolve)

        # This is currently in place for backward compat with the server - `token_accounts` is deprecated
        if resp.token_accounts and len(resp.token_account_infos) != len(resp.token_accounts):
            # If we aren't requesting account info, we can interpolate the results ourselves.
            if not include_account_info:
                return [AccountInfo(PublicKey(a.value)) for a in resp.token_accounts]
            else:
                raise Error('server does not support resolving with account info')

        return [AccountInfo.from_proto(a) for a in resp.token_account_infos]

    def get_transaction(
        self, tx_id: bytes, commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> TransactionData:
        """Get a transaction from Agora.

        :param tx_id: The id of the transaction, in bytes.
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use. Only applicable for
            Solana transactions.
        :return: A :class:`TransactionData <agora.model.transaction.TransactionData>` object.
        """

        def _submit_request():
            req = tx_pb.GetTransactionRequest(
                transaction_id=model_pb.TransactionId(value=tx_id),
                commitment=commitment.to_proto(),
            )
            return self._transaction_stub_v4.GetTransaction(req, metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp = retry(self._retry_strategies, _submit_request)

        if resp.item.transaction_id.value:
            return TransactionData.from_proto(resp.item, resp.state)

        return TransactionData(tx_id, TransactionState.from_proto_v4(resp.state))

    def sign_transaction(
        self, tx: solana.Transaction, invoice_list: Optional[InvoiceList] = None
    ) -> SignTransactionResult:
        """ Submits a transaction

        :param tx:
        :param invoice_list:
        :return: A :class:`SignTransactionResult <agora.client.internal.SignTransactionResult>` object.
        """
        tx_bytes = tx.marshal()

        result = SignTransactionResult()

        def _submit_request():
            req = tx_pb.SignTransactionRequest(
                transaction=model_pb.Transaction(
                    value=tx_bytes,
                ),
                invoice_list=invoice_list.to_proto() if invoice_list else None,
            )
            resp = self._transaction_stub_v4.SignTransaction(req, metadata=self._metadata,
                                                             timeout=_GRPC_TIMEOUT_SECONDS)

            if resp.signature and len(resp.signature.value) == solana.SIGNATURE_LENGTH:
                result.tx_id = resp.signature.value

            if resp.result == tx_pb.SignTransactionResponse.Result.REJECTED:
                raise TransactionRejectedError()
            elif resp.result == tx_pb.SignTransactionResponse.Result.INVOICE_ERROR:
                result.invoice_errors = resp.invoice_errors
            elif resp.result != tx_pb.SignTransactionResponse.Result.OK:
                raise TransactionError(f'unexpected result from agora: {resp.result}', tx_id=resp.signature.value)

            return result

        return retry(self._retry_strategies, _submit_request)

    def submit_solana_transaction(
        self, tx: solana.Transaction, invoice_list: Optional[InvoiceList] = None,
        commitment: Optional[Commitment] = Commitment.SINGLE, dedupe_id: Optional[bytes] = None
    ) -> SubmitTransactionResult:
        """Submit a Solana transaction to Agora.

        :param tx: The Solana transaction.
        :param invoice_list: (optional) An :class:`InvoiceList <agora.model.invoice.InvoiceList>` to associate with the
            transaction
        :param commitment: The :class:`Commitment <agora.solana.commitment.Commitment>` to use.
        :param dedupe_id: The dedupe ID to use for the transaction submission
        :return: A :class:`SubmitTransactionResult <agora.client.internal.SubmitTransactionResult>` object.
        """

        attempt = 0
        tx_bytes = tx.marshal()

        def _submit_request():
            nonlocal attempt

            attempt += 1
            req = tx_pb.SubmitTransactionRequest(
                transaction=model_pb.Transaction(
                    value=tx_bytes,
                ),
                invoice_list=invoice_list.to_proto() if invoice_list else None,
                commitment=commitment.to_proto(),
                dedupe_id=dedupe_id,
            )
            resp = self._transaction_stub_v4.SubmitTransaction(req, metadata=self._metadata,
                                                               timeout=_GRPC_TIMEOUT_SECONDS)

            if resp.result == tx_pb.SubmitTransactionResponse.Result.REJECTED:
                raise TransactionRejectedError()
            if resp.result == tx_pb.SubmitTransactionResponse.Result.PAYER_REQUIRED:
                raise PayerRequiredError()

            result = SubmitTransactionResult(tx_id=resp.signature.value)
            if resp.result == tx_pb.SubmitTransactionResponse.Result.ALREADY_SUBMITTED:
                # If this occurs on the first attempt, it's likely due to the submission of two identical transactions
                # in quick succession and we should raise the error to the caller. Otherwise, it's likely that the
                # transaction completed successfully on a previous attempt that failed due to a transient error.
                if attempt == 1:
                    raise AlreadySubmittedError(tx_id=resp.signature.value)
            elif resp.result == tx_pb.SubmitTransactionResponse.Result.FAILED:
                result.errors = TransactionErrors.from_solana_tx(tx, resp.transaction_error, resp.signature.value)
            elif resp.result == tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR:
                result.invoice_errors = resp.invoice_errors
            elif resp.result != tx_pb.SubmitTransactionResponse.Result.OK:
                raise TransactionError(f'unexpected result from agora: {resp.result}', tx_id=resp.signature.value)

            return result

        return retry(self._retry_strategies, _submit_request)

    def get_service_config(self) -> tx_pb.GetServiceConfigResponse:
        def _submit_request():
            return self._transaction_stub_v4.GetServiceConfig(
                tx_pb.GetServiceConfigRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        resp_bytes = self._response_cache.get(_SERVICE_CONFIG_CACHE_KEY)
        if resp_bytes:
            resp = tx_pb.GetServiceConfigResponse()
            resp.ParseFromString(resp_bytes)
            return resp

        resp = retry(self._retry_strategies, _submit_request)
        self._response_cache.set(_SERVICE_CONFIG_CACHE_KEY, resp.SerializeToString(), 1800)  # cache for 30 min
        return resp

    def get_recent_blockhash(self) -> tx_pb.GetRecentBlockhashResponse:
        def _submit_request():
            return self._transaction_stub_v4.GetRecentBlockhash(
                tx_pb.GetRecentBlockhashRequest(), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

        return retry(self._retry_strategies, _submit_request)

    def get_minimum_balance_for_rent_exception(self) -> int:
        def _submit_request():
            return self._transaction_stub_v4.GetMinimumBalanceForRentExemption(
                tx_pb.GetMinimumBalanceForRentExemptionRequest(size=token.ACCOUNT_SIZE), metadata=self._metadata,
                timeout=_GRPC_TIMEOUT_SECONDS
            ).lamports

        return retry(self._retry_strategies, _submit_request)

    def request_airdrop(
        self, public_key: PublicKey, quarks: int, commitment: Optional[Commitment] = Commitment.SINGLE
    ) -> bytes:
        def _request_airdrop():
            resp = self._airdrop_stub_v4.RequestAirdrop(
                airdrop_pb.RequestAirdropRequest(
                    account_id=model_pb.SolanaAccountId(
                        value=public_key.raw
                    ),
                    quarks=quarks,
                    commitment=commitment.to_proto(),
                ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS
            )
            if resp.result == airdrop_pb.RequestAirdropResponse.Result.OK:
                return resp.signature.value
            if resp.result == airdrop_pb.RequestAirdropResponse.Result.NOT_FOUND:
                raise AccountNotFoundError()
            if resp.result == airdrop_pb.RequestAirdropResponse.INSUFFICIENT_KIN:
                raise InsufficientBalanceError()

            raise Error(f'unexpected response from airdrop service: {resp.result}')

        return retry(self._retry_strategies, _request_airdrop)
