from typing import List, Optional

import grpc
from agoraapi.account.v3 import account_service_pb2 as account_pb, account_service_pb2_grpc as account_pb_grpc
from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb, transaction_service_pb2_grpc as tx_pb_grpc

from agora.client.internal.internal import InternalClient, SubmitTransactionResult
from agora.error import TransactionErrors, AccountExistsError, AccountNotFoundError, \
    TransactionNotFoundError, Error, TransactionRejectedError
from agora.model import PrivateKey, TransactionData, AccountInfo, InvoiceList, PublicKey
from agora.retry import Strategy, retry
from agora.utils import user_agent
from agora.version import VERSION

_GRPC_TIMEOUT_SECONDS = 10


class V3InternalClient(InternalClient):
    """ An internal client for interacting with the V3 Agora APIs.

    :param grpc_channel: A GRPC :class:`Channel <grpc.Channel>` object to use for Agora requests.
    :param retry_strategies: A list of :class:`Strategy <agora.retry.Strategy>` to use when retrying requests.
    :param kin_version: (optional) The version of Kin to use. Defaults to using Kin 3.
    """

    def __init__(self, grpc_channel: grpc.Channel, retry_strategies: List[Strategy], kin_version: Optional[int] = 3):
        self._account_stub = account_pb_grpc.AccountStub(grpc_channel)
        self._transaction_stub = tx_pb_grpc.TransactionStub(grpc_channel)

        self._retry_strategies = retry_strategies
        self._kin_version = kin_version
        self._metadata = (
            user_agent(VERSION),
            ('kin-version', str(kin_version)),
        )

    def get_blockchain_version(self) -> int:
        # TODO: make a request to Agora to get the migration status of the blockchain
        return self._kin_version

    def create_account(self, private_key: PrivateKey):
        def _create():
            resp = self._account_stub.CreateAccount(account_pb.CreateAccountRequest(
                account_id=model_pb.StellarAccountId(
                    value=private_key.public_key.stellar_address
                ),
            ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
            if resp.result == account_pb.CreateAccountResponse.Result.EXISTS:
                raise AccountExistsError()

        retry(self._retry_strategies, _create)

    def get_account_info(self, public_key: PublicKey) -> AccountInfo:
        resp = self._account_stub.GetAccountInfo(account_pb.GetAccountInfoRequest(
            account_id=model_pb.StellarAccountId(
                value=public_key.stellar_address
            ),
        ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
        if resp.result == account_pb.GetAccountInfoResponse.Result.NOT_FOUND:
            raise AccountNotFoundError

        return resp.account_info

    def get_transaction(self, tx_hash: bytes) -> TransactionData:
        resp = self._transaction_stub.GetTransaction(tx_pb.GetTransactionRequest(
            transaction_hash=model_pb.TransactionHash(
                value=tx_hash
            )
        ), metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)
        if resp.state is tx_pb.GetTransactionResponse.State.UNKNOWN:
            raise TransactionNotFoundError()
        if resp.state == tx_pb.GetTransactionResponse.State.SUCCESS:
            return TransactionData.from_proto(resp.item, kin_version=self._kin_version)

        raise Error(f'Unexpected transaction state from Agora: {resp.state}')

    def submit_transaction(self, tx_bytes: bytes, invoice_list: Optional[InvoiceList]) -> SubmitTransactionResult:
        def _submit():
            req = tx_pb.SubmitTransactionRequest(
                envelope_xdr=tx_bytes,
                invoice_list=invoice_list.to_proto() if invoice_list else None,
            )
            resp = self._transaction_stub.SubmitTransaction(req, metadata=self._metadata, timeout=_GRPC_TIMEOUT_SECONDS)

            result = SubmitTransactionResult(tx_hash=resp.hash.value)
            if resp.result == tx_pb.SubmitTransactionResponse.Result.REJECTED:
                raise TransactionRejectedError()
            elif resp.result == tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR:
                result.invoice_errors = resp.invoice_errors
            elif resp.result == tx_pb.SubmitTransactionResponse.Result.FAILED:
                result.tx_error = TransactionErrors.from_result(resp.result_xdr)
            elif resp.result != tx_pb.SubmitTransactionResponse.Result.OK:
                raise Error(f'unexpected result from agora: {resp.result}')

            return result

        return retry(self._retry_strategies, _submit)
