import base64
from concurrent import futures
from typing import Tuple

import grpc
import grpc_testing
import pytest
from agoraapi.account.v4 import account_service_pb2 as account_pb_v4
from agoraapi.airdrop.v4 import airdrop_service_pb2 as airdrop_pb_v4
from agoraapi.common.v3 import model_pb2 as model_pb_v3
from agoraapi.common.v4 import model_pb2 as model_pb_v4
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb_v4

from agora import solana
from agora.client.client import _NON_RETRIABLE_ERRORS
from agora.client.internal import InternalClient
from agora.error import AccountExistsError, AccountNotFoundError, Error, TransactionRejectedError, BadNonceError, \
    InsufficientBalanceError, PayerRequiredError, AlreadySubmittedError
from agora.keys import PrivateKey
from agora.model import TransactionType, AgoraMemo, InvoiceList, Invoice, LineItem
from agora.model.transaction import TransactionState
from agora.retry import NonRetriableErrorsStrategy, LimitStrategy
from agora.solana import Transaction, Commitment
from agora.solana import token, memo
from agora.solana.transaction import HASH_LENGTH
from agora.utils import user_agent
from agora.version import VERSION
from tests.utils import generate_keys

_recent_blockhash = bytes(HASH_LENGTH)
_recent_blockhash_resp = tx_pb_v4.GetRecentBlockhashResponse(
    blockhash=model_pb_v4.Blockhash(value=_recent_blockhash)
)

_min_balance = 2039280
_min_balance_resp = tx_pb_v4.GetMinimumBalanceForRentExemptionResponse(lamports=_min_balance)

_subsidizer = PrivateKey.random().public_key
_token = PrivateKey.random().public_key
_service_config_resp = tx_pb_v4.GetServiceConfigResponse(
    subsidizer_account=model_pb_v4.SolanaAccountId(value=_subsidizer.raw),
    token=model_pb_v4.SolanaAccountId(value=_token.raw),
)


@pytest.fixture(scope='class')
def grpc_channel():
    return grpc_testing.channel([
        account_pb_v4.DESCRIPTOR.services_by_name['Account'],
        airdrop_pb_v4.DESCRIPTOR.services_by_name['Airdrop'],
        tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'],
    ], grpc_testing.strict_real_time)


@pytest.fixture(scope='class', autouse=True)
def executor():
    executor = futures.ThreadPoolExecutor(1)
    yield executor
    executor.shutdown(wait=False)


@pytest.fixture(scope='class')
def no_retry_client(grpc_channel) -> InternalClient:
    """Returns an AgoraClient that has an app index and no retrying configured.
    """
    return InternalClient(grpc_channel, [])


@pytest.fixture(scope='class')
def retry_client(grpc_channel):
    """Returns an AgoraClient that has retrying configured for non-nonce-related errors.
    """
    retry_strategies = [
        NonRetriableErrorsStrategy(_NON_RETRIABLE_ERRORS),
        LimitStrategy(3),
    ]
    return InternalClient(grpc_channel, retry_strategies)


class TestInternalClientV4:
    def test_get_blockchain_version(self, grpc_channel, executor, no_retry_client):
        future = executor.submit(no_retry_client.get_blockchain_version)

        md, request, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetMinimumKinVersion']
        )
        resp = tx_pb_v4.GetMinimumKinVersionResponse(version=4)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')
        TestInternalClientV4._assert_metadata(md)

        assert future.result() == 4

    def test_create_solana_account(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_create_tx()

        # Test default commitment
        future = executor.submit(no_retry_client.create_solana_account, tx)

        req = self._set_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())
        assert req.transaction.value == tx.marshal()
        assert req.commitment == model_pb_v4.Commitment.SINGLE

        assert not future.result()

        # Test other commitment
        future = executor.submit(no_retry_client.create_solana_account, tx, Commitment.MAX)

        req = self._set_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())
        assert req.transaction.value == tx.marshal()
        assert req.commitment == model_pb_v4.Commitment.MAX

        assert not future.result()

    @pytest.mark.parametrize(
        "result, error_type",
        [
            (account_pb_v4.CreateAccountResponse.Result.EXISTS, AccountExistsError),
            (account_pb_v4.CreateAccountResponse.Result.PAYER_REQUIRED, PayerRequiredError),
            (account_pb_v4.CreateAccountResponse.Result.BAD_NONCE, BadNonceError),
        ]
    )
    def test_create_solana_account_errors(self, grpc_channel, executor, no_retry_client, result, error_type):
        tx = self._gen_create_tx()

        future = executor.submit(no_retry_client.create_solana_account, tx)

        resp = account_pb_v4.CreateAccountResponse(result=result)
        req = self._set_create_account_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        with pytest.raises(error_type):
            future.result()

    def test_get_account_info(self, grpc_channel, executor, no_retry_client):
        private_key = PrivateKey.random()
        future = executor.submit(no_retry_client.get_solana_account_info, private_key.public_key)

        resp = account_pb_v4.GetAccountInfoResponse(account_info=account_pb_v4.AccountInfo(
            account_id=model_pb_v4.SolanaAccountId(value=private_key.public_key.raw),
            balance=10,
        ))
        req = self._set_get_account_info_resp(grpc_channel, resp)
        assert req.account_id.value == private_key.public_key.raw

        account_info = future.result()
        assert account_info.account_id == private_key.public_key
        assert account_info.balance == 10

    def test_get_account_info_not_found(self, grpc_channel, executor, no_retry_client):
        private_key = PrivateKey.random()
        future = executor.submit(no_retry_client.get_solana_account_info, private_key.public_key)

        resp = account_pb_v4.GetAccountInfoResponse(result=account_pb_v4.GetAccountInfoResponse.Result.NOT_FOUND)
        req = self._set_get_account_info_resp(grpc_channel, resp)
        assert req.account_id.value == private_key.public_key.raw

        with pytest.raises(AccountNotFoundError):
            future.result()

    def test_resolve_token_accounts(self, grpc_channel, executor, no_retry_client):
        owner = PrivateKey.random().public_key
        close_authority = PrivateKey.random().public_key
        token_accounts = [priv.public_key for priv in generate_keys(2)]

        # account info not requested, only IDs available
        future = executor.submit(no_retry_client.resolve_token_accounts, owner, False)
        resp = account_pb_v4.ResolveTokenAccountsResponse(
            token_accounts=[
                model_pb_v4.SolanaAccountId(
                    value=token_account.raw
                ) for token_account in token_accounts
            ]
        )
        req = self._set_resolve_token_accounts_resp(grpc_channel, resp)
        assert req.account_id.value == owner.raw
        assert not req.include_account_info

        token_account_infos = future.result()
        assert len(token_account_infos) == 2
        for idx, token_account in enumerate(token_accounts):
            account_info = token_account_infos[idx]
            assert account_info.account_id == token_account
            assert not account_info.balance
            assert not account_info.owner
            assert not account_info.close_authority

        # account info not requested, account infos available
        future = executor.submit(no_retry_client.resolve_token_accounts, owner, False)
        resp = account_pb_v4.ResolveTokenAccountsResponse(
            token_account_infos=[
                account_pb_v4.AccountInfo(
                    account_id=model_pb_v4.SolanaAccountId(
                        value=token_account.raw
                    ),
                ) for token_account in token_accounts
            ],
            token_accounts=[
                model_pb_v4.SolanaAccountId(
                    value=token_account.raw
                ) for token_account in token_accounts
            ]
        )
        req = self._set_resolve_token_accounts_resp(grpc_channel, resp)
        assert req.account_id.value == owner.raw
        assert not req.include_account_info

        token_account_infos = future.result()
        assert len(token_account_infos) == 2
        for idx, token_account in enumerate(token_accounts):
            account_info = token_account_infos[idx]
            assert account_info.account_id == token_account
            assert not account_info.balance
            assert not account_info.owner
            assert not account_info.close_authority

        # account info requested
        future = executor.submit(no_retry_client.resolve_token_accounts, owner, True)
        resp = account_pb_v4.ResolveTokenAccountsResponse(
            token_account_infos=[
                account_pb_v4.AccountInfo(
                    account_id=model_pb_v4.SolanaAccountId(
                        value=token_account.raw
                    ),
                    balance=10 + idx,
                    owner=model_pb_v4.SolanaAccountId(
                        value=owner.raw,
                    ),
                    close_authority=model_pb_v4.SolanaAccountId(
                        value=close_authority.raw
                    )
                ) for idx, token_account in enumerate(token_accounts)
            ],
        )
        req = self._set_resolve_token_accounts_resp(grpc_channel, resp)
        assert req.account_id.value == owner.raw
        assert req.include_account_info

        token_account_infos = future.result()
        assert len(token_account_infos) == 2
        for idx, token_account in enumerate(token_accounts):
            account_info = token_account_infos[idx]
            assert account_info.account_id == token_account
            assert account_info.balance == 10 + idx
            assert account_info.owner == owner
            assert account_info.close_authority == close_authority

        # account info requested but not available
        future = executor.submit(no_retry_client.resolve_token_accounts, owner, True)
        resp = account_pb_v4.ResolveTokenAccountsResponse(
            token_accounts=[
                model_pb_v4.SolanaAccountId(
                    value=token_account.raw
                ) for token_account in token_accounts
            ],
        )
        req = self._set_resolve_token_accounts_resp(grpc_channel, resp)
        assert req.account_id.value == owner.raw
        assert req.include_account_info

        with pytest.raises(Error) as e:
            future.result()
        assert 'account info' in str(e)

    def test_get_transaction(self, grpc_channel, executor, no_retry_client):
        source, dest = [key.public_key for key in generate_keys(2)]
        transaction_id = b'someid'
        future = executor.submit(no_retry_client.get_transaction, transaction_id)

        agora_memo = AgoraMemo.new(1, TransactionType.SPEND, 0, b'')
        tx = Transaction.new(PrivateKey.random().public_key, [
            memo.memo_instruction(base64.b64encode(agora_memo.val).decode('utf-8')),
            token.transfer(source, dest, PrivateKey.random().public_key, 100),
        ])

        resp = tx_pb_v4.GetTransactionResponse(
            state=tx_pb_v4.GetTransactionResponse.State.SUCCESS,
            item=tx_pb_v4.HistoryItem(
                transaction_id=model_pb_v4.TransactionId(
                    value=transaction_id,
                ),
                solana_transaction=model_pb_v4.Transaction(
                    value=tx.marshal(),
                ),
                payments=[
                    tx_pb_v4.HistoryItem.Payment(
                        source=model_pb_v4.SolanaAccountId(value=source.raw),
                        destination=model_pb_v4.SolanaAccountId(value=dest.raw),
                        amount=100,
                    )
                ],
                invoice_list=model_pb_v3.InvoiceList(
                    invoices=[
                        model_pb_v3.Invoice(
                            items=[
                                model_pb_v3.Invoice.LineItem(title='t1', amount=15),
                            ]
                        ),
                    ]
                )
            ),
        )
        req = self._set_get_transaction_resp(grpc_channel, resp)
        assert req.transaction_id.value == transaction_id

        tx_data = future.result()
        assert tx_data.tx_id == transaction_id
        assert tx_data.transaction_state == TransactionState.SUCCESS
        assert len(tx_data.payments) == 1
        assert not tx_data.error

        p = tx_data.payments[0]
        assert p.sender.raw == source.raw
        assert p.destination.raw == dest.raw
        assert p.tx_type == TransactionType.SPEND
        assert p.quarks == 100
        assert p.invoice.to_proto().SerializeToString() == resp.item.invoice_list.invoices[0].SerializeToString()
        assert not p.memo

    def test_get_transaction_not_successful(self, grpc_channel, executor, no_retry_client):
        transaction_id = b'someid'
        future = executor.submit(no_retry_client.get_transaction, transaction_id)

        resp = tx_pb_v4.GetTransactionResponse(
            state=tx_pb_v4.GetTransactionResponse.State.FAILED,
        )
        req = self._set_get_transaction_resp(grpc_channel, resp)
        assert req.transaction_id.value == transaction_id

        tx_data = future.result()
        assert tx_data.tx_id == transaction_id
        assert tx_data.transaction_state == TransactionState.FAILED
        assert len(tx_data.payments) == 0
        assert not tx_data.error

    def test_sign_transaction(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        il = self._gen_invoice_list()

        # OK response
        future = executor.submit(no_retry_client.sign_transaction, tx, il)
        tx_sig = bytes(solana.SIGNATURE_LENGTH)
        resp = tx_pb_v4.SignTransactionResponse(
            result=tx_pb_v4.SignTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_sign_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()
        assert req.invoice_list == il.to_proto()

        result = future.result()
        assert result.tx_id == tx_sig
        assert not result.invoice_errors

        # Rejected
        future = executor.submit(no_retry_client.sign_transaction, tx)
        resp = tx_pb_v4.SignTransactionResponse(
            result=tx_pb_v4.SignTransactionResponse.Result.REJECTED,
        )
        req = self._set_sign_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()
        assert not req.invoice_list.invoices

        with pytest.raises(TransactionRejectedError):
            future.result()

        # Invoice Errors
        future = executor.submit(no_retry_client.sign_transaction, tx, il)
        invoice_errors = [
            model_pb_v3.InvoiceError(
                op_index=0,
                invoice=il.invoices[0].to_proto(),
                reason=model_pb_v3.InvoiceError.Reason.SKU_NOT_FOUND,
            ),
        ]
        resp = tx_pb_v4.SignTransactionResponse(
            result=tx_pb_v4.SignTransactionResponse.Result.INVOICE_ERROR,
            invoice_errors=invoice_errors,
        )
        req = self._set_sign_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()
        assert req.invoice_list == il.to_proto()

        result = future.result()
        assert not result.tx_id
        assert len(result.invoice_errors) == 1
        assert result.invoice_errors[0] == invoice_errors[0]

    def test_submit_transaction(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        il = self._gen_invoice_list()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx, il)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()
        assert req.invoice_list == il.to_proto()

        result = future.result()
        assert result.tx_id == tx_sig
        assert not result.errors
        assert not result.invoice_errors

    def test_submit_transaction_already_submitted(self, grpc_channel, executor, retry_client):
        tx = self._gen_tx()
        tx_sig = b'somesig'

        # Receive ALREADY_SUBMITTED on first attempt - should result in an error
        future = executor.submit(retry_client.submit_solana_transaction, tx)
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.ALREADY_SUBMITTED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()
        assert not req.invoice_list.invoices

        with pytest.raises(AlreadySubmittedError):
            future.result()

        future = executor.submit(retry_client.submit_solana_transaction, tx)

        # Internal error first attempt: should retry
        md, req, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['SubmitTransaction']
        )
        rpc.terminate(tx_pb_v4.SubmitTransactionResponse(), (), grpc.StatusCode.INTERNAL, '')
        assert req.transaction.value == tx.marshal()

        # ALREADY_SUBMITTED second attempt: should look like a success
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.ALREADY_SUBMITTED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()
        assert not req.invoice_list.invoices

        result = future.result()
        assert result.tx_id == tx_sig
        assert not result.errors
        assert not result.invoice_errors

    def test_submit_transaction_invoice_error(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.INVOICE_ERROR,
            signature=model_pb_v4.TransactionSignature(value=tx_sig),
            invoice_errors=[
                model_pb_v3.InvoiceError(
                    op_index=0,
                    invoice=model_pb_v3.Invoice(items=[
                        model_pb_v3.Invoice.LineItem(
                            title='title',
                            amount=10,
                        ),
                    ]),
                    reason=model_pb_v3.InvoiceError.Reason.ALREADY_PAID,
                ),
            ],
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        result = future.result()
        assert result.tx_id == tx_sig
        assert not result.errors
        assert result.invoice_errors == resp.invoice_errors

    def test_submit_transaction_rejected(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.REJECTED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        with pytest.raises(TransactionRejectedError):
            future.result()

    def test_submit_transaction_payer_required(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.PAYER_REQUIRED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        with pytest.raises(PayerRequiredError):
            future.result()

    def test_submit_transaction_failed(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig),
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.BAD_NONCE,
            ),
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        result = future.result()
        assert result.tx_id == tx_sig
        assert result.errors
        assert isinstance(result.errors.tx_error, BadNonceError)
        assert len(result.errors.op_errors) == 1
        assert isinstance(result.errors.op_errors[0], BadNonceError)
        assert isinstance(result.errors.payment_errors[0], BadNonceError)
        assert not result.invoice_errors

    def test_submit_transaction_unexpected_result(self, grpc_channel, executor, no_retry_client):
        tx = self._gen_tx()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.PAYER_REQUIRED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig),
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        with pytest.raises(Error):
            future.result()

    def test_minimum_balance(self, grpc_channel, executor, no_retry_client):
        future = executor.submit(no_retry_client.get_minimum_balance_for_rent_exception)
        self._set_get_min_balance_response(grpc_channel)

        result = future.result()
        assert result == _min_balance

    def test_request_airdrop(self, grpc_channel, executor, no_retry_client):
        public_key = PrivateKey.random().public_key
        future = executor.submit(no_retry_client.request_airdrop, public_key, 100, Commitment.MAX)

        tx_sig = b'somesig'
        resp = airdrop_pb_v4.RequestAirdropResponse(result=airdrop_pb_v4.RequestAirdropResponse.Result.OK,
                                                    signature=model_pb_v4.TransactionSignature(value=tx_sig))
        req = self._set_request_airdrop_resp(grpc_channel, resp)
        assert req.account_id.value == public_key.raw
        assert req.quarks == 100
        assert req.commitment == Commitment.MAX

        assert future.result() == tx_sig

    def test_request_airdrop_not_found(self, grpc_channel, executor, no_retry_client):
        public_key = PrivateKey.random().public_key
        future = executor.submit(no_retry_client.request_airdrop, public_key, 100)

        resp = airdrop_pb_v4.RequestAirdropResponse(result=airdrop_pb_v4.RequestAirdropResponse.Result.NOT_FOUND)
        req = self._set_request_airdrop_resp(grpc_channel, resp)
        assert req.account_id.value == public_key.raw
        assert req.quarks == 100

        with pytest.raises(AccountNotFoundError):
            future.result()

    def test_request_airdrop_insufficient_kin(self, grpc_channel, executor, no_retry_client):
        public_key = PrivateKey.random().public_key

        future = executor.submit(no_retry_client.request_airdrop, public_key, 100)
        resp = airdrop_pb_v4.RequestAirdropResponse(result=airdrop_pb_v4.RequestAirdropResponse.Result.INSUFFICIENT_KIN)
        req = self._set_request_airdrop_resp(grpc_channel, resp)
        assert req.account_id.value == public_key.raw
        assert req.quarks == 100

        with pytest.raises(InsufficientBalanceError):
            future.result()

    def test_get_service_config_cache(self, grpc_channel, executor, no_retry_client):
        no_retry_client._response_cache.clear_all()

        future = executor.submit(no_retry_client.get_service_config)
        self._set_get_service_config_resp(grpc_channel)
        assert future.result() == _service_config_resp

        # Result should be cached
        assert no_retry_client.get_service_config() == _service_config_resp

    @staticmethod
    def _set_create_account_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.CreateAccountResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> account_pb_v4.CreateAccountRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb_v4.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_get_account_info_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.GetAccountInfoResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> account_pb_v4.GetAccountInfoRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb_v4.DESCRIPTOR.services_by_name['Account'].methods_by_name['GetAccountInfo']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_resolve_token_accounts_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.ResolveTokenAccountsResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> account_pb_v4.ResolveTokenAccountsRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb_v4.DESCRIPTOR.services_by_name['Account'].methods_by_name['ResolveTokenAccounts']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_get_transaction_resp(
        channel: grpc_testing.Channel, resp: tx_pb_v4.GetTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> tx_pb_v4.GetTransactionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_sign_transaction_resp(
        channel: grpc_testing.Channel, resp: tx_pb_v4.SignTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> tx_pb_v4.SignTransactionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['SignTransaction']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_submit_transaction_resp(
        channel: grpc_testing.Channel, resp: tx_pb_v4.SubmitTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> tx_pb_v4.SubmitTransactionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['SubmitTransaction']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_request_airdrop_resp(
        channel: grpc_testing.Channel, resp: airdrop_pb_v4.RequestAirdropResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> airdrop_pb_v4.RequestAirdropRequest:
        md, request, rpc = channel.take_unary_unary(
            airdrop_pb_v4.DESCRIPTOR.services_by_name['Airdrop'].methods_by_name['RequestAirdrop']
        )
        rpc.terminate(resp, (), status, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_get_service_config_resp(
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetServiceConfigRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetServiceConfig']
        )
        rpc.terminate(_service_config_resp, (), grpc.StatusCode.OK, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_get_recent_blockhash_resp(
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetRecentBlockhashRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetRecentBlockhash']
        )
        rpc.terminate(_recent_blockhash_resp, (), grpc.StatusCode.OK, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _set_get_min_balance_response(
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetMinimumBalanceForRentExemptionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetMinimumBalanceForRentExemption']
        )
        rpc.terminate(_min_balance_resp, (), grpc.StatusCode.OK, '')

        TestInternalClientV4._assert_metadata(md)
        return request

    @staticmethod
    def _assert_metadata(md: Tuple[Tuple, ...]):
        assert len(md) >= 3
        assert md[0] == user_agent(VERSION)
        assert md[1] == ('kin-version', '4')
        if len(md) == 4:
            assert md[2] == ('app-index', '1')


    @staticmethod
    def _gen_tx():
        sender, dest, owner = generate_keys(3)
        return solana.Transaction.new(
            _subsidizer,
            [
                token.transfer(sender, dest, owner, 0)
            ]
        )

    @staticmethod
    def _gen_create_tx():
        private_key = PrivateKey.random()
        create_instruction, addr = token.create_associated_token_account(
            _subsidizer,
            private_key.public_key,
            _token)

        return solana.Transaction.new(
            _subsidizer,
            [
                create_instruction,
                token.set_authority(
                    addr,
                    private_key.public_key,
                    token.AuthorityType.CLOSE_ACCOUNT,
                    new_authority=_subsidizer,
                )
            ]
        )

    @staticmethod
    def _gen_invoice_list():
        return InvoiceList(
            [
                Invoice(
                    [
                        LineItem('Item1', 10),
                    ]
                )
            ]
        )
