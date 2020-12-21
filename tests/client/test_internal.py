import base64
import hashlib
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
from agora.client.utils import _generate_token_account
from agora.error import AccountExistsError, AccountNotFoundError, Error, TransactionRejectedError, BadNonceError, \
    InsufficientBalanceError, PayerRequiredError, NoSubsidizerError, AlreadySubmittedError
from agora.keys import PrivateKey
from agora.model import TransactionType, AgoraMemo
from agora.model.transaction import TransactionState
from agora.retry import NonRetriableErrorsStrategy, LimitStrategy
from agora.solana import Transaction
from agora.solana import token
from agora.solana.memo import memo_instruction
from agora.solana.system import decompile_create_account
from agora.solana.token import decompile_initialize_account, transfer, decompile_set_authority
from agora.solana.transaction import HASH_LENGTH, SIGNATURE_LENGTH
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
_token_program = PrivateKey.random().public_key
_service_config_resp = tx_pb_v4.GetServiceConfigResponse(
    subsidizer_account=model_pb_v4.SolanaAccountId(value=_subsidizer.raw),
    token=model_pb_v4.SolanaAccountId(value=_token.raw),
    token_program=model_pb_v4.SolanaAccountId(value=_token_program.raw),
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
    return InternalClient(grpc_channel, [], kin_version=4)


@pytest.fixture(scope='class')
def retry_client(grpc_channel):
    """Returns an AgoraClient that has retrying configured for non-nonce-related errors.
    """
    retry_strategies = [
        NonRetriableErrorsStrategy(_NON_RETRIABLE_ERRORS),
        LimitStrategy(3),
    ]
    return InternalClient(grpc_channel, retry_strategies, kin_version=4)


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
        private_key = PrivateKey.random()
        token_account_key = _generate_token_account(private_key)

        no_retry_client._response_cache.clear_all()
        future = executor.submit(no_retry_client.create_solana_account, private_key)

        self._set_get_service_config_resp(grpc_channel)
        self._set_get_recent_blockhash_resp(grpc_channel)
        self._set_get_min_balance_response(grpc_channel)

        req = self._set_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 3
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert token_account_key.public_key.verify(tx.message.marshal(), tx.signatures[1])
        assert private_key.public_key.verify(tx.message.marshal(), tx.signatures[2])

        sys_create = decompile_create_account(tx.message, 0)
        assert sys_create.funder == _subsidizer
        assert sys_create.address == token_account_key.public_key
        assert sys_create.owner == _token_program
        assert sys_create.lamports == _min_balance
        assert sys_create.size == token.ACCOUNT_SIZE

        token_init = decompile_initialize_account(tx.message, 1, _token_program)
        assert token_init.account == token_account_key.public_key
        assert token_init.mint == _token
        assert token_init.owner == private_key.public_key

        token_set_auth = decompile_set_authority(tx.message, 2, _token_program)
        assert token_set_auth.account == token_account_key.public_key
        assert token_set_auth.current_authority == private_key.public_key
        assert token_set_auth.authority_type == token.AuthorityType.CloseAccount
        assert token_set_auth.new_authority == _subsidizer

        assert not future.result()

    @pytest.mark.parametrize(
        "result, error_type",
        [
            (account_pb_v4.CreateAccountResponse.Result.EXISTS, AccountExistsError),
            (account_pb_v4.CreateAccountResponse.Result.PAYER_REQUIRED, PayerRequiredError),
            (account_pb_v4.CreateAccountResponse.Result.BAD_NONCE, BadNonceError),
        ]
    )
    def test_create_account_errors(self, grpc_channel, executor, no_retry_client, result, error_type):
        private_key = PrivateKey.random()
        token_account_key = PrivateKey(hashlib.sha256(private_key.raw).digest())

        no_retry_client._response_cache.clear_all()
        future = executor.submit(no_retry_client.create_solana_account, private_key)

        self._set_get_service_config_resp(grpc_channel)
        self._set_get_recent_blockhash_resp(grpc_channel)
        self._set_get_min_balance_response(grpc_channel)

        resp = account_pb_v4.CreateAccountResponse(result=result)
        req = self._set_create_account_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 3
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert token_account_key.public_key.verify(tx.message.marshal(), tx.signatures[1])
        assert private_key.public_key.verify(tx.message.marshal(), tx.signatures[2])

        sys_create = decompile_create_account(tx.message, 0)
        assert sys_create.funder == _subsidizer
        assert sys_create.address == token_account_key.public_key
        assert sys_create.owner == _token_program
        assert sys_create.lamports == _min_balance
        assert sys_create.size == token.ACCOUNT_SIZE

        token_init = decompile_initialize_account(tx.message, 1, _token_program)
        assert token_init.account == token_account_key.public_key
        assert token_init.mint == _token
        assert token_init.owner == private_key.public_key

        token_set_auth = decompile_set_authority(tx.message, 2, _token_program)
        assert token_set_auth.account == token_account_key.public_key
        assert token_set_auth.current_authority == private_key.public_key
        assert token_set_auth.authority_type == token.AuthorityType.CloseAccount
        assert token_set_auth.new_authority == _subsidizer

        with pytest.raises(error_type):
            future.result()

    def test_create_account_no_service_subsidizer(self, grpc_channel, executor, no_retry_client):
        private_key = PrivateKey.random()
        token_account_key = _generate_token_account(private_key)

        no_retry_client._response_cache.clear_all()
        future = executor.submit(no_retry_client.create_solana_account, private_key)

        md, request, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetServiceConfig']
        )
        rpc.terminate(tx_pb_v4.GetServiceConfigResponse(
            token=model_pb_v4.SolanaAccountId(value=_token.raw),
            token_program=model_pb_v4.SolanaAccountId(value=_token_program.raw),
        ), (), grpc.StatusCode.OK, '')

        TestInternalClientV4._assert_metadata(md)

        with pytest.raises(NoSubsidizerError):
            future.result()

        subsidizer = PrivateKey.random()
        future = executor.submit(no_retry_client.create_solana_account, private_key, subsidizer=subsidizer)

        self._set_get_recent_blockhash_resp(grpc_channel)
        self._set_get_min_balance_response(grpc_channel)

        req = self._set_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 3
        assert subsidizer.public_key.verify(tx.message.marshal(), tx.signatures[0])
        assert token_account_key.public_key.verify(tx.message.marshal(), tx.signatures[1])
        assert private_key.public_key.verify(tx.message.marshal(), tx.signatures[2])

        sys_create = decompile_create_account(tx.message, 0)
        assert sys_create.funder == subsidizer.public_key
        assert sys_create.address == token_account_key.public_key
        assert sys_create.owner == _token_program
        assert sys_create.lamports == _min_balance
        assert sys_create.size == token.ACCOUNT_SIZE

        token_init = decompile_initialize_account(tx.message, 1, _token_program)
        assert token_init.account == token_account_key.public_key
        assert token_init.mint == _token
        assert token_init.owner == private_key.public_key

        token_set_auth = decompile_set_authority(tx.message, 2, _token_program)
        assert token_set_auth.account == token_account_key.public_key
        assert token_set_auth.current_authority == private_key.public_key
        assert token_set_auth.authority_type == token.AuthorityType.CloseAccount
        assert token_set_auth.new_authority == subsidizer.public_key

        assert not future.result()

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
        assert account_info.account_id == private_key.public_key.raw
        assert account_info.balance == 10
        assert not account_info.sequence_number

    def test_get_account_info_not_found(self, grpc_channel, executor, no_retry_client):
        private_key = PrivateKey.random()
        future = executor.submit(no_retry_client.get_solana_account_info, private_key.public_key)

        resp = account_pb_v4.GetAccountInfoResponse(result=account_pb_v4.GetAccountInfoResponse.Result.NOT_FOUND)
        req = self._set_get_account_info_resp(grpc_channel, resp)
        assert req.account_id.value == private_key.public_key.raw

        with pytest.raises(AccountNotFoundError):
            future.result()

    def test_get_transaction(self, grpc_channel, executor, no_retry_client):
        source, dest = [key.public_key for key in generate_keys(2)]
        transaction_id = b'someid'
        future = executor.submit(no_retry_client.get_transaction, transaction_id)

        agora_memo = AgoraMemo.new(1, TransactionType.SPEND, 0, b'')
        tx = Transaction.new(PrivateKey.random().public_key, [
            memo_instruction(base64.b64encode(agora_memo.val).decode('utf-8')),
            transfer(source, dest, PrivateKey.random().public_key, 100, _token_program),
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

    def test_submit_transaction(self, grpc_channel, executor, no_retry_client):
        tx = self._generate_tx()
        future = executor.submit(no_retry_client.submit_solana_transaction, tx)

        tx_sig = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

        result = future.result()
        assert result.tx_id == tx_sig
        assert not result.errors
        assert not result.invoice_errors

    def test_submit_transaction_already_submitted(self, grpc_channel, executor, retry_client):
        tx = self._generate_tx()
        tx_sig = b'somesig'

        # Receive ALREADY_SUBMITTED on first attempt - should result in an error
        future = executor.submit(retry_client.submit_solana_transaction, tx)
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.ALREADY_SUBMITTED,
            signature=model_pb_v4.TransactionSignature(value=tx_sig)
        )
        req = self._set_submit_transaction_resp(grpc_channel, resp)
        assert req.transaction.value == tx.marshal()

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

        result = future.result()
        assert result.tx_id == tx_sig
        assert not result.errors
        assert not result.invoice_errors

    def test_submit_transaction_invoice_error(self, grpc_channel, executor, no_retry_client):
        tx = self._generate_tx()
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
        tx = self._generate_tx()
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
        tx = self._generate_tx()
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
        tx = self._generate_tx()
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
        tx = self._generate_tx()
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

    def test_request_airdrop(self, grpc_channel, executor, no_retry_client):
        public_key = PrivateKey.random().public_key
        future = executor.submit(no_retry_client.request_airdrop, public_key, 100)

        tx_sig = b'somesig'
        resp = airdrop_pb_v4.RequestAirdropResponse(result=airdrop_pb_v4.RequestAirdropResponse.Result.OK,
                                                    signature=model_pb_v4.TransactionSignature(value=tx_sig))
        req = self._set_request_airdrop_resp(grpc_channel, resp)
        assert req.account_id.value == public_key.raw
        assert req.quarks == 100

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

    def test_kin_4_get_service_config_cache(self, grpc_channel, executor, no_retry_client):
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
    def _set_submit_transaction_resp(
        channel: grpc_testing.Channel, resp: tx_pb_v4.SubmitTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> tx_pb_v4.GetTransactionRequest:
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
        assert len(md) == 3
        assert md[0] == user_agent(VERSION)
        assert md[1] == ('kin-version', '4')

    @staticmethod
    def _generate_tx():
        sender, dest, owner = generate_keys(3)
        return solana.Transaction.new(
            _subsidizer,
            [
                token.transfer(sender, dest, owner, 0, _token_program)
            ]
        )
