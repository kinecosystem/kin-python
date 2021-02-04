import base64
import uuid
from concurrent import futures
from typing import Tuple, Optional

import grpc
import grpc_testing
import pytest
from agoraapi.account.v4 import account_service_pb2 as account_pb_v4
from agoraapi.airdrop.v4 import airdrop_service_pb2 as airdrop_pb_v4
from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.common.v4 import model_pb2 as model_pb_v4
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb_v4

from agora.client.account.resolution import AccountResolution
from agora.client.client import Client, RetryConfig, BaseClient
from agora.client.environment import Environment
from agora.client.utils import _generate_token_account
from agora.error import AccountNotFoundError, InsufficientBalanceError, BadNonceError, TransactionRejectedError, \
    UnsupportedMethodError, NoSubsidizerError
from agora.keys import PrivateKey, PublicKey
from agora.model.earn import Earn, EarnBatch
from agora.model.invoice import InvoiceList, Invoice, LineItem
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.transaction import TransactionState
from agora.model.transaction_type import TransactionType
from agora.solana import token, transfer, memo_instruction, Commitment
from agora.solana.memo import decompile_memo
from agora.solana.system import decompile_create_account
from agora.solana.token import decompile_initialize_account, decompile_transfer, decompile_set_authority
from agora.solana.token.program import DecompiledTransfer
from agora.solana.transaction import HASH_LENGTH, Transaction, SIGNATURE_LENGTH
from agora.utils import user_agent
from agora.version import VERSION
from tests.utils import generate_keys

_config_with_retry = RetryConfig(max_retries=2, min_delay=0.1, max_delay=2, max_nonce_refreshes=0)
_config_with_nonce_retry = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=2)

_recent_blockhash = bytes(HASH_LENGTH)
_recent_blockhash_resp = tx_pb_v4.GetRecentBlockhashResponse(
    blockhash=model_pb_v4.Blockhash(value=_recent_blockhash)
)

_subsidizer = PrivateKey.random().public_key
_token = PrivateKey.random().public_key
_token_program = PrivateKey.random().public_key

_min_balance = 2039280
_min_balance_resp = tx_pb_v4.GetMinimumBalanceForRentExemptionResponse(lamports=_min_balance)


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
def app_index_client(grpc_channel) -> Client:
    """Returns an AgoraClient that has an app index and no retrying configured.
    """
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config)


@pytest.fixture(scope='class')
def no_app_client(grpc_channel) -> Client:
    """Returns an AgoraClient that has no app index and no retrying configured.
    """
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, grpc_channel=grpc_channel, retry_config=retry_config)


@pytest.fixture(scope='class')
def retry_client(grpc_channel):
    """Returns an AgoraClient that has retrying configured for non-nonce-related errors.
    """
    return Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=_config_with_retry)


@pytest.fixture(scope='class')
def nonce_retry_client(grpc_channel):
    """Returns an AgoraClient that has retrying configured only for nonce-related errors.
    """
    return Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=_config_with_nonce_retry)


class TestBaseClient:
    def test_not_implemented(self):
        private_key = PrivateKey.random()
        public_key = PrivateKey.random().public_key

        client = BaseClient()
        with pytest.raises(NotImplementedError):
            client.create_account(private_key)

        with pytest.raises(NotImplementedError):
            client.get_transaction(b'')

        with pytest.raises(NotImplementedError):
            client.get_balance(public_key)

        with pytest.raises(NotImplementedError):
            client.submit_payment(Payment(private_key, public_key, TransactionType.NONE, 0))

        with pytest.raises(NotImplementedError):
            client.submit_earn_batch(private_key, [])

        with pytest.raises(NotImplementedError):
            client.close()


# Filter warnings caused by instantiating Horizon inside AgoraApi
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
class TestAgoraClient:
    def test_invalid_inits(self, grpc_channel):
        with pytest.raises(ValueError):
            Client(Environment.TEST, grpc_channel=grpc_channel, endpoint='fakeendpoint')

    def test_kin_4_create_account(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()

        future = executor.submit(app_index_client.create_account, private_key)

        self._set_v4_get_min_balance_resp(grpc_channel)
        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        req = self._set_v4_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())
        self._assert_create_tx(req.transaction.value, private_key)

        assert not future.result()

    def test_kin_4_create_account_no_service_subsidizer(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()

        future = executor.submit(app_index_client.create_account, private_key)

        self._set_v4_get_min_balance_resp(grpc_channel)
        self._set_v4_get_service_config_resp_no_subsidizer(grpc_channel, app_index_client)

        with pytest.raises(NoSubsidizerError):
            future.result()

        subsidizer = PrivateKey.random()
        future = executor.submit(app_index_client.create_account, private_key, subsidizer=subsidizer)

        self._set_v4_get_min_balance_resp(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        req = self._set_v4_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())
        self._assert_create_tx(req.transaction.value, private_key, subsidizer)

        assert not future.result()

    def test_kin_4_create_account_with_nonce_retry(self, grpc_channel, executor):
        client = Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=_config_with_nonce_retry)

        private_key = PrivateKey.random()
        future = executor.submit(client.create_account, private_key)

        self._set_v4_get_min_balance_resp(grpc_channel)
        self._set_v4_get_service_config_resp(grpc_channel, client)

        create_reqs = []
        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            self._set_v4_get_recent_blockhash_resp(grpc_channel)

            resp = account_pb_v4.CreateAccountResponse(result=account_pb_v4.CreateAccountResponse.Result.BAD_NONCE)
            create_reqs.append(self._set_v4_create_account_resp(grpc_channel, resp))

        assert len(create_reqs) == _config_with_nonce_retry.max_nonce_refreshes + 1
        for req in create_reqs:
            self._assert_create_tx(req.transaction.value, private_key)

        with pytest.raises(BadNonceError):
            future.result()

    def test_kin_4_get_balance(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.get_balance, private_key.public_key)

        resp = account_pb_v4.GetAccountInfoResponse(
            result=account_pb_v4.GetAccountInfoResponse.Result.OK,
            account_info=account_pb_v4.AccountInfo(
                account_id=model_pb_v4.SolanaAccountId(value=private_key.public_key.raw),
                balance=100000,
            )
        )
        req = self._set_v4_get_account_info_resp(grpc_channel, resp)

        assert future.result() == 100000

        assert req.account_id.value == private_key.public_key.raw

    def test_kin_4_get_balance_not_found(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        resolved_key = PrivateKey.random()

        # Test with EXACT resolution
        future = executor.submit(app_index_client.get_balance, private_key.public_key,
                                 account_resolution=AccountResolution.EXACT)

        resp = account_pb_v4.GetAccountInfoResponse(
            result=account_pb_v4.GetAccountInfoResponse.Result.NOT_FOUND,
        )
        req = self._set_v4_get_account_info_resp(grpc_channel, resp)

        with pytest.raises(AccountNotFoundError):
            future.result()

        assert req.account_id.value == private_key.public_key.raw

        # Test with PREFERRED resolution
        future = executor.submit(app_index_client.get_balance, private_key.public_key,
                                 account_resolution=AccountResolution.PREFERRED)

        req1 = self._set_v4_get_account_info_resp(grpc_channel, resp)

        self._set_v4_resolve_token_accounts_resp(grpc_channel, account_pb_v4.ResolveTokenAccountsResponse(
            token_accounts=[model_pb_v4.SolanaAccountId(value=resolved_key.public_key.raw)]
        ))

        req2 = self._set_v4_get_account_info_resp(grpc_channel, account_pb_v4.GetAccountInfoResponse(
            result=account_pb_v4.GetAccountInfoResponse.Result.OK,
            account_info=account_pb_v4.AccountInfo(
                account_id=model_pb_v4.SolanaAccountId(value=resolved_key.public_key.raw),
                balance=200000
            )
        ))

        assert future.result() == 200000

        assert req1.account_id.value == private_key.public_key.raw
        assert req2.account_id.value == resolved_key.public_key.raw

    def test_kin_4_get_transaction(self, grpc_channel, executor, app_index_client):
        source, dest = [key.public_key for key in generate_keys(2)]
        transaction_id = b'someid'
        future = executor.submit(app_index_client.get_transaction, transaction_id)

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
                invoice_list=model_pb.InvoiceList(
                    invoices=[
                        model_pb.Invoice(
                            items=[
                                model_pb.Invoice.LineItem(title='t1', amount=15),
                            ]
                        ),
                    ]
                )
            ),
        )

        md, req, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

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

    def test_kin_4_get_transaction_unknown(self, grpc_channel, executor, app_index_client):
        transaction_id = b'someid'
        future = executor.submit(app_index_client.get_transaction, transaction_id)

        md, request, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        resp = tx_pb_v4.GetTransactionResponse(state=tx_pb_v4.GetTransactionResponse.State.UNKNOWN)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        tx_data = future.result()
        assert tx_data.tx_id == transaction_id
        assert tx_data.transaction_state == TransactionState.UNKNOWN

        self._assert_user_agent(md)
        assert request.transaction_id.value == transaction_id

    def test_kin_4_submit_payment_simple(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        future = executor.submit(no_app_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert payment.sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        decompiled = decompile_transfer(tx.message, 0, _token_program)
        self._assert_transfer(decompiled, sender.public_key, dest, sender.public_key, 100000)

        assert not req.invoice_list.invoices

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_no_service_subsidizer(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        subsidizer = PrivateKey.random()
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        future = executor.submit(no_app_client.submit_payment, payment)

        self._set_v4_get_service_config_resp_no_subsidizer(grpc_channel, no_app_client)

        with pytest.raises(NoSubsidizerError):
            future.result()

        payment.subsidizer = subsidizer
        future = executor.submit(no_app_client.submit_payment, payment)

        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert payment.subsidizer.public_key.verify(tx.message.marshal(), tx.signatures[0])
        assert payment.sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        decompiled = decompile_transfer(tx.message, 0, _token_program)
        self._assert_transfer(decompiled, sender.public_key, dest, sender.public_key, 100000)

        assert not req.invoice_list.invoices

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_invoice(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        invoice = Invoice([LineItem('title1', int(5e5))])
        payment = Payment(sender, dest, TransactionType.NONE, 100000, invoice=invoice)

        future = executor.submit(app_index_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert payment.sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        expected_memo = AgoraMemo.new(1, TransactionType.NONE, 1,
                                      InvoiceList([payment.invoice]).get_sha_224_hash()).val
        m = decompile_memo(tx.message, 0)
        assert base64.b64decode(m.data) == expected_memo

        decompiled = decompile_transfer(tx.message, 1, _token_program)
        self._assert_transfer(decompiled, sender.public_key, dest, sender.public_key, 100000)

        assert req.invoice_list.invoices[0].SerializeToString() == invoice.to_proto().SerializeToString()

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_memo(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000, memo='somememo')

        future = executor.submit(app_index_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert payment.sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        m = decompile_memo(tx.message, 0)
        assert m.data.decode('utf-8') == payment.memo

        decompiled = decompile_transfer(tx.message, 1, _token_program)
        self._assert_transfer(decompiled, sender.public_key, dest, sender.public_key, 100000)

        assert not req.invoice_list.invoices

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_acc_resolution(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        resolved_sender = PrivateKey.random().public_key
        dest = PrivateKey.random().public_key
        resolved_dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        future = executor.submit(no_app_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.INVALID_ACCOUNT,
            ),
            signature=model_pb_v4.TransactionSignature(value=b'failedsig')
        )
        self._set_v4_submit_tx_resp(grpc_channel, resp)

        # Both sender and destination should get resolved
        self._set_v4_resolve_token_accounts_resp(grpc_channel, account_pb_v4.ResolveTokenAccountsResponse(
            token_accounts=[model_pb_v4.SolanaAccountId(value=resolved_sender.raw)]
        ))
        self._set_v4_resolve_token_accounts_resp(grpc_channel, account_pb_v4.ResolveTokenAccountsResponse(
            token_accounts=[model_pb_v4.SolanaAccountId(value=resolved_dest.raw)]
        ))

        # Resubmit transaction
        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig'),
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert payment.sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        decompiled = decompile_transfer(tx.message, 0, _token_program)
        self._assert_transfer(decompiled, resolved_sender, resolved_dest, sender.public_key, 100000)

        assert not req.invoice_list.invoices

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_acc_resolution_exact(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        future = executor.submit(no_app_client.submit_payment, payment, sender_resolution=AccountResolution.EXACT,
                                 dest_resolution=AccountResolution.EXACT)

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.INVALID_ACCOUNT,
            ),
            signature=model_pb_v4.TransactionSignature(value=b'failedsig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        transfer = decompile_transfer(tx.message, 0, _token_program)
        assert transfer.source == sender.public_key
        assert transfer.dest == dest
        assert transfer.owner == sender.public_key
        assert transfer.amount == payment.quarks

        assert not req.invoice_list.invoices

        with pytest.raises(AccountNotFoundError):
            future.result()

    def test_kin_4_submit_payment_error(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(app_index_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.REJECTED,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        self._set_v4_submit_tx_resp(grpc_channel, resp)

        with pytest.raises(TransactionRejectedError):
            future.result()

    def test_kin_4_submit_payment_with_nonce_retry(self, grpc_channel, executor, nonce_retry_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(nonce_retry_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel, nonce_retry_client)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            signature=model_pb_v4.TransactionSignature(value=b'somesig'),
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.BAD_NONCE,
            ),
        )

        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            self._set_v4_submit_tx_resp(grpc_channel, resp)

        with pytest.raises(BadNonceError):
            future.result()

    def test_kin_4_submit_payment_invalid(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key

        # invoice but no app index
        payment = Payment(sender, dest, TransactionType.NONE, 100000, invoice=Invoice([LineItem('title', 100)]))
        future = executor.submit(no_app_client.submit_payment, payment)
        with pytest.raises(ValueError):
            future.result()

    def test_kin_4_submit_earn_batch_simple(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, i) for i in range(15)]
        b = EarnBatch(sender, earns, dedupe_id=uuid.uuid4().bytes)

        future = executor.submit(no_app_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        tx_id = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_id),
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)
        assert req.dedupe_id == b.dedupe_id

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        for idx, earn in enumerate(earns):
            transfer = decompile_transfer(tx.message, idx, _token_program)
            assert transfer.source == sender.public_key
            assert transfer.dest == earn.destination
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        result = future.result()
        assert result.tx_id == tx_id
        assert not result.tx_error
        assert not result.earn_errors

    def test_kin_4_submit_earn_batch_with_subsidizer(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        subsidizer = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, i) for i in range(15)]
        b = EarnBatch(sender, earns, subsidizer=subsidizer)

        future = executor.submit(no_app_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp_no_subsidizer(grpc_channel, no_app_client)

        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        tx_id = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_id),
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert subsidizer.public_key.verify(tx.message.marshal(), tx.signatures[0])
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        for instruction_idx, earn in enumerate(earns):
            transfer = decompile_transfer(tx.message, instruction_idx, _token_program)
            assert transfer.source == sender.public_key
            assert transfer.dest == earn.destination
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        result = future.result()
        assert result.tx_id == tx_id
        assert not result.tx_error
        assert not result.earn_errors

    def test_kin_4_submit_earn_batch_memo(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, i) for i in range(15)]
        b = EarnBatch(sender, earns, memo='somememo')

        future = executor.submit(no_app_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)

        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        tx_id = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_id),
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        m = decompile_memo(tx.message, 0)
        assert m.data.decode('utf-8') == 'somememo'

        for instruction_idx, earn in enumerate(earns):
            transfer = decompile_transfer(tx.message, instruction_idx + 1, _token_program)
            assert transfer.source == sender.public_key
            assert transfer.dest == earn.destination
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        result = future.result()
        assert result.tx_id == tx_id
        assert not result.tx_error
        assert not result.earn_errors

    def test_kin_4_submit_earn_batch_with_invoices(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku')])
        earns = [Earn(PrivateKey.random().public_key, i,
                      invoice=invoice) for i in range(15)]
        b = EarnBatch(sender, earns)

        future = executor.submit(app_index_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)

        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        tx_id = b'somesig'
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=tx_id),
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        m = decompile_memo(tx.message, 0)
        il = InvoiceList([invoice] * len(earns))
        expected_memo = AgoraMemo.new(1, TransactionType.EARN, 1, il.get_sha_224_hash()).val
        assert m.data == base64.b64encode(expected_memo)

        for instruction_idx, earn in enumerate(earns):
            transfer = decompile_transfer(tx.message, instruction_idx + 1, _token_program)
            assert transfer.source == sender.public_key
            assert transfer.dest == earn.destination
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == len(earns)

        result = future.result()
        assert result.tx_id == tx_id
        assert not result.tx_error
        assert not result.earn_errors

    def test_kin_4_submit_earn_batch_with_acc_resolution(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        resolved_sender = PrivateKey.random().public_key
        earns = [Earn(PrivateKey.random().public_key, i) for i in range(10)]
        resolved_destinations = [PrivateKey.random().public_key for _ in earns]
        b = EarnBatch(sender, earns)

        future = executor.submit(no_app_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)

        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.INVALID_ACCOUNT,
            ),
            signature=model_pb_v4.TransactionSignature(value=b'failedsig')
        )
        self._set_v4_submit_tx_resp(grpc_channel, resp)

        # Both sender and destination should get resolved
        self._set_v4_resolve_token_accounts_resp(grpc_channel, account_pb_v4.ResolveTokenAccountsResponse(
            token_accounts=[model_pb_v4.SolanaAccountId(value=resolved_sender.raw)]
        ))
        for resolved_dest in resolved_destinations:
            self._set_v4_resolve_token_accounts_resp(grpc_channel, account_pb_v4.ResolveTokenAccountsResponse(
                token_accounts=[model_pb_v4.SolanaAccountId(value=resolved_dest.raw)]
            ))

        # Resubmit transaction
        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig'),
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        for idx, earn in enumerate(earns):
            transfer = decompile_transfer(tx.message, idx, _token_program)
            assert transfer.source == resolved_sender
            assert transfer.dest == resolved_destinations[idx]
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        result = future.result()
        assert result.tx_id == b'somesig'
        assert not result.tx_error
        assert not result.earn_errors

    def test_kin_4_submit_earn_batch_failed_acc_resolution_exact(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, i) for i in range(10)]
        b = EarnBatch(sender, earns)

        future = executor.submit(
            no_app_client.submit_earn_batch, b, sender_resolution=AccountResolution.EXACT,
            dest_resolution=AccountResolution.EXACT,
        )

        self._set_v4_get_service_config_resp(grpc_channel, no_app_client)

        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.INVALID_ACCOUNT,
                instruction_index=1
            ),
            signature=model_pb_v4.TransactionSignature(value=b'failedsig')
        )

        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        for idx, earn in enumerate(earns):
            transfer = decompile_transfer(tx.message, idx, _token_program)
            assert transfer.source == sender.public_key
            assert transfer.dest == earn.destination
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        result = future.result()
        assert result.tx_id == b'failedsig'
        assert isinstance(result.tx_error, AccountNotFoundError)
        assert len(result.earn_errors) == 1
        assert result.earn_errors[0].earn_index == 1
        assert isinstance(result.earn_errors[0].error, AccountNotFoundError)

    def test_kin_4_submit_earn_batch_rejected(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000),
            Earn(PrivateKey.random().public_key, 100000),
        ]
        b = EarnBatch(sender, earns)

        future = executor.submit(app_index_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.REJECTED,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        self._set_v4_submit_tx_resp(grpc_channel, resp)

        with pytest.raises(TransactionRejectedError):
            future.result()

    def test_kin_4_submit_earn_batch_tx_failed(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000),
            Earn(PrivateKey.random().public_key, 100000),
        ]
        b = EarnBatch(sender, earns)

        future = executor.submit(app_index_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, app_index_client)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            signature=model_pb_v4.TransactionSignature(value=b'somesig'),
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.INSUFFICIENT_FUNDS,
                instruction_index=2,
            ),
        )
        self._set_v4_submit_tx_resp(grpc_channel, resp)

        result = future.result()
        assert result.tx_id == b'somesig'
        assert isinstance(result.tx_error, InsufficientBalanceError)
        assert len(result.earn_errors) == 1

        assert result.earn_errors[0].earn_index == 1
        assert isinstance(result.earn_errors[0].error, InsufficientBalanceError)

    def test_kin_4_submit_earn_batch_with_nonce_retry(self, grpc_channel, executor, nonce_retry_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]
        b = EarnBatch(sender, earns)

        future = executor.submit(nonce_retry_client.submit_earn_batch, b)

        self._set_v4_get_service_config_resp(grpc_channel, nonce_retry_client)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            signature=model_pb_v4.TransactionSignature(value=b'somesig'),
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.BAD_NONCE,
            ),
        )

        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            self._set_v4_submit_tx_resp(grpc_channel, resp)

        with pytest.raises(BadNonceError):
            future.result()

    def test_kin_4_earn_batch_invalid(self, grpc_channel, executor, no_app_client, app_index_client):
        sender = PrivateKey.random()

        # invoices with no app index
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title2', 100000, 'description2', b'somesku')])),
        ]
        b = EarnBatch(sender, earns)

        future = executor.submit(no_app_client.submit_earn_batch, b)

        with pytest.raises(ValueError):
            future.result()

        # not all earns having invoices
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(PrivateKey.random().public_key, 100000),
        ]
        b = EarnBatch(sender, earns)

        future = executor.submit(app_index_client.submit_earn_batch, b)

        with pytest.raises(ValueError):
            future.result()

        # mixed invoices and memo
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
        ]
        b = EarnBatch(sender, earns, memo="somememo")

        future = executor.submit(app_index_client.submit_earn_batch, b)

        with pytest.raises(ValueError):
            future.result()

    def test_request_airdrop(self, grpc_channel, executor, no_app_client):
        public_key = PrivateKey.random().public_key
        future = executor.submit(no_app_client.request_airdrop, public_key, 100, Commitment.MAX)

        tx_sig = b'somesig'
        resp = airdrop_pb_v4.RequestAirdropResponse(result=airdrop_pb_v4.RequestAirdropResponse.Result.OK,
                                                    signature=model_pb_v4.TransactionSignature(value=tx_sig))
        req = self._set_request_airdrop_resp(grpc_channel, resp)
        assert req.account_id.value == public_key.raw
        assert req.quarks == 100
        assert req.commitment == Commitment.MAX

        assert future.result() == tx_sig

    def test_request_airdrop_unsupported_env(self, grpc_channel, executor):
        public_key = PrivateKey.random().public_key
        client = Client(Environment.PRODUCTION, 0)
        future = executor.submit(client.request_airdrop, public_key, 100, Commitment.MAX)

        with pytest.raises(UnsupportedMethodError):
            future.result()

    @staticmethod
    def _set_v4_create_account_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.CreateAccountResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> account_pb_v4.CreateAccountRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb_v4.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )
        rpc.terminate(resp, (), status, '')

        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_get_account_info_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.GetAccountInfoResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ) -> account_pb_v4.GetAccountInfoRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb_v4.DESCRIPTOR.services_by_name['Account'].methods_by_name['GetAccountInfo']
        )
        rpc.terminate(resp, (), status, '')
        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_resolve_token_accounts_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.ResolveTokenAccountsResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ) -> account_pb_v4.GetAccountInfoRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb_v4.DESCRIPTOR.services_by_name['Account'].methods_by_name['ResolveTokenAccounts']
        )
        rpc.terminate(resp, (), status, '')
        return request

    @staticmethod
    def _set_v4_submit_tx_resp(
        channel: grpc_testing.Channel, resp: tx_pb_v4.SubmitTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ):
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['SubmitTransaction']
        )
        rpc.terminate(resp, (), status, '')
        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_get_recent_blockhash_resp(
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetRecentBlockhashRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetRecentBlockhash']
        )
        rpc.terminate(_recent_blockhash_resp, (), grpc.StatusCode.OK, '')

        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_get_service_config_resp(
        channel: grpc_testing.Channel, client: Client,
    ) -> tx_pb_v4.GetServiceConfigRequest:
        client._internal_client._response_cache.clear_all()

        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetServiceConfig']
        )
        rpc.terminate(tx_pb_v4.GetServiceConfigResponse(
            subsidizer_account=model_pb_v4.SolanaAccountId(value=_subsidizer.raw),
            token=model_pb_v4.SolanaAccountId(value=_token.raw),
            token_program=model_pb_v4.SolanaAccountId(value=_token_program.raw),
        ), (), grpc.StatusCode.OK, '')

        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_get_service_config_resp_no_subsidizer(
        channel: grpc_testing.Channel, client: Client,
    ) -> tx_pb_v4.GetServiceConfigRequest:
        client._internal_client._response_cache.clear_all()
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetServiceConfig']
        )
        rpc.terminate(tx_pb_v4.GetServiceConfigResponse(
            token=model_pb_v4.SolanaAccountId(value=_token.raw),
            token_program=model_pb_v4.SolanaAccountId(value=_token_program.raw),
        ), (), grpc.StatusCode.OK, '')

        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_get_min_balance_resp(
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetMinimumBalanceForRentExemptionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetMinimumBalanceForRentExemption']
        )
        rpc.terminate(_min_balance_resp, (), grpc.StatusCode.OK, '')

        TestAgoraClient._assert_kin_4_md(md)
        return request

    @staticmethod
    def _set_v4_get_min_blockchain_version(
        channel: grpc_testing.Channel,
        kin_version=4,
    ) -> tx_pb_v4.GetMinimumKinVersionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetMinimumKinVersion']
        )
        rpc.terminate(tx_pb_v4.GetMinimumKinVersionResponse(version=kin_version), (), grpc.StatusCode.OK, '')

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
        return request

    @staticmethod
    def _assert_create_tx(tx_bytes: bytes, private_key: PrivateKey, subsidizer: Optional[PrivateKey] = None):
        token_account_key = _generate_token_account(private_key)
        tx = Transaction.unmarshal(tx_bytes)
        assert len(tx.signatures) == 3

        if subsidizer:
            assert subsidizer.public_key.verify(tx.message.marshal(), tx.signatures[0])
        else:
            assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert token_account_key.public_key.verify(tx.message.marshal(), tx.signatures[1])
        assert private_key.public_key.verify(tx.message.marshal(), tx.signatures[2])

        sys_create = decompile_create_account(tx.message, 0)
        assert sys_create.funder == subsidizer.public_key if subsidizer else _subsidizer
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
        assert token_set_auth.new_authority == subsidizer.public_key if subsidizer else _subsidizer

    @staticmethod
    def _assert_transfer(decompiled: DecompiledTransfer, source: PublicKey, dest: PublicKey, owner: PublicKey,
                         amount: int):
        assert decompiled.source == source
        assert decompiled.dest == dest
        assert decompiled.owner == owner
        assert decompiled.amount == amount

    @staticmethod
    def _assert_user_agent(md):
        assert len(md) >= 2
        assert len(md[0]) == 2
        assert md[0] == user_agent(VERSION)

    @staticmethod
    def _assert_kin_4_md(md: Tuple[Tuple, ...]):
        assert len(md) == 3
        assert md[0] == user_agent(VERSION)
        assert md[1] == ('kin-version', '4')
