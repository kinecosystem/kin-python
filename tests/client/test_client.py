import base64
from concurrent import futures
from typing import List, Tuple

import grpc
import grpc_testing
import pytest
from agoraapi.account.v3 import account_service_pb2 as account_pb
from agoraapi.account.v4 import account_service_pb2 as account_pb_v4
from agoraapi.common.v3 import model_pb2 as model_pb
from agoraapi.common.v4 import model_pb2 as model_pb_v4
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from agoraapi.transaction.v4 import transaction_service_pb2 as tx_pb_v4
from kin_base import transaction_envelope as te, memo, operation
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora import solana
from agora.client.account.resolution import AccountResolution
from agora.client.client import Client, RetryConfig, BaseClient, _NETWORK_NAMES
from agora.client.environment import Environment
from agora.error import AccountExistsError, AccountNotFoundError, InsufficientBalanceError, \
    DestinationDoesNotExistError, BadNonceError, UnsupportedVersionError, \
    TransactionRejectedError, Error, AlreadyPaidError
from agora.keys import PrivateKey
from agora.model.earn import Earn
from agora.model.invoice import InvoiceList, Invoice, LineItem
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.transaction import TransactionState
from agora.model.transaction_type import TransactionType
from agora.solana import token, transfer, memo_instruction
from agora.solana.memo import decompile_memo
from agora.solana.system import decompile_create_account
from agora.solana.token import decompile_initialize_account, decompile_transfer
from agora.solana.transaction import HASH_LENGTH, Transaction, SIGNATURE_LENGTH
from agora.utils import partition, kin_to_quarks, quarks_to_kin, kin_2_envelope_from_xdr
from agora.utils import user_agent
from agora.version import VERSION
from tests.utils import gen_account_id, gen_tx_envelope_xdr, gen_payment_op, gen_payment_op_result, gen_result_xdr, \
    gen_hash_memo, gen_kin_2_payment_op

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
        account_pb.DESCRIPTOR.services_by_name['Account'],
        tx_pb.DESCRIPTOR.services_by_name['Transaction'],
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
def whitelisting_client(grpc_channel) -> Client:
    """Returns an AgoraClient that has no retrying configured and a whitelist keypair set.
    """
    private_key = PrivateKey.random()
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, app_index=1, whitelist_key=private_key,
                  grpc_channel=grpc_channel, retry_config=retry_config)


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


@pytest.fixture(scope='class')
def kin_2_client(grpc_channel) -> Client:
    """Returns an AgoraClient that is configured to use Kin 2.
    """
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config, kin_version=2)


@pytest.fixture(scope='class')
def kin_4_client(grpc_channel) -> Client:
    """Returns an AgoraClient that is configured to use Kin 4.
    """
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config, kin_version=4)


@pytest.fixture(scope='class')
def kin_4_no_app_client(grpc_channel) -> Client:
    """Returns an AgoraClient that is configured to use Kin 4.
    """
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, app_index=0, grpc_channel=grpc_channel, retry_config=retry_config, kin_version=4)


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

    def test_unsupported_version(self, grpc_channel):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)

        with pytest.raises(ValueError):
            Client(Environment.TEST, grpc_channel=grpc_channel, retry_config=retry_config, kin_version=5)

        client = Client(Environment.TEST, grpc_channel=grpc_channel, retry_config=retry_config)
        client._kin_version = 5

        private_key = PrivateKey.random()
        public_key = PrivateKey.random().public_key
        with pytest.raises(UnsupportedVersionError):
            client.create_account(private_key)

        with pytest.raises(UnsupportedVersionError):
            client.get_balance(public_key)

        with pytest.raises(UnsupportedVersionError):
            client.submit_payment(Payment(private_key, public_key, TransactionType.NONE, 0))

        with pytest.raises(UnsupportedVersionError):
            client.submit_earn_batch(private_key, [])

    def test_create_account(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.create_account, private_key)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )

        rpc.terminate(account_pb.CreateAccountResponse(), (), grpc.StatusCode.OK, '')

        self._assert_user_agent(md)
        assert request.account_id.value == private_key.public_key.stellar_address
        assert not future.result()

    def test_create_account_kin_2(self, grpc_channel, executor, kin_2_client):
        private_key = PrivateKey.random()
        future = executor.submit(kin_2_client.create_account, private_key)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )

        rpc.terminate(account_pb.CreateAccountResponse(), (), grpc.StatusCode.OK, '')

        assert md[1] == ('kin-version', '2')
        assert request.account_id.value == private_key.public_key.stellar_address
        assert not future.result()

    def test_create_account_exists(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        application_future = executor.submit(app_index_client.create_account, private_key)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )
        resp = account_pb.CreateAccountResponse(result=account_pb.CreateAccountResponse.Result.EXISTS)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        with pytest.raises(AccountExistsError):
            application_future.result()

        self._assert_user_agent(md)
        assert request.account_id.value == private_key.public_key.stellar_address

    def test_get_transaction(self, grpc_channel, executor, app_index_client):
        tx_hash = b'somehash'
        future = executor.submit(app_index_client.get_transaction, tx_hash)

        md, request, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        # Create full response
        op_result = gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [op_result, op_result])

        il = model_pb.InvoiceList(invoices=[
            model_pb.Invoice(
                items=[
                    model_pb.Invoice.LineItem(title='t1', amount=15),
                ]
            ),
        ])
        fk = InvoiceList.from_proto(il).get_sha_224_hash()
        memo = AgoraMemo.new(1, TransactionType.EARN, 1, fk)
        hash_memo = gen_hash_memo(memo.val)

        acc1 = gen_account_id()
        acc2 = gen_account_id()
        operations = [gen_payment_op(acc2, amount=15)]
        envelope_xdr = gen_tx_envelope_xdr(acc1, 1, operations, hash_memo)

        history_item = tx_pb_v4.HistoryItem(
            transaction_id=model_pb_v4.TransactionId(value=tx_hash),
            cursor=tx_pb_v4.Cursor(value=b'cursor1'),
            stellar_transaction=model_pb_v4.StellarTransaction(
                result_xdr=result_xdr,
                envelope_xdr=envelope_xdr,
            ),
            payments=[
                tx_pb_v4.HistoryItem.Payment(
                    source=model_pb_v4.SolanaAccountId(value=acc1.ed25519),
                    destination=model_pb_v4.SolanaAccountId(value=acc2.ed25519),
                    amount=15,
                ),
            ],
            invoice_list=il,
        )
        resp = tx_pb_v4.GetTransactionResponse(
            state=tx_pb_v4.GetTransactionResponse.State.SUCCESS,
            item=history_item,
        )
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        self._assert_user_agent(md)

        tx_data = future.result()
        assert tx_data.transaction_id == tx_hash
        assert len(tx_data.payments) == 1
        assert not tx_data.error

        payment1 = tx_data.payments[0]
        assert payment1.sender.raw == acc1.ed25519
        assert payment1.destination.raw == acc2.ed25519
        assert payment1.tx_type == memo.tx_type()
        assert payment1.quarks == 15
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        assert request.transaction_id.value == tx_hash

    def test_get_transaction_kin_2(self, grpc_channel, executor, kin_2_client):
        tx_hash = b'somehash'
        future = executor.submit(kin_2_client.get_transaction, tx_hash)

        md, request, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        # Create full response
        op_result = gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [op_result, op_result])

        il = model_pb.InvoiceList(invoices=[
            model_pb.Invoice(
                items=[
                    model_pb.Invoice.LineItem(title='t1', amount=15),
                ]
            ),
        ])
        fk = InvoiceList.from_proto(il).get_sha_224_hash()
        memo = AgoraMemo.new(1, TransactionType.EARN, 1, fk)
        hash_memo = gen_hash_memo(memo.val)

        acc1 = gen_account_id()
        acc2 = gen_account_id()
        operations = [gen_kin_2_payment_op(acc2, raw_amount=1500)]  # equivalent to 15 quarks
        envelope_xdr = gen_tx_envelope_xdr(acc1, 1, operations, hash_memo)

        history_item = tx_pb_v4.HistoryItem(
            transaction_id=model_pb_v4.TransactionId(value=tx_hash),
            cursor=tx_pb_v4.Cursor(value=b'cursor1'),
            stellar_transaction=model_pb_v4.StellarTransaction(
                result_xdr=result_xdr,
                envelope_xdr=envelope_xdr,
            ),
            payments=[
                tx_pb_v4.HistoryItem.Payment(
                    source=model_pb_v4.SolanaAccountId(value=acc1.ed25519),
                    destination=model_pb_v4.SolanaAccountId(value=acc2.ed25519),
                    amount=15,
                ),
            ],
            invoice_list=il,
        )
        resp = tx_pb_v4.GetTransactionResponse(
            state=tx_pb_v4.GetTransactionResponse.State.SUCCESS,
            item=history_item,
        )
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        assert md[1] == ('kin-version', '2')

        tx_data = future.result()
        assert tx_data.transaction_id == tx_hash
        assert len(tx_data.payments) == 1
        assert not tx_data.error

        payment1 = tx_data.payments[0]
        assert payment1.sender.raw == acc1.ed25519
        assert payment1.destination.raw == acc2.ed25519
        assert payment1.tx_type == memo.tx_type()
        assert payment1.quarks == 15
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        assert request.transaction_id.value == tx_hash

    def test_get_transaction_unknown(self, grpc_channel, executor, app_index_client):
        tx_hash = b'somehash'
        future = executor.submit(app_index_client.get_transaction, tx_hash)

        md, request, rpc = grpc_channel.take_unary_unary(
            tx_pb_v4.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        resp = tx_pb_v4.GetTransactionResponse(state=tx_pb.GetTransactionResponse.State.UNKNOWN)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        tx_data = future.result()
        assert tx_data.transaction_id == tx_hash
        assert tx_data.transaction_state == TransactionState.UNKNOWN

        self._assert_user_agent(md)
        assert request.transaction_id.value == tx_hash

    def test_get_balance(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.get_balance, private_key.public_key)

        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.OK,
            account_info=account_pb.AccountInfo(
                account_id=model_pb.StellarAccountId(
                    value=private_key.public_key.stellar_address
                ),
                sequence_number=10,
                balance=100000,
            )
        )
        req = self._set_get_account_info_resp(grpc_channel, resp)

        assert future.result() == 100000

        assert req.account_id.value == private_key.public_key.stellar_address

    def test_get_balance_not_found(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.get_balance, private_key.public_key)

        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.NOT_FOUND,
        )
        req = self._set_get_account_info_resp(grpc_channel, resp)

        with pytest.raises(AccountNotFoundError):
            future.result()

        assert req.account_id.value == private_key.public_key.stellar_address

    def test_submit_payment_simple(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_kin_2(self, grpc_channel, executor, kin_2_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(kin_2_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_kin_2_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_channel(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        channel = PrivateKey.random()
        payment = Payment(sender, dest, TransactionType.EARN, 100000,
                          channel=channel)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, channel, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == channel.public_key.stellar_address

        expected_signers = [channel, sender]
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, expected_signers, channel, 100, 11, expected_memo,
                                      payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_whitelisting(self, grpc_channel, executor, whitelisting_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(whitelisting_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender, whitelisting_client.whitelist_key], sender, 100,
                                      11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_invoice(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku')])
        payment = Payment(sender, dest, TransactionType.EARN, 100000, invoice=invoice)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(
            AgoraMemo.new(1, TransactionType.EARN, 1, InvoiceList([invoice]).get_sha_224_hash()).val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 1
        assert submit_req.invoice_list.invoices[0].SerializeToString() == invoice.to_proto().SerializeToString()

    def test_submit_payment_with_invoice_no_app_index(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku')])
        payment = Payment(sender, dest, TransactionType.EARN, 100000, invoice=invoice)

        future = executor.submit(no_app_client.submit_payment, payment)
        with pytest.raises(ValueError):
            future.result()

    def test_submit_payment_with_memo(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000, memo='somememo')

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.TextMemo('somememo')
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_rejected(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.REJECTED,
            hash=model_pb.TransactionHash(value=b'somehash'),
        )
        submit_req = self._set_submit_transaction_resp(grpc_channel, resp)

        with pytest.raises(TransactionRejectedError):
            future.result()

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_invoice_error(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku1')])
        payment = Payment(sender, dest, TransactionType.EARN, 100000, invoice=invoice)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR,
            invoice_errors=[
                model_pb.InvoiceError(
                    op_index=0,
                    invoice=invoice.to_proto(),
                    reason=model_pb.InvoiceError.Reason.ALREADY_PAID,
                )
            ]
        )
        submit_req = self._set_submit_transaction_resp(grpc_channel, resp)

        with pytest.raises(AlreadyPaidError):
            future.result()

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(
            AgoraMemo.new(1, TransactionType.EARN, 1, InvoiceList([invoice]).get_sha_224_hash()).val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 1
        assert submit_req.invoice_list.invoices[0].SerializeToString() == invoice.to_proto().SerializeToString()

    def test_submit_payment_tx_failed(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txFAILED, [gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED)])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )
        submit_req = self._set_submit_transaction_resp(grpc_channel, resp)

        with pytest.raises(InsufficientBalanceError):
            future.result()

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_retry(self, grpc_channel, executor, retry_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=5,  # invalid result code, should throw an error
            hash=model_pb.TransactionHash(value=b'somehash'),
        )

        submit_reqs = []
        for i in range(_config_with_retry.max_retries + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_resp(grpc_channel, resp))

        with pytest.raises(Error):
            future.result()

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        for submit_req in submit_reqs:
            self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_nonce_retry(self, grpc_channel, executor, nonce_retry_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(nonce_retry_client.submit_payment, payment)

        result_xdr = gen_result_xdr(xdr_const.txBAD_SEQ, [])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)
        submit_reqs = []
        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            req = self._set_submit_transaction_resp(grpc_channel, resp)
            submit_reqs.append(req)
            env = te.TransactionEnvelope.from_xdr(base64.b64encode(req.envelope_xdr))

        with pytest.raises(BadNonceError):
            future.result()

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        for idx, submit_req in enumerate(submit_reqs):
            self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11 + idx, expected_memo,
                                          payment)
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_multiple(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(250)]

        future = executor.submit(app_index_client.submit_earn_batch, sender, all_earns)

        account_reqs = []
        submit_reqs = []
        tx_hashes = []
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        starting_seq = 10

        for i in range(3):
            account_reqs.append(self._set_successful_get_account_info_resp(grpc_channel, sender, starting_seq + i))
            tx_hash = f'somehash{i}'.encode()
            submit_reqs.append(self._set_successful_submit_transaction_resp(grpc_channel, tx_hash, result_xdr))
            tx_hashes.append(tx_hash)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 250
        assert len(batch_earn_result.failed) == 0

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.public_key.stellar_address

        earn_batches = partition(all_earns, 100)
        for idx, submit_req in enumerate(submit_reqs):
            expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, starting_seq + idx + 1,
                                             expected_memo, sender, earn_batches[idx])
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_multiple_kin_2(self, grpc_channel, executor, kin_2_client):
        sender = PrivateKey.random()
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(250)]

        future = executor.submit(kin_2_client.submit_earn_batch, sender, all_earns)

        account_reqs = []
        submit_reqs = []
        tx_hashes = []
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        starting_seq = 10

        for i in range(3):
            account_reqs.append(self._set_successful_get_account_info_resp(grpc_channel, sender, starting_seq + i))
            tx_hash = f'somehash{i}'.encode()
            submit_reqs.append(self._set_successful_submit_transaction_resp(grpc_channel, tx_hash, result_xdr))
            tx_hashes.append(tx_hash)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 250
        assert len(batch_earn_result.failed) == 0

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.public_key.stellar_address

        earn_batches = partition(all_earns, 100)
        for idx, submit_req in enumerate(submit_reqs):
            expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
            self._assert_kin_2_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100,
                                                   starting_seq + idx + 1,
                                                   expected_memo, sender, earn_batches[idx])
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_same_dest(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        all_earns = [Earn(dest, i) for i in range(5)]

        future = executor.submit(app_index_client.submit_earn_batch, sender, all_earns)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)
        tx_hash = 'somehash'.encode()
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, tx_hash, result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 5
        assert len(batch_earn_result.failed) == 0

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11,
                                         expected_memo, sender, all_earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_channel(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        channel = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns, channel=channel)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, channel, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 1
        assert len(batch_earn_result.failed) == 0

        earn_result = batch_earn_result.succeeded[0]
        assert earn_result.earn == earns[0]
        assert earn_result.transaction_id == b'somehash'
        assert not earn_result.error

        assert account_req.account_id.value == channel.public_key.stellar_address

        expected_signers = [channel, sender]
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, expected_signers, channel, 100, 11, expected_memo,
                                         sender, earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_whitelisting(self, grpc_channel, executor, whitelisting_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(whitelisting_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 1
        assert len(batch_earn_result.failed) == 0

        earn_result = batch_earn_result.succeeded[0]
        assert earn_result.earn == earns[0]
        assert earn_result.transaction_id == b'somehash'
        assert not earn_result.error

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_signers = [sender, whitelisting_client.whitelist_key]
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, expected_signers, sender, 100, 11, expected_memo,
                                         sender, earns)

    def test_submit_earn_batch_with_memo(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns, memo="somememo")

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 1
        assert len(batch_earn_result.failed) == 0

        earn_result = batch_earn_result.succeeded[0]
        assert earn_result.earn == earns[0]
        assert earn_result.transaction_id == b'somehash'
        assert not earn_result.error

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.TextMemo('somememo')
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo,
                                         sender, earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_invoices(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title2', 100000, 'description2', b'somesku')])),
        ]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_resp(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 2
        assert len(batch_earn_result.failed) == 0

        for idx, earn_result in enumerate(batch_earn_result.succeeded):
            assert earn_result.transaction_id == b'somehash'
            assert earn_result.earn == earns[idx]
            assert not earn_result.error

        assert account_req.account_id.value == sender.public_key.stellar_address

        il = InvoiceList([earn.invoice for earn in earns])
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, il.get_sha_224_hash()).val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 2
        assert submit_req.invoice_list.SerializeToString() == il.to_proto().SerializeToString()

    def test_submit_earn_batch_with_invoices_no_app_index(self, grpc_channel, executor, no_app_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title2', 100000, 'description2', b'somesku')])),
        ]

        future = executor.submit(no_app_client.submit_earn_batch, sender, earns)

        with pytest.raises(ValueError):
            future.result()

    def test_submit_earn_batch_with_some_invoices(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(PrivateKey.random().public_key, 100000),
        ]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns)

        with pytest.raises(ValueError):
            future.result()

    def test_submit_earn_batch_with_invoices_and_memo(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
        ]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns, memo="somememo")

        with pytest.raises(ValueError):
            future.result()

    def test_submit_earn_batch_rejected(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000),
            Earn(PrivateKey.random().public_key, 100000),
        ]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.REJECTED,
            hash=model_pb.TransactionHash(value=b'somehash'),
        )
        submit_req = self._set_submit_transaction_resp(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 2

        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == earns[idx]
            assert not earn_result.transaction_id
            assert isinstance(earn_result.error, TransactionRejectedError)

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_invoice_error(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(PrivateKey.random().public_key, 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
        ]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR,
            invoice_errors=[
                model_pb.InvoiceError(
                    op_index=0,
                    invoice=earns[0].invoice.to_proto(),
                    reason=model_pb.InvoiceError.Reason.ALREADY_PAID,
                ),
                model_pb.InvoiceError(
                    op_index=0,
                    invoice=earns[1].invoice.to_proto(),
                    reason=model_pb.InvoiceError.Reason.WRONG_DESTINATION,
                )
            ]
        )
        submit_req = self._set_submit_transaction_resp(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 2

        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == earns[idx]
            assert not earn_result.transaction_id
            assert isinstance(earn_result.error, Error)

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(
            AgoraMemo.new(1, TransactionType.EARN, 1,
                          InvoiceList([earn.invoice for earn in earns]).get_sha_224_hash()).val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 2
        assert (submit_req.invoice_list.invoices[0].SerializeToString() ==
                earns[0].invoice.to_proto().SerializeToString())
        assert (submit_req.invoice_list.invoices[1].SerializeToString() ==
                earns[1].invoice.to_proto().SerializeToString())

    def test_submit_earn_batch_tx_failed(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        earns = [
            Earn(PrivateKey.random().public_key, 100000),
            Earn(PrivateKey.random().public_key, 100000),
        ]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txFAILED, [gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED),
                                                         gen_payment_op_result(xdr_const.PAYMENT_NO_DESTINATION)])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )
        submit_req = self._set_submit_transaction_resp(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 2

        expected_errors = [InsufficientBalanceError, DestinationDoesNotExistError]
        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == earns[idx]
            assert earn_result.transaction_id  # make sure it's set
            assert isinstance(earn_result.error, expected_errors[idx])

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_retry(self, grpc_channel, executor, retry_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(retry_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=5,  # invalid result code, should throw an error
            hash=model_pb.TransactionHash(value=b'somehash'),
        )

        submit_reqs = []
        for i in range(_config_with_retry.max_retries + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_resp(grpc_channel, resp))

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 1

        earn_result = batch_earn_result.failed[0]
        assert not earn_result.transaction_id
        assert earn_result.earn == earns[0]
        assert isinstance(earn_result.error, Error)

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        for submit_req in submit_reqs:
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo,
                                             sender,
                                             earns)
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_nonce_retry(self, grpc_channel, executor, nonce_retry_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(nonce_retry_client.submit_earn_batch, sender, earns)

        result_xdr = gen_result_xdr(xdr_const.txBAD_SEQ, [])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)
        submit_reqs = []
        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_resp(grpc_channel, resp))

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 1

        earn_result = batch_earn_result.failed[0]
        assert not earn_result.transaction_id
        assert earn_result.earn == earns[0]
        assert isinstance(earn_result.error, BadNonceError)

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        for idx, submit_req in enumerate(submit_reqs):
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11 + idx, expected_memo,
                                             sender,
                                             earns)
            assert len(submit_req.invoice_list.invoices) == 0

    # Kin 4 Tests
    # Note: create_account and get_transaction currently proxies directly to the internal client, which is tested
    # separately. If this changes, more tests should be added.
    def test_get_balance_migrate(self, grpc_channel, executor):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
        client = Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config)

        public_key = PrivateKey.random().public_key
        future = executor.submit(client.get_balance, public_key)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['GetAccountInfo']
        )
        assert request.account_id.value == public_key.stellar_address
        rpc.terminate(account_pb.CreateAccountResponse(), (), grpc.StatusCode.FAILED_PRECONDITION, '')

        self._set_v4_get_min_blockchain_version(grpc_channel, kin_version=4)

        v4_req = self._set_v4_get_account_info_resp(grpc_channel, account_pb_v4.GetAccountInfoResponse(
            result=account_pb_v4.GetAccountInfoResponse.Result.OK,
            account_info=account_pb_v4.AccountInfo(
                account_id=model_pb_v4.SolanaAccountId(value=public_key.raw),
                balance=100000,
            )
        ))
        assert v4_req.account_id.value == public_key.raw

        assert future.result() == 100000
        assert client._kin_version == 4

    def test_create_account_migrate(self, grpc_channel, executor):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
        client = Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config)

        private_key = PrivateKey.random()
        future = executor.submit(client.create_account, private_key)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )
        assert request.account_id.value == private_key.public_key.stellar_address
        rpc.terminate(account_pb.CreateAccountResponse(), (), grpc.StatusCode.FAILED_PRECONDITION, '')

        self._set_v4_get_min_blockchain_version(grpc_channel, kin_version=4)
        self._set_v4_get_service_config_resp(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)
        self._set_v4_get_min_balance_resp(grpc_channel)

        v4_req = self._set_v4_create_account_resp(grpc_channel, account_pb_v4.CreateAccountResponse())

        tx = Transaction.unmarshal(v4_req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert private_key.public_key.verify(tx.message.marshal(), tx.signatures[1])

        sys_create = decompile_create_account(tx.message, 0)
        assert sys_create.funder == _subsidizer
        assert sys_create.address == private_key.public_key
        assert sys_create.owner == _token_program
        assert sys_create.lamports == _min_balance
        assert sys_create.size == token.ACCOUNT_SIZE

        token_init = decompile_initialize_account(tx.message, 1, _token_program)
        assert token_init.account == private_key.public_key
        assert token_init.mint == _token
        assert token_init.owner == private_key.public_key

        assert not future.result()
        assert client._kin_version == 4

    def test_submit_payment_migrate(self, grpc_channel, executor):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
        client = Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config)

        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)
        assert account_req.account_id.value == sender.public_key.stellar_address

        submit_req = self._set_submit_transaction_resp(grpc_channel, tx_pb.SubmitTransactionResponse(),
                                                       grpc.StatusCode.FAILED_PRECONDITION)
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

        self._set_v4_get_min_blockchain_version(grpc_channel, kin_version=4)
        self._set_v4_get_service_config_resp(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        v4_req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(v4_req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        expected_memo = AgoraMemo.new(1, TransactionType.EARN, 1, b'').val
        m = decompile_memo(tx.message, 0)
        assert base64.b64decode(m.data) == expected_memo

        transfer = decompile_transfer(tx.message, 1, _token_program)
        assert transfer.source == sender.public_key
        assert transfer.dest == dest
        assert transfer.owner == sender.public_key
        assert transfer.amount == payment.quarks

        assert not v4_req.invoice_list.invoices

        assert future.result() == b'somesig'
        assert client._kin_version == 4

    def test_submit_payment_migrate_with_acc_resolution(self, grpc_channel, executor):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
        client = Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=retry_config)

        sender = PrivateKey.random()
        resolved_sender = PrivateKey.random().public_key
        dest = PrivateKey.random().public_key
        resolved_dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_resp(grpc_channel, sender, 10)
        assert account_req.account_id.value == sender.public_key.stellar_address

        submit_req = self._set_submit_transaction_resp(grpc_channel, tx_pb.SubmitTransactionResponse(),
                                                       grpc.StatusCode.FAILED_PRECONDITION)
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

        self._set_v4_get_min_blockchain_version(grpc_channel, kin_version=4)
        self._set_v4_get_service_config_resp(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.FAILED,
            transaction_error=model_pb_v4.TransactionError(
                reason=model_pb_v4.TransactionError.Reason.INVALID_ACCOUNT,
            ),
            signature=model_pb_v4.TransactionSignature(value=b'failedsig'),
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
        v4_req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(v4_req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        expected_memo = AgoraMemo.new(1, TransactionType.EARN, 1, b'').val
        m = decompile_memo(tx.message, 0)
        assert base64.b64decode(m.data) == expected_memo

        transfer = decompile_transfer(tx.message, 1, _token_program)
        assert transfer.source == resolved_sender
        assert transfer.dest == resolved_dest
        assert transfer.owner == sender.public_key
        assert transfer.amount == payment.quarks

        assert not v4_req.invoice_list.invoices

        assert future.result() == b'somesig'
        assert client._kin_version == 4

    def test_kin_4_get_balance(self, grpc_channel, executor, kin_4_client):
        private_key = PrivateKey.random()
        future = executor.submit(kin_4_client.get_balance, private_key.public_key)

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

    def test_kin_4_create_account_with_nonce_retry(self, grpc_channel, executor):
        client = Client(Environment.TEST, app_index=1, grpc_channel=grpc_channel, retry_config=_config_with_nonce_retry,
                        kin_version=4)

        private_key = PrivateKey.random()
        future = executor.submit(client.create_account, private_key)

        self._set_v4_get_service_config_resp(grpc_channel)

        create_reqs = []
        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            self._set_v4_get_min_balance_resp(grpc_channel)

            resp = account_pb_v4.CreateAccountResponse(result=account_pb_v4.CreateAccountResponse.Result.BAD_NONCE)
            create_reqs.append(self._set_v4_create_account_resp(grpc_channel, resp))

        assert len(create_reqs) == _config_with_nonce_retry.max_nonce_refreshes + 1
        with pytest.raises(BadNonceError):
            future.result()

    def test_kin_4_submit_payment_invalid(self, grpc_channel, executor, kin_4_client, kin_4_no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key

        # invoice but no app index
        payment = Payment(sender, dest, TransactionType.NONE, 100000, invoice=Invoice([LineItem('title', 100)]))
        future = executor.submit(kin_4_no_app_client.submit_payment, payment)
        with pytest.raises(ValueError):
            future.result()

        # channel for kin 4 payment
        payment = Payment(sender, dest, TransactionType.NONE, 100000, channel=PrivateKey.random())
        future = executor.submit(kin_4_client.submit_payment, payment)
        with pytest.raises(ValueError):
            future.result()

    def test_kin_4_submit_payment_simple(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
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

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_subsidizer(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        subsidizer = PrivateKey.random()
        payment = Payment(sender, dest, TransactionType.NONE, 100000, subsidizer=subsidizer)

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_payment, payment)

        self._set_v4_get_service_config_resp_no_subsidizer(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert subsidizer.public_key.verify(tx.message.marshal(), tx.signatures[0])
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        transfer = decompile_transfer(tx.message, 0, _token_program)
        assert transfer.source == sender.public_key
        assert transfer.dest == dest
        assert transfer.owner == sender.public_key
        assert transfer.amount == payment.quarks

        assert not req.invoice_list.invoices

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_invoice(self, grpc_channel, executor, kin_4_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        invoice = Invoice([LineItem('title1', int(5e5))])
        payment = Payment(sender, dest, TransactionType.NONE, 100000, invoice=invoice)

        kin_4_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel)
        self._set_v4_get_recent_blockhash_resp(grpc_channel)

        resp = tx_pb_v4.SubmitTransactionResponse(
            result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
            signature=model_pb_v4.TransactionSignature(value=b'somesig')
        )
        req = self._set_v4_submit_tx_resp(grpc_channel, resp)

        tx = Transaction.unmarshal(req.transaction.value)
        assert len(tx.signatures) == 2
        assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        expected_memo = AgoraMemo.new(1, TransactionType.NONE, 1, InvoiceList([invoice]).get_sha_224_hash()).val
        m = decompile_memo(tx.message, 0)
        assert base64.b64decode(m.data) == expected_memo

        transfer = decompile_transfer(tx.message, 1, _token_program)
        assert transfer.source == sender.public_key
        assert transfer.dest == dest
        assert transfer.owner == sender.public_key
        assert transfer.amount == payment.quarks

        assert req.invoice_list.invoices[0].SerializeToString() == invoice.to_proto().SerializeToString()

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_acc_resolution(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        resolved_sender = PrivateKey.random().public_key
        dest = PrivateKey.random().public_key
        resolved_dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_payment, payment)

        self._set_v4_get_service_config_resp(grpc_channel)
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
        assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

        transfer = decompile_transfer(tx.message, 0, _token_program)
        assert transfer.source == resolved_sender
        assert transfer.dest == resolved_dest
        assert transfer.owner == sender.public_key
        assert transfer.amount == payment.quarks

        assert not req.invoice_list.invoices

        assert future.result() == b'somesig'

    def test_kin_4_submit_payment_with_acc_resolution_exact(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.NONE, 100000)

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_payment, payment, sender_resolution=AccountResolution.EXACT,
                                 dest_resolution=AccountResolution.EXACT)

        self._set_v4_get_service_config_resp(grpc_channel)
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

    def test_kin_4_submit_earn_batch_simple(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(60)]

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_earn_batch, sender, all_earns)

        self._set_v4_get_service_config_resp(grpc_channel)

        reqs = []
        tx_ids = []

        # this test results in 19 earns per submitted batch
        for i in range(4):
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            tx_id = f'somesig{i}'.encode()
            resp = tx_pb_v4.SubmitTransactionResponse(
                result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
                signature=model_pb_v4.TransactionSignature(value=tx_id),
            )
            reqs.append(self._set_v4_submit_tx_resp(grpc_channel, resp))
            tx_ids.append(tx_id)

        earn_batches = partition(all_earns, 19)
        for idx, req in enumerate(reqs):
            tx = Transaction.unmarshal(req.transaction.value)
            assert len(tx.signatures) == 2
            assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
            assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

            for instruction_idx, earn in enumerate(earn_batches[idx]):
                transfer = decompile_transfer(tx.message, instruction_idx, _token_program)
                assert transfer.source == sender.public_key
                assert transfer.dest == earn.destination
                assert transfer.owner == sender.public_key
                assert transfer.amount == earn.quarks

            assert len(req.invoice_list.invoices) == 0

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 60
        assert len(batch_earn_result.failed) == 0

    def test_kin_4_submit_earn_batch_with_subsidizer(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        subsidizer = PrivateKey.random()
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(60)]

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_earn_batch, sender, all_earns, subsidizer=subsidizer)

        self._set_v4_get_service_config_resp_no_subsidizer(grpc_channel)

        reqs = []
        tx_ids = []

        # this test results in 19 earns per submitted batch
        for i in range(4):
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            tx_id = f'somesig{i}'.encode()
            resp = tx_pb_v4.SubmitTransactionResponse(
                result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
                signature=model_pb_v4.TransactionSignature(value=tx_id),
            )
            reqs.append(self._set_v4_submit_tx_resp(grpc_channel, resp))
            tx_ids.append(tx_id)

        earn_batches = partition(all_earns, 19)
        for idx, req in enumerate(reqs):
            tx = Transaction.unmarshal(req.transaction.value)
            assert len(tx.signatures) == 2
            assert subsidizer.public_key.verify(tx.message.marshal(), tx.signatures[0])
            assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

            for instruction_idx, earn in enumerate(earn_batches[idx]):
                transfer = decompile_transfer(tx.message, instruction_idx, _token_program)
                assert transfer.source == sender.public_key
                assert transfer.dest == earn.destination
                assert transfer.owner == sender.public_key
                assert transfer.amount == earn.quarks

            assert len(req.invoice_list.invoices) == 0

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 60
        assert len(batch_earn_result.failed) == 0

    def test_kin_4_submit_earn_batch_memo(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(60)]

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_earn_batch, sender, all_earns, memo='somememo')

        self._set_v4_get_service_config_resp(grpc_channel)

        reqs = []
        tx_ids = []

        # this test results in 19 earns per submitted batch because of the memo
        for i in range(4):
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            tx_id = f'somesig{i}'.encode()
            resp = tx_pb_v4.SubmitTransactionResponse(
                result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
                signature=model_pb_v4.TransactionSignature(value=tx_id),
            )
            reqs.append(self._set_v4_submit_tx_resp(grpc_channel, resp))
            tx_ids.append(tx_id)

        earn_batches = partition(all_earns, 19)
        for idx, req in enumerate(reqs):
            tx = Transaction.unmarshal(req.transaction.value)
            assert len(tx.signatures) == 2
            assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
            assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

            m = decompile_memo(tx.message, 0)
            assert m.data.decode('utf-8') == 'somememo'

            for instruction_idx, earn in enumerate(earn_batches[idx]):
                transfer = decompile_transfer(tx.message, instruction_idx + 1, _token_program)
                assert transfer.source == sender.public_key
                assert transfer.dest == earn.destination
                assert transfer.owner == sender.public_key
                assert transfer.amount == earn.quarks

            assert len(req.invoice_list.invoices) == 0

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 60
        assert len(batch_earn_result.failed) == 0

    def test_kin_4_submit_earn_batch_with_invoices(self, grpc_channel, executor, kin_4_client):
        sender = PrivateKey.random()
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku')])
        all_earns = [Earn(PrivateKey.random().public_key, i,
                          invoice=invoice) for i in range(60)]

        kin_4_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_client.submit_earn_batch, sender, all_earns)

        self._set_v4_get_service_config_resp(grpc_channel)

        reqs = []
        tx_ids = []

        # this test results in 18 earns per submitted batch because of the memo
        for i in range(4):
            self._set_v4_get_recent_blockhash_resp(grpc_channel)
            tx_id = f'somesig{i}'.encode()
            resp = tx_pb_v4.SubmitTransactionResponse(
                result=tx_pb_v4.SubmitTransactionResponse.Result.OK,
                signature=model_pb_v4.TransactionSignature(value=tx_id),
            )
            reqs.append(self._set_v4_submit_tx_resp(grpc_channel, resp))
            tx_ids.append(tx_id)

        earn_batches = partition(all_earns, 18)
        for idx, req in enumerate(reqs):
            tx = Transaction.unmarshal(req.transaction.value)
            assert len(tx.signatures) == 2
            assert tx.signatures[0] == bytes(SIGNATURE_LENGTH)
            assert sender.public_key.verify(tx.message.marshal(), tx.signatures[1])

            m = decompile_memo(tx.message, 0)
            il = InvoiceList([invoice] * len(earn_batches[idx]))
            expected_memo = AgoraMemo.new(1, TransactionType.EARN, 1, il.get_sha_224_hash()).val
            assert m.data == base64.b64encode(expected_memo)

            for instruction_idx, earn in enumerate(earn_batches[idx]):
                transfer = decompile_transfer(tx.message, instruction_idx + 1, _token_program)
                assert transfer.source == sender.public_key
                assert transfer.dest == earn.destination
                assert transfer.owner == sender.public_key
                assert transfer.amount == earn.quarks

            assert len(req.invoice_list.invoices) == len(earn_batches[idx])

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 60
        assert len(batch_earn_result.failed) == 0

    def test_kin_4_submit_earn_batch_with_acc_resolution(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        resolved_sender = PrivateKey.random().public_key
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(10)]
        resolved_destinations = [PrivateKey.random().public_key for _ in all_earns]

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(kin_4_no_app_client.submit_earn_batch, sender, all_earns)

        self._set_v4_get_service_config_resp(grpc_channel)

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

        for idx, earn in enumerate(all_earns):
            transfer = decompile_transfer(tx.message, idx, _token_program)
            assert transfer.source == resolved_sender
            assert transfer.dest == resolved_destinations[idx]
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 10
        assert len(batch_earn_result.failed) == 0

    def test_kin_4_submit_earn_batch_failed_acc_resolution_exact(self, grpc_channel, executor, kin_4_no_app_client):
        sender = PrivateKey.random()
        all_earns = [Earn(PrivateKey.random().public_key, i) for i in range(10)]

        kin_4_no_app_client._internal_client._response_cache.clear_all()
        future = executor.submit(
            kin_4_no_app_client.submit_earn_batch, sender, all_earns, sender_resolution=AccountResolution.EXACT,
            dest_resolution=AccountResolution.EXACT,
        )

        self._set_v4_get_service_config_resp(grpc_channel)

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

        for idx, earn in enumerate(all_earns):
            transfer = decompile_transfer(tx.message, idx, _token_program)
            assert transfer.source == sender.public_key
            assert transfer.dest == earn.destination
            assert transfer.owner == sender.public_key
            assert transfer.amount == earn.quarks

        assert len(req.invoice_list.invoices) == 0

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 10
        for idx, result in enumerate(batch_earn_result.failed):
            assert result.earn == all_earns[idx]
            assert result.transaction_id == b'failedsig'
            assert isinstance(result.error, AccountNotFoundError)

    @pytest.mark.parametrize(
        "has_separate_sender, has_agora_memo, has_text_memo",
        [
            (False, False, False),
            (False, False, True),
            (False, True, False),
            (True, False, False),
            (True, False, True),
            (True, True, False),
        ]
    )
    def test_estimate_earn_batch_tx_size(self, kin_4_no_app_client, has_separate_sender, has_agora_memo, has_text_memo):
        subsidizer = PrivateKey.random()
        token_program = PrivateKey.random().public_key

        owner = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, i) for i in range(20)]
        transfer_sender = PrivateKey.random() if has_separate_sender else None
        agora_memo = AgoraMemo.new(1, TransactionType.NONE, 1, b'') if has_agora_memo else None
        text_memo = "1-text" if has_text_memo else None
        print(text_memo)

        for i in range(1, len(earns)):
            batch = earns[:i]
            instructions = []

            if has_agora_memo:
                instructions.append(memo_instruction(base64.b64encode(agora_memo.val).decode('utf-8')))
            elif has_text_memo:
                instructions.append(memo_instruction(text_memo))

            sender = transfer_sender if transfer_sender else owner
            instructions += [
                transfer(sender.public_key, earn.destination, owner.public_key, earn.quarks, token_program)
                for earn in batch]

            tx = solana.Transaction.new(subsidizer.public_key, instructions)
            tx.sign([subsidizer, owner])
            est = Client._estimate_earn_batch_tx_size(
                batch,
                has_separate_sender=has_separate_sender,
                has_agora_memo=has_agora_memo,
                memo=text_memo)
            print(f'estimated: {est}')
            assert est == len(tx.marshal())

    @staticmethod
    def _set_v4_create_account_resp(
        channel: grpc_testing.Channel, resp: account_pb_v4.CreateAccountResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK,
    ) -> account_pb.CreateAccountRequest:
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
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetServiceConfigRequest:
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
        channel: grpc_testing.Channel,
    ) -> tx_pb_v4.GetServiceConfigRequest:
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
    def _set_get_account_info_resp(
        channel: grpc_testing.Channel, resp: account_pb.GetAccountInfoResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ) -> account_pb.GetAccountInfoRequest:
        md, request, rpc = channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['GetAccountInfo']
        )
        rpc.terminate(resp, (), status, '')
        TestAgoraClient._assert_user_agent(md)
        return request

    @staticmethod
    def _set_successful_get_account_info_resp(
        channel: grpc_testing.Channel, pk: PrivateKey, sequence: int, balance: int = kin_to_quarks("1000"),
    ) -> account_pb.GetAccountInfoRequest:
        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.OK,
            account_info=account_pb.AccountInfo(
                account_id=model_pb.StellarAccountId(
                    value=pk.public_key.stellar_address
                ),
                sequence_number=sequence,
                balance=balance,
            )
        )
        return TestAgoraClient._set_get_account_info_resp(channel, resp)

    @staticmethod
    def _set_submit_transaction_resp(
        channel: grpc_testing.Channel, resp: tx_pb.SubmitTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ) -> tx_pb.SubmitTransactionRequest:
        md, request, rpc = channel.take_unary_unary(
            tx_pb.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['SubmitTransaction']
        )
        rpc.terminate(resp, (), status, '')
        TestAgoraClient._assert_user_agent(md)
        return request

    @staticmethod
    def _set_successful_submit_transaction_resp(channel: grpc_testing.Channel, tx_hash: bytes, result_xdr: bytes):
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.OK,
            hash=model_pb.TransactionHash(value=tx_hash),
            ledger=10,
            result_xdr=result_xdr,
        )
        return TestAgoraClient._set_submit_transaction_resp(channel, resp)

    @staticmethod
    def _assert_payment_envelope(
        envelope_xdr: bytes, signers: List[PrivateKey], tx_source: PrivateKey, base_fee: int, sequence: int,
        tx_memo: memo.Memo, payment: Payment
    ):
        envelope = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))
        operations = envelope.tx.operations

        TestAgoraClient._assert_envelope_properties(envelope, signers, tx_source, base_fee, sequence,
                                                    tx_memo)

        for idx, op in enumerate(operations):
            assert isinstance(op, operation.Payment)
            assert op.source == payment.sender.public_key.stellar_address
            assert op.destination == payment.destination.stellar_address
            assert op.amount == quarks_to_kin(payment.quarks)

    @staticmethod
    def _assert_earn_batch_envelope(
        envelope_xdr: bytes, signers: List[PrivateKey], tx_source: PrivateKey,
        base_fee: int, sequence: int, tx_memo: memo.Memo, sender: PrivateKey, earns: List[Earn]
    ):
        envelope = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))
        operations = envelope.tx.operations

        TestAgoraClient._assert_envelope_properties(envelope, signers, tx_source, base_fee * len(operations), sequence,
                                                    tx_memo)

        assert len(operations) == len(earns)
        for idx, op in enumerate(operations):
            earn = earns[idx]
            assert isinstance(op, operation.Payment)
            assert op.source == sender.public_key.stellar_address
            assert op.destination == earn.destination.stellar_address
            assert op.amount == quarks_to_kin(earn.quarks)

    @staticmethod
    def _assert_envelope_properties(
        envelope: te.TransactionEnvelope, signers: List[PrivateKey], tx_source: PrivateKey,
        fee: int, sequence: int, tx_memo: memo.Memo
    ):
        assert len(envelope.signatures) == len(signers)
        for idx, signer in enumerate(signers):
            signer.public_key.verify(envelope.hash_meta(), envelope.signatures[idx].signature)

        tx = envelope.tx
        assert tx.source.decode() == tx_source.public_key.stellar_address
        assert tx.fee == fee
        assert tx.sequence == sequence
        assert tx.memo == tx_memo

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

    @staticmethod
    def _assert_kin_2_payment_envelope(
        envelope_xdr: bytes, signers: List[PrivateKey], tx_source: PrivateKey, base_fee: int, sequence: int,
        tx_memo: memo.Memo, payment: Payment
    ):
        envelope = kin_2_envelope_from_xdr(_NETWORK_NAMES[2][Environment.TEST], base64.b64encode(envelope_xdr))
        operations = envelope.tx.operations

        TestAgoraClient._assert_envelope_properties(envelope, signers, tx_source, base_fee, sequence, tx_memo)

        for idx, op in enumerate(operations):
            assert isinstance(op, operation.Payment)
            assert op.source == payment.sender.public_key.stellar_address
            assert op.destination == payment.destination.stellar_address

            # Inside the kin_base module, the base currency has been 'scaled' by a factor of 100 from
            # Stellar (i.e., the smallest denomination used is 1e-5 instead of 1e-7). However, Kin 2 uses the minimum
            # Stellar denomination of 1e-7.
            #
            # When parsing an XDR transaction, which contains amounts in the smallest denomination of the currency,
            # `kin_base` assumes a smallest denomination of 1e-5. Therefore, for Kin 2 transactions, we must multiply
            # what we expect the amount to be by 100 to account for the 100x scaling factor.
            assert op.amount == quarks_to_kin(payment.quarks * 100)

    @staticmethod
    def _assert_kin_2_earn_batch_envelope(
        envelope_xdr: bytes, signers: List[PrivateKey], tx_source: PrivateKey,
        base_fee: int, sequence: int, tx_memo: memo.Memo, sender: PrivateKey, earns: List[Earn]
    ):
        envelope = kin_2_envelope_from_xdr(_NETWORK_NAMES[2][Environment.TEST], base64.b64encode(envelope_xdr))
        operations = envelope.tx.operations

        TestAgoraClient._assert_envelope_properties(envelope, signers, tx_source, base_fee * len(operations), sequence,
                                                    tx_memo)
        assert len(operations) == len(earns)
        for idx, op in enumerate(operations):
            earn = earns[idx]
            assert isinstance(op, operation.Payment)
            assert op.source == sender.public_key.stellar_address
            assert op.destination == earn.destination.stellar_address

            # Inside the kin_base module, the base currency has been 'scaled' by a factor of 100 from
            # Stellar (i.e., the smallest denomination used is 1e-5 instead of 1e-7). However, Kin 2 uses the minimum
            # Stellar denomination of 1e-7.
            #
            # When parsing an XDR transaction, which contains amounts in the smallest denomination of the currency,
            # `kin_base` assumes a smallest denomination of 1e-5. Therefore, for Kin 2 transactions, we must multiply
            # what we expect the amount to be by 100 to account for the 100x scaling factor.
            assert op.amount == quarks_to_kin(earn.quarks * 100)
