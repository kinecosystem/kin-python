import base64
from concurrent import futures
from typing import List

import grpc
import grpc_testing
import pytest
from agoraapi.account.v3 import account_service_pb2 as account_pb
from agoraapi.common.v3 import model_pb2
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base import transaction_envelope as te, memo, operation
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora.client.client import Client, RetryConfig, BaseClient
from agora.client.environment import Environment
from agora.error import AccountExistsError, AccountNotFoundError, InsufficientBalanceError, \
    DestinationDoesNotExistError, BadNonceError, UnsupportedVersionError, \
    TransactionRejectedError, TransactionNotFound, Error, AlreadyPaidError
from agora.model.earn import Earn
from agora.model.invoice import InvoiceList, Invoice, LineItem
from agora.model.keys import PrivateKey
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.transaction_type import TransactionType
from agora.utils import partition, kin_to_quarks, quarks_to_kin
from tests.utils import gen_account_id, gen_tx_envelope_xdr, gen_payment_op, \
    gen_payment_op_result, gen_result_xdr, gen_hash_memo

_config_with_retry = RetryConfig(max_retries=2, min_delay=0.1, max_delay=2, max_nonce_refreshes=0)
_config_with_nonce_retry = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=2)


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
            client.submit_payment(Payment(private_key, public_key, TransactionType.UNKNOWN, 0))

        with pytest.raises(NotImplementedError):
            client.submit_earn_batch(private_key, [])


# Filter warnings caused by instantiating Horizon inside AgoraApi
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
class TestAgoraClient:
    def test_invalid_inits(self, grpc_channel):
        with pytest.raises(ValueError):
            Client(Environment.TEST, grpc_channel=grpc_channel, endpoint='fakeendpoint')

    def test_unsupported_version(self, grpc_channel):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
        client = Client(Environment.TEST, grpc_channel=grpc_channel, retry_config=retry_config)
        client._kin_version = 4

        private_key = PrivateKey.random()
        public_key = PrivateKey.random().public_key
        with pytest.raises(UnsupportedVersionError):
            client.create_account(private_key)

        with pytest.raises(UnsupportedVersionError):
            client.get_balance(public_key)

        with pytest.raises(UnsupportedVersionError):
            client.submit_payment(Payment(private_key, public_key, TransactionType.UNKNOWN, 0))

        with pytest.raises(UnsupportedVersionError):
            client.submit_earn_batch(private_key, [])

    def test_create_account(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.create_account, private_key)

        _, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )

        rpc.terminate(account_pb.CreateAccountResponse(), (), grpc.StatusCode.OK, '')

        assert request.account_id.value == private_key.public_key.stellar_address
        assert not future.result()

    def test_create_account_exists(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        application_future = executor.submit(app_index_client.create_account, private_key)

        _, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )
        resp = account_pb.CreateAccountResponse(result=account_pb.CreateAccountResponse.Result.EXISTS)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        with pytest.raises(AccountExistsError):
            application_future.result()

        assert request.account_id.value == private_key.public_key.stellar_address

    def test_get_transaction(self, grpc_channel, executor, app_index_client):
        tx_hash = b'somehash'
        future = executor.submit(app_index_client.get_transaction, tx_hash)

        _, request, rpc = grpc_channel.take_unary_unary(
            tx_pb.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        # Create full response
        op_result = gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)
        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [op_result, op_result])

        il = model_pb2.InvoiceList(invoices=[
            model_pb2.Invoice(
                items=[
                    model_pb2.Invoice.LineItem(title='t1', amount=15),
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

        history_item = tx_pb.HistoryItem(
            hash=model_pb2.TransactionHash(value=tx_hash),
            result_xdr=result_xdr,
            envelope_xdr=envelope_xdr,
            cursor=tx_pb.Cursor(value=b'cursor1'),
            invoice_list=il,
        )
        resp = tx_pb.GetTransactionResponse(
            state=tx_pb.GetTransactionResponse.State.SUCCESS,
            ledger=10,
            item=history_item,
        )
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        tx_data = future.result()
        assert tx_data.tx_hash == tx_hash
        assert len(tx_data.payments) == 1
        assert not tx_data.error

        payment1 = tx_data.payments[0]
        assert payment1.sender.raw == acc1.ed25519
        assert payment1.dest.raw == acc2.ed25519
        assert payment1.payment_type == memo.tx_type()
        assert payment1.quarks == 15
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        assert request.transaction_hash.value == tx_hash

    def test_get_transaction_unknown(self, grpc_channel, executor, app_index_client):
        tx_hash = b'somehash'
        future = executor.submit(app_index_client.get_transaction, tx_hash)

        _, request, rpc = grpc_channel.take_unary_unary(
            tx_pb.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        resp = tx_pb.GetTransactionResponse(state=tx_pb.GetTransactionResponse.State.UNKNOWN)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        with pytest.raises(TransactionNotFound):
            future.result()

        assert request.transaction_hash.value == tx_hash

    def test_get_balance(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.get_balance, private_key.public_key)

        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.OK,
            account_info=account_pb.AccountInfo(
                account_id=model_pb2.StellarAccountId(
                    value=private_key.public_key.stellar_address
                ),
                sequence_number=10,
                balance=100000,
            )
        )
        req = self._set_get_account_info_response(grpc_channel, resp)

        assert future.result() == 100000

        assert req.account_id.value == private_key.public_key.stellar_address

    def test_get_balance_not_found(self, grpc_channel, executor, app_index_client):
        private_key = PrivateKey.random()
        future = executor.submit(app_index_client.get_balance, private_key.public_key)

        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.NOT_FOUND,
        )
        req = self._set_get_account_info_response(grpc_channel, resp)

        with pytest.raises(AccountNotFoundError):
            future.result()

        assert req.account_id.value == private_key.public_key.stellar_address

    def test_submit_payment_simple(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_source(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        source = PrivateKey.random()
        payment = Payment(sender, dest, TransactionType.EARN, 100000,
                          source=source)

        future = executor.submit(app_index_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, source, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == source.public_key.stellar_address

        expected_signers = [source, sender]
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_payment_envelope(submit_req.envelope_xdr, expected_signers, source, 100, 11, expected_memo,
                                      payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_whitelisting(self, grpc_channel, executor, whitelisting_client):
        sender = PrivateKey.random()
        dest = PrivateKey.random().public_key
        payment = Payment(sender, dest, TransactionType.EARN, 100000)

        future = executor.submit(whitelisting_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.REJECTED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR,
            invoice_errors=[
                tx_pb.SubmitTransactionResponse.InvoiceError(
                    op_index=0,
                    invoice=invoice.to_proto(),
                    reason=tx_pb.SubmitTransactionResponse.InvoiceError.Reason.ALREADY_PAID,
                )
            ]
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txFAILED, [gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED)])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=5,  # invalid result code, should throw an error
            hash=model_pb2.TransactionHash(value=b'somehash'),
        )

        submit_reqs = []
        for i in range(_config_with_retry.max_retries + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_response(grpc_channel, resp))

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
            hash=model_pb2.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )

        account_reqs = []
        submit_reqs = []
        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            account_reqs.append(self._set_successful_get_account_info_response(grpc_channel, sender, 10))
            submit_reqs.append(self._set_submit_transaction_response(grpc_channel, resp))

        with pytest.raises(BadNonceError):
            future.result()

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        for submit_req in submit_reqs:
            self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
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
            account_reqs.append(self._set_successful_get_account_info_response(grpc_channel, sender, starting_seq + i))
            tx_hash = 'somehash{}'.format(i).encode()
            submit_reqs.append(self._set_successful_submit_transaction_response(grpc_channel, tx_hash, result_xdr))
            tx_hashes.append(tx_hash)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 250
        assert len(batch_earn_result.failed) == 0

        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == all_earns[idx]
            assert earn_result.tx_hash == tx_hashes[idx // 100]
            assert not earn_result.error

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.public_key.stellar_address

        earn_batches = partition(all_earns, 100)
        for idx, submit_req in enumerate(submit_reqs):
            expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, starting_seq + idx + 1,
                                             expected_memo, sender, earn_batches[idx])
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_source(self, grpc_channel, executor, app_index_client):
        sender = PrivateKey.random()
        source = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(app_index_client.submit_earn_batch, sender, earns, source=source)

        account_req = self._set_successful_get_account_info_response(grpc_channel, source, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 1
        assert len(batch_earn_result.failed) == 0

        earn_result = batch_earn_result.succeeded[0]
        assert earn_result.earn == earns[0]
        assert earn_result.tx_hash == b'somehash'
        assert not earn_result.error

        assert account_req.account_id.value == source.public_key.stellar_address

        expected_signers = [source, sender]
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, expected_signers, source, 100, 11, expected_memo,
                                         sender, earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_whitelisting(self, grpc_channel, executor, whitelisting_client):
        sender = PrivateKey.random()
        earns = [Earn(PrivateKey.random().public_key, 100000)]

        future = executor.submit(whitelisting_client.submit_earn_batch, sender, earns)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 1
        assert len(batch_earn_result.failed) == 0

        earn_result = batch_earn_result.succeeded[0]
        assert earn_result.earn == earns[0]
        assert earn_result.tx_hash == b'somehash'
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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 1
        assert len(batch_earn_result.failed) == 0

        earn_result = batch_earn_result.succeeded[0]
        assert earn_result.earn == earns[0]
        assert earn_result.tx_hash == b'somehash'
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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 2
        assert len(batch_earn_result.failed) == 0

        for idx, earn_result in enumerate(batch_earn_result.succeeded):
            assert earn_result.tx_hash == b'somehash'
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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.REJECTED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 2

        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == earns[idx]
            assert not earn_result.tx_hash
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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.INVOICE_ERROR,
            invoice_errors=[
                tx_pb.SubmitTransactionResponse.InvoiceError(
                    op_index=0,
                    invoice=earns[0].invoice.to_proto(),
                    reason=tx_pb.SubmitTransactionResponse.InvoiceError.Reason.ALREADY_PAID,
                ),
                tx_pb.SubmitTransactionResponse.InvoiceError(
                    op_index=0,
                    invoice=earns[1].invoice.to_proto(),
                    reason=tx_pb.SubmitTransactionResponse.InvoiceError.Reason.WRONG_DESTINATION,
                )
            ]
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 2

        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == earns[idx]
            assert not earn_result.tx_hash
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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txFAILED, [gen_payment_op_result(xdr_const.PAYMENT_UNDERFUNDED),
                                                         gen_payment_op_result(xdr_const.PAYMENT_NO_DESTINATION)])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 2

        expected_errors = [InsufficientBalanceError, DestinationDoesNotExistError]
        for idx, earn_result in enumerate(batch_earn_result.failed):
            assert earn_result.earn == earns[idx]
            assert earn_result.tx_hash  # make sure it's set
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

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=5,  # invalid result code, should throw an error
            hash=model_pb2.TransactionHash(value=b'somehash'),
        )

        submit_reqs = []
        for i in range(_config_with_retry.max_retries + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_response(grpc_channel, resp))

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 1

        earn_result = batch_earn_result.failed[0]
        assert not earn_result.tx_hash
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
            hash=model_pb2.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )

        account_reqs = []
        submit_reqs = []
        for i in range(_config_with_nonce_retry.max_nonce_refreshes + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            account_reqs.append(self._set_successful_get_account_info_response(grpc_channel, sender, 10))
            submit_reqs.append(self._set_submit_transaction_response(grpc_channel, resp))

        batch_earn_result = future.result()
        assert len(batch_earn_result.succeeded) == 0
        assert len(batch_earn_result.failed) == 1

        earn_result = batch_earn_result.failed[0]
        assert not earn_result.tx_hash
        assert earn_result.earn == earns[0]
        assert isinstance(earn_result.error, BadNonceError)

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.public_key.stellar_address

        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 1, b'').val)
        for submit_req in submit_reqs:
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo,
                                             sender,
                                             earns)
            assert len(submit_req.invoice_list.invoices) == 0

    @staticmethod
    def _set_get_account_info_response(
        channel: grpc_testing.Channel, resp: account_pb.GetAccountInfoResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ) -> account_pb.GetAccountInfoRequest:
        _, request, rpc = channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['GetAccountInfo']
        )
        rpc.terminate(resp, (), status, '')
        return request

    @staticmethod
    def _set_successful_get_account_info_response(
        channel: grpc_testing.Channel, pk: PrivateKey, sequence: int, balance: int = kin_to_quarks("1000")
    ) -> account_pb.GetAccountInfoRequest:
        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.OK,
            account_info=account_pb.AccountInfo(
                account_id=model_pb2.StellarAccountId(
                    value=pk.public_key.stellar_address
                ),
                sequence_number=sequence,
                balance=balance,
            )
        )
        return TestAgoraClient._set_get_account_info_response(channel, resp)

    @staticmethod
    def _set_submit_transaction_response(
        channel: grpc_testing.Channel, resp: tx_pb.SubmitTransactionResponse,
        status: grpc.StatusCode = grpc.StatusCode.OK
    ) -> tx_pb.SubmitTransactionRequest:
        _, request, rpc = channel.take_unary_unary(
            tx_pb.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['SubmitTransaction']
        )
        rpc.terminate(resp, (), status, '')
        return request

    @staticmethod
    def _set_successful_submit_transaction_response(channel: grpc_testing.Channel, tx_hash: bytes, result_xdr: bytes):
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.OK,
            hash=model_pb2.TransactionHash(value=tx_hash),
            ledger=10,
            result_xdr=result_xdr,
        )
        return TestAgoraClient._set_submit_transaction_response(channel, resp)

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
            signer.verify(envelope.hash_meta(), envelope.signatures[idx].signature)

        tx = envelope.tx
        assert tx.source.decode() == tx_source.public_key.stellar_address
        assert tx.fee == fee
        assert tx.sequence == sequence
        assert tx.memo == tx_memo
