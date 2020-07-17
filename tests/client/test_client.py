import base64
from concurrent import futures
from typing import List

import ed25519
import grpc
import grpc_testing
import kin_base
import pytest
from agoraapi.account.v3 import account_service_pb2 as account_pb
from agoraapi.common.v3 import model_pb2
from agoraapi.transaction.v3 import transaction_service_pb2 as tx_pb
from kin_base import transaction_envelope as te, memo, operation
from kin_base.stellarxdr import StellarXDR_const as xdr_const

from agora.client.client import Client, RetryConfig, BaseClient
from agora.client.utils import _KIN_TO_QUARKS, kin_to_quarks, quarks_to_kin
from agora.client.environment import Environment
from agora.error import AccountExistsError, AccountNotFoundError, InvoiceError, InvoiceErrorReason, \
    InsufficientBalanceError, OperationInvoiceError, DestinationDoesNotExistError, TransactionError, BadNonceError, \
    UnsupportedVersionError, TransactionRejectedError
from agora.model.earn import Earn
from agora.model.invoice import InvoiceList, Invoice, LineItem
from agora.model.memo import AgoraMemo
from agora.model.payment import Payment
from agora.model.transaction import TransactionState
from agora.model.transaction_type import TransactionType
from agora.utils import partition
from tests.utils import gen_account_id, gen_tx_envelope_xdr, gen_payment_op, \
    gen_payment_op_result, gen_result_xdr, gen_hash_memo

_config_with_retry = RetryConfig(max_retries=2, min_delay=0.5, max_delay=2, max_nonce_refreshes=0)
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
def no_retry_client(grpc_channel) -> Client:
    """Returns an AgoraClient that has no retrying configured.
    """
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, 0, grpc_channel=grpc_channel, retry_config=retry_config)


@pytest.fixture(scope='class')
def whitelisting_client(grpc_channel) -> Client:
    """Returns an AgoraClient that has no retrying configured and a whitelist keypair set.
    """
    whitelisting_kp = kin_base.Keypair.random()
    retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
    return Client(Environment.TEST, 0, whitelist_key=whitelisting_kp.raw_seed(),
                  grpc_channel=grpc_channel, retry_config=retry_config)


@pytest.fixture(scope='class')
def retry_client(grpc_channel):
    """Returns an AgoraClient that has retrying configured for non-nonce-related errors.
    """
    return Client(Environment.TEST, 0, grpc_channel=grpc_channel, retry_config=_config_with_retry)


@pytest.fixture(scope='class')
def nonce_retry_client(grpc_channel):
    """Returns an AgoraClient that has retrying configured only for nonce-related errors.
    """
    return Client(Environment.TEST, 0, grpc_channel=grpc_channel, retry_config=_config_with_nonce_retry)


class TestBaseClient(object):
    def test_not_implemented(self):
        client = BaseClient()
        with pytest.raises(NotImplementedError):
            client.create_account(b'')

        with pytest.raises(NotImplementedError):
            client.get_transaction(b'')

        with pytest.raises(NotImplementedError):
            client.get_balance(b'')

        with pytest.raises(NotImplementedError):
            client.submit_payment(Payment(b'', b'', TransactionType.UNKNOWN, 0))

        with pytest.raises(NotImplementedError):
            client.submit_earn_batch(b'', [])


# Filter warnings caused by instantiating Horizon inside AgoraApi
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
class TestAgoraClient(object):
    def test_unsupported_version(self, grpc_channel):
        retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
        client = Client(Environment.TEST, 0, grpc_channel=grpc_channel, retry_config=retry_config)
        client._kin_version = 4

        with pytest.raises(UnsupportedVersionError):
            client.create_account(b'')

        with pytest.raises(UnsupportedVersionError):
            client.get_balance(b'')

        with pytest.raises(UnsupportedVersionError):
            client.submit_payment(Payment(b'', b'', TransactionType.UNKNOWN, 0))

        with pytest.raises(UnsupportedVersionError):
            client.submit_earn_batch(b'', [])

    def test_create_account(self, grpc_channel, executor, no_retry_client):
        kp = kin_base.Keypair.random()
        future = executor.submit(no_retry_client.create_account, kp.raw_seed())

        _, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )

        rpc.terminate(account_pb.CreateAccountResponse(), (), grpc.StatusCode.OK, '')

        assert request.account_id.value == kp.address().decode()
        assert not future.result()

    def test_create_account_exists(self, grpc_channel, executor, no_retry_client):
        kp = kin_base.Keypair.random()
        application_future = executor.submit(no_retry_client.create_account, kp.raw_seed())

        _, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['CreateAccount']
        )
        resp = account_pb.CreateAccountResponse(result=account_pb.CreateAccountResponse.Result.EXISTS)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        with pytest.raises(AccountExistsError):
            application_future.result()

        assert request.account_id.value == kp.address().decode()

    def test_get_transaction(self, grpc_channel, executor, no_retry_client):
        tx_hash = b'somehash'
        future = executor.submit(no_retry_client.get_transaction, tx_hash)

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
        memo = AgoraMemo.new(1, TransactionType.EARN, 0, fk)
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

        status, data = future.result()
        assert status == TransactionState.SUCCESS
        assert data.tx_hash == tx_hash
        assert len(data.payments) == 1

        payment1 = data.payments[0]
        assert payment1.sender == acc1.ed25519
        assert payment1.dest == acc2.ed25519
        assert payment1.payment_type == memo.tx_type()
        assert payment1.quarks == 15
        assert (payment1.invoice.to_proto().SerializeToString() == il.invoices[0].SerializeToString())
        assert not payment1.memo

        assert request.transaction_hash.value == tx_hash

    def test_get_transaction_no_data(self, grpc_channel, executor, no_retry_client):
        tx_hash = b'somehash'
        future = executor.submit(no_retry_client.get_transaction, tx_hash)

        _, request, rpc = grpc_channel.take_unary_unary(
            tx_pb.DESCRIPTOR.services_by_name['Transaction'].methods_by_name['GetTransaction']
        )

        resp = tx_pb.GetTransactionResponse(state=tx_pb.GetTransactionResponse.State.UNKNOWN)
        rpc.terminate(resp, (), grpc.StatusCode.OK, '')

        status, data = future.result()
        assert status == TransactionState.UNKNOWN
        assert not data

        assert request.transaction_hash.value == tx_hash

    def test_get_balance(self, grpc_channel, executor, no_retry_client):
        kp = kin_base.Keypair.random()
        future = executor.submit(no_retry_client.get_balance, kp.raw_public_key())

        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.OK,
            account_info=account_pb.AccountInfo(
                account_id=model_pb2.StellarAccountId(
                    value=kp.address().decode()
                ),
                sequence_number=10,
                balance=100000,
            )
        )
        req = self._set_get_account_info_response(grpc_channel, resp)

        assert future.result() == 100000

        assert req.account_id.value == kp.address().decode()

    def test_get_balance_not_found(self, grpc_channel, executor, no_retry_client):
        kp = kin_base.Keypair.random()
        future = executor.submit(no_retry_client.get_balance, kp.raw_public_key())

        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.NOT_FOUND,
        )
        req = self._set_get_account_info_response(grpc_channel, resp)

        with pytest.raises(AccountNotFoundError):
            future.result()

        assert req.account_id.value == kp.address().decode()

    def test_submit_payment_simple(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000)

        future = executor.submit(no_retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.address().decode()

        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_source(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        source = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000,
                          source=source.raw_seed())

        future = executor.submit(no_retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, source, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == source.address().decode()

        expected_signers = [sender, source]
        self._assert_payment_envelope(submit_req.envelope_xdr, expected_signers, source, 100, 11, memo.NoneMemo(),
                                      payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_whitelisting(self, grpc_channel, executor, whitelisting_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000)

        future = executor.submit(whitelisting_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.address().decode()

        self._assert_payment_envelope(submit_req.envelope_xdr, [sender, whitelisting_client.whitelist_kp], sender, 0,
                                      11,
                                      memo.NoneMemo(), payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_invoice(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku')])
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000, invoice=invoice)

        future = executor.submit(no_retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.address().decode()

        expected_memo = memo.HashMemo(
            AgoraMemo.new(1, TransactionType.EARN, 0, InvoiceList([invoice]).get_sha_224_hash()).val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 1
        assert submit_req.invoice_list.invoices[0].SerializeToString() == invoice.to_proto().SerializeToString()

    def test_submit_payment_with_memo(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000, memo='somememo')

        future = executor.submit(no_retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        assert future.result() == b'somehash'

        assert account_req.account_id.value == sender.address().decode()

        expected_memo = memo.TextMemo('somememo')
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_rejected(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000)

        future = executor.submit(no_retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.REJECTED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

        with pytest.raises(TransactionRejectedError):
            future.result()

        assert account_req.account_id.value == sender.address().decode()

        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_invoice_error(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        invoice = Invoice([LineItem('title1', 100000, 'description1', b'somesku1')])
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000, invoice=invoice)

        future = executor.submit(no_retry_client.submit_payment, payment)

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

        with pytest.raises(InvoiceError) as excinfo:
            future.result()

            e = excinfo.value
            assert len(e.errors) == 1
            assert e.errors[0].op_index == 0
            assert e.errors[0].reason == InvoiceErrorReason.ALREADY_PAID

        assert account_req.account_id.value == sender.address().decode()

        expected_memo = memo.HashMemo(
            AgoraMemo.new(1, TransactionType.EARN, 0, InvoiceList([invoice]).get_sha_224_hash()).val)
        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, payment)
        assert len(submit_req.invoice_list.invoices) == 1
        assert submit_req.invoice_list.invoices[0].SerializeToString() == invoice.to_proto().SerializeToString()

    def test_submit_payment_tx_failed(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000)

        future = executor.submit(no_retry_client.submit_payment, payment)

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

        assert account_req.account_id.value == sender.address().decode()

        self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), payment)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_retry(self, grpc_channel, executor, retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000)

        future = executor.submit(retry_client.submit_payment, payment)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txINTERNAL_ERROR, [])
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )

        submit_reqs = []
        for i in range(_config_with_retry.max_retries + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_response(grpc_channel, resp))

        with pytest.raises(TransactionError):
            future.result()

        assert account_req.account_id.value == sender.address().decode()

        for submit_req in submit_reqs:
            self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), payment)
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_payment_with_nonce_retry(self, grpc_channel, executor, nonce_retry_client):
        sender = kin_base.Keypair.random()
        dest = kin_base.Keypair.random()
        payment = Payment(sender.raw_seed(), dest.raw_public_key(), TransactionType.EARN, 100000)

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
            assert account_req.account_id.value == sender.address().decode()

        for submit_req in submit_reqs:
            self._assert_payment_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), payment)
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_multiple(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        all_earns = [Earn(kin_base.Keypair.random().raw_public_key(), i) for i in range(250)]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), all_earns)

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
        assert len(batch_earn_result.tx_results) == 3

        earn_batches = partition(all_earns, 100)
        for idx, earn_batch in enumerate(earn_batches):
            tx_result = batch_earn_result.tx_results[idx]
            assert tx_result.tx_hash == tx_hashes[idx]
            assert len(tx_result.earn_results) == len(earn_batch)

            earn_results = tx_result.earn_results
            assert all(earn_result.earn == earn_batch[idx] for idx, earn_result in enumerate(earn_results))
            assert all(not earn_result.error for earn_result in earn_results)

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.address().decode()

        for idx, submit_req in enumerate(submit_reqs):
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, starting_seq + idx + 1,
                                             memo.NoneMemo(), sender, earn_batches[idx])
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_source(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        source = kin_base.Keypair.random()
        earns = [Earn(kin_base.Keypair.random().raw_public_key(), 100000)]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns, source=source.raw_seed())

        account_req = self._set_successful_get_account_info_response(grpc_channel, source, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash == b'somehash'
        assert len(tx_result.earn_results) == 1

        earn_result = tx_result.earn_results[0]
        assert earn_result.earn == earns[0]
        assert not earn_result.error

        assert account_req.account_id.value == source.address().decode()

        expected_signers = [sender, source]
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, expected_signers, source, 100, 11, memo.NoneMemo(),
                                         sender, earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_whitelisting(self, grpc_channel, executor, whitelisting_client):
        sender = kin_base.Keypair.random()
        earns = [Earn(kin_base.Keypair.random().raw_public_key(), 100000)]

        future = executor.submit(whitelisting_client.submit_earn_batch, sender.raw_seed(), earns)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash == b'somehash'
        assert len(tx_result.earn_results) == 1

        earn_result = tx_result.earn_results[0]
        assert earn_result.earn == earns[0]
        assert not earn_result.error

        assert account_req.account_id.value == sender.address().decode()

        expected_signers = [sender, whitelisting_client.whitelist_kp]
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, expected_signers, sender, 0, 11, memo.NoneMemo(),
                                         sender, earns)

    def test_submit_payment_with_invoices(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [
            Earn(kin_base.Keypair.random().raw_public_key(), 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(kin_base.Keypair.random().raw_public_key(), 100000,
                 invoice=Invoice([LineItem('title2', 100000, 'description2', b'somesku')])),
        ]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash == b'somehash'
        assert len(tx_result.earn_results) == 2

        for idx, earn in enumerate(earns):
            earn_result = tx_result.earn_results[idx]
            assert earn_result.earn == earns[idx]
            assert not earn_result.error

        assert account_req.account_id.value == sender.address().decode()

        il = InvoiceList([earn.invoice for earn in earns])
        expected_memo = memo.HashMemo(AgoraMemo.new(1, TransactionType.EARN, 0, il.get_sha_224_hash()).val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 2
        assert submit_req.invoice_list.SerializeToString() == il.to_proto().SerializeToString()

    def test_submit_earn_batch_with_memo(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [Earn(kin_base.Keypair.random().raw_public_key(), 100000)]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns, memo="somememo")

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txSUCCESS, [gen_payment_op_result(xdr_const.PAYMENT_SUCCESS)])
        submit_req = self._set_successful_submit_transaction_response(grpc_channel, b'somehash', result_xdr)

        batch_earn_result = future.result()
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash == b'somehash'
        assert len(tx_result.earn_results) == 1

        earn_result = tx_result.earn_results[0]
        assert earn_result.earn == earns[0]
        assert not earn_result.error

        assert account_req.account_id.value == sender.address().decode()

        expected_memo = memo.TextMemo('somememo')
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo,
                                         sender, earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_some_invoices(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [
            Earn(kin_base.Keypair.random().raw_public_key(), 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(kin_base.Keypair.random().raw_public_key(), 100000),
        ]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns)

        self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        with pytest.raises(ValueError):
            future.result()

    def test_submit_earn_batch_with_invoices_and_memo(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [
            Earn(kin_base.Keypair.random().raw_public_key(), 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
        ]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns, memo="somememo")

        self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        with pytest.raises(ValueError):
            future.result()

    def test_submit_earn_batch_rejected(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [
            Earn(kin_base.Keypair.random().raw_public_key(), 100000),
            Earn(kin_base.Keypair.random().raw_public_key(), 100000),
        ]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.REJECTED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
        )
        submit_req = self._set_submit_transaction_response(grpc_channel, resp)

        batch_earn_result = future.result()
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash  # make sure it's set
        assert len(tx_result.earn_results) == 2

        assert tx_result.earn_results[0].earn == earns[0]
        assert isinstance(tx_result.earn_results[0].error, TransactionRejectedError)
        assert tx_result.earn_results[1].earn == earns[1]
        assert isinstance(tx_result.earn_results[1].error, TransactionRejectedError)

        assert account_req.account_id.value == sender.address().decode()

        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_invoice_error(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [
            Earn(kin_base.Keypair.random().raw_public_key(), 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
            Earn(kin_base.Keypair.random().raw_public_key(), 100000,
                 invoice=Invoice([LineItem('title1', 100000, 'description1', b'somesku')])),
        ]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns)

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
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash  # make sure it's set
        assert len(tx_result.earn_results) == 2

        expected_reasons = [InvoiceErrorReason.ALREADY_PAID, InvoiceErrorReason.WRONG_DESTINATION]
        for idx, earn_result in enumerate(tx_result.earn_results):
            assert earn_result.earn == earns[idx]
            assert isinstance(earn_result.error, OperationInvoiceError)
            assert earn_result.error.reason == expected_reasons[idx]

        assert account_req.account_id.value == sender.address().decode()

        expected_memo = memo.HashMemo(
            AgoraMemo.new(1, TransactionType.EARN, 0,
                          InvoiceList([earn.invoice for earn in earns]).get_sha_224_hash()).val)
        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, expected_memo, sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 2
        assert (submit_req.invoice_list.invoices[0].SerializeToString() ==
                earns[0].invoice.to_proto().SerializeToString())
        assert (submit_req.invoice_list.invoices[1].SerializeToString() ==
                earns[1].invoice.to_proto().SerializeToString())

    def test_submit_earn_batch_tx_failed(self, grpc_channel, executor, no_retry_client):
        sender = kin_base.Keypair.random()
        earns = [
            Earn(kin_base.Keypair.random().raw_public_key(), 100000),
            Earn(kin_base.Keypair.random().raw_public_key(), 100000),
        ]

        future = executor.submit(no_retry_client.submit_earn_batch, sender.raw_seed(), earns)

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
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash  # make sure it's set
        assert len(tx_result.earn_results) == 2

        assert tx_result.earn_results[0].earn == earns[0]
        assert isinstance(tx_result.earn_results[0].error, InsufficientBalanceError)
        assert tx_result.earn_results[1].earn == earns[1]
        assert isinstance(tx_result.earn_results[1].error, DestinationDoesNotExistError)

        assert account_req.account_id.value == sender.address().decode()

        self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(), sender,
                                         earns)
        assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_retry(self, grpc_channel, executor, retry_client):
        sender = kin_base.Keypair.random()
        earns = [Earn(kin_base.Keypair.random().raw_public_key(), 100000)]

        future = executor.submit(retry_client.submit_earn_batch, sender.raw_seed(), earns)

        account_req = self._set_successful_get_account_info_response(grpc_channel, sender, 10)

        result_xdr = gen_result_xdr(xdr_const.txINTERNAL_ERROR, [])

        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.FAILED,
            hash=model_pb2.TransactionHash(value=b'somehash'),
            ledger=10,
            result_xdr=result_xdr,
        )

        submit_reqs = []
        for i in range(_config_with_retry.max_retries + 1):
            # this blocks until the system under test invokes the RPC, so if the test completes then the RPC was called
            # the expected number of times.
            submit_reqs.append(self._set_submit_transaction_response(grpc_channel, resp))

        batch_earn_result = future.result()
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash  # make sure it's set
        assert len(tx_result.earn_results) == 1

        assert tx_result.earn_results[0].earn == earns[0]
        assert isinstance(tx_result.earn_results[0].error, TransactionError)

        assert account_req.account_id.value == sender.address().decode()

        for submit_req in submit_reqs:
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(),
                                             sender,
                                             earns)
            assert len(submit_req.invoice_list.invoices) == 0

    def test_submit_earn_batch_with_nonce_retry(self, grpc_channel, executor, nonce_retry_client):
        sender = kin_base.Keypair.random()
        earns = [Earn(kin_base.Keypair.random().raw_public_key(), 100000)]

        future = executor.submit(nonce_retry_client.submit_earn_batch, sender.raw_seed(), earns)

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
        assert len(batch_earn_result.tx_results) == 1

        tx_result = batch_earn_result.tx_results[0]
        assert tx_result.tx_hash  # make sure it's set
        assert len(tx_result.earn_results) == 1

        assert tx_result.earn_results[0].earn == earns[0]
        assert isinstance(tx_result.earn_results[0].error, BadNonceError)

        for account_req in account_reqs:
            assert account_req.account_id.value == sender.address().decode()

        for submit_req in submit_reqs:
            self._assert_earn_batch_envelope(submit_req.envelope_xdr, [sender], sender, 100, 11, memo.NoneMemo(),
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
        channel: grpc_testing.Channel, kp: kin_base.Keypair, sequence: int, balance: int = kin_to_quarks(1000)
    ) -> account_pb.GetAccountInfoRequest:
        resp = account_pb.GetAccountInfoResponse(
            result=account_pb.GetAccountInfoResponse.Result.OK,
            account_info=account_pb.AccountInfo(
                account_id=model_pb2.StellarAccountId(
                    value=kp.address().decode()
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
    def _set_successful_submit_transaction_response(channel: grpc_testing.Channel, tx_hash: bytes, result_xdr: str):
        resp = tx_pb.SubmitTransactionResponse(
            result=tx_pb.SubmitTransactionResponse.Result.OK,
            hash=model_pb2.TransactionHash(value=tx_hash),
            ledger=10,
            result_xdr=result_xdr,
        )
        return TestAgoraClient._set_submit_transaction_response(channel, resp)

    @staticmethod
    def _assert_payment_envelope(
        envelope_xdr: bytes, signers: List[kin_base.Keypair], tx_source: kin_base.Keypair, base_fee: int, sequence: int,
        tx_memo: memo.Memo, payment: Payment
    ):
        envelope = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))
        operations = envelope.tx.operations

        TestAgoraClient._assert_envelope_properties(envelope, signers, tx_source, base_fee, sequence,
                                                    tx_memo)

        for idx, op in enumerate(operations):
            assert isinstance(op, operation.Payment)
            assert op.source == kin_base.Keypair.from_raw_seed(payment.sender).address().decode()
            assert op.destination == kin_base.Keypair(ed25519.VerifyingKey(payment.destination)).address().decode()
            assert float(op.amount) == quarks_to_kin(payment.quarks)

    @staticmethod
    def _assert_earn_batch_envelope(
        envelope_xdr: bytes, signers: List[kin_base.Keypair], tx_source: kin_base.Keypair,
        base_fee: int, sequence: int, tx_memo: memo.Memo, sender: kin_base.Keypair, earns: List[Earn]
    ):
        envelope = te.TransactionEnvelope.from_xdr(base64.b64encode(envelope_xdr))
        operations = envelope.tx.operations

        TestAgoraClient._assert_envelope_properties(envelope, signers, tx_source, base_fee * len(operations), sequence,
                                                    tx_memo)

        assert len(operations) == len(earns)
        for idx, op in enumerate(operations):
            earn = earns[idx]
            assert isinstance(op, operation.Payment)
            assert op.source == sender.address().decode()
            assert op.destination == kin_base.Keypair(ed25519.VerifyingKey(earn.destination)).address().decode()
            assert float(op.amount) == quarks_to_kin(earn.quarks)

    @staticmethod
    def _assert_envelope_properties(
        envelope: te.TransactionEnvelope, signers: List[kin_base.Keypair], tx_source: kin_base.Keypair,
        fee: int, sequence: int, tx_memo: memo.Memo
    ):
        assert len(envelope.signatures) == len(signers)
        for idx, signer in enumerate(signers):
            signer.verify(envelope.hash_meta(), envelope.signatures[idx].signature)

        tx = envelope.tx
        assert tx.source == tx_source.address()
        assert tx.fee == fee
        assert tx.sequence == sequence
        assert tx.memo == tx_memo
