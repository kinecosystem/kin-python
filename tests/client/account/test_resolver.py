from concurrent import futures

import grpc
import grpc_testing
import pytest
from agoraapi.account.v4 import account_service_pb2_grpc as account_pb_grpc, account_service_pb2 as account_pb
from agoraapi.common.v4 import model_pb2 as model_pb

from agora.client.account.resolver import TokenAccountResolver
from agora.keys import PrivateKey
from agora.retry import LimitStrategy
from tests.utils import generate_keys


@pytest.fixture(scope='class')
def grpc_channel():
    return grpc_testing.channel([
        account_pb.DESCRIPTOR.services_by_name['Account'],
    ], grpc_testing.strict_real_time)


@pytest.fixture(scope='class', autouse=True)
def executor():
    executor = futures.ThreadPoolExecutor(1)
    yield executor
    executor.shutdown(wait=False)


class TestTokenAccountResolver:
    def test_all(self, grpc_channel, executor):
        resolver = TokenAccountResolver(
            account_stub=account_pb_grpc.AccountStub(grpc_channel)
        )

        owner, token1, token2 = [key.public_key for key in generate_keys(3)]
        future = executor.submit(resolver.resolve_token_accounts, owner)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['ResolveTokenAccounts']
        )
        rpc.terminate(account_pb.ResolveTokenAccountsResponse(
            token_accounts=[model_pb.SolanaAccountId(value=key.raw) for key in [token1, token2]]
        ), (), grpc.StatusCode.OK, '')

        assert future.result() == [token1, token2]

        # ensure it's cached
        assert resolver.resolve_token_accounts(owner) == [token1, token2]

    def test_no_accounts(self, grpc_channel, executor):
        resolver = TokenAccountResolver(
            account_stub=account_pb_grpc.AccountStub(grpc_channel)
        )

        account = generate_keys(1)[0].public_key
        future = executor.submit(resolver.resolve_token_accounts, account)

        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['ResolveTokenAccounts']
        )
        rpc.terminate(account_pb.ResolveTokenAccountsResponse(), (), grpc.StatusCode.OK, '')

        assert future.result() == []

        # ensure not cached
        future = executor.submit(resolver.resolve_token_accounts, account)
        md, request, rpc = grpc_channel.take_unary_unary(
            account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['ResolveTokenAccounts']
        )
        rpc.terminate(account_pb.ResolveTokenAccountsResponse(), (), grpc.StatusCode.OK, '')

        assert future.result() == []

    def test_no_account_retry(self, grpc_channel, executor):
        resolver = TokenAccountResolver(
            account_stub=account_pb_grpc.AccountStub(grpc_channel),
            retry_strategies=[
                LimitStrategy(3)
            ]
        )

        owner = PrivateKey.random()
        future = executor.submit(resolver.resolve_token_accounts, owner)

        for _ in range(3):
            md, request, rpc = grpc_channel.take_unary_unary(
                account_pb.DESCRIPTOR.services_by_name['Account'].methods_by_name['ResolveTokenAccounts']
            )
            rpc.terminate(account_pb.ResolveTokenAccountsResponse(), (), grpc.StatusCode.OK, '')

        assert future.result() == []
