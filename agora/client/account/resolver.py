from typing import List

from agoraapi.account.v4 import account_service_pb2_grpc as account_pb_grpc, account_service_pb2 as account_pb
from agoraapi.common.v4 import model_pb2 as model_pb

from agora.cache.cache import LRUCache
from agora.error import NoTokenAccountsError
from agora.keys import PublicKey, ED25519_PUB_KEY_SIZE
from agora.retry import Strategy, retry


class TokenAccountResolver:
    """Resolves owner account IDs to their token accounts. Handles caching.

    :param account_stub: the Agora Account Service stub to use for requests.
    """

    def __init__(self, account_stub: account_pb_grpc.AccountStub, retry_strategies: List[Strategy] = None):
        self._account_stub = account_stub
        self._retry_strategies = retry_strategies if retry_strategies else []
        self._cache = LRUCache(300, 30000)

    def resolve_token_accounts(self, public_key: PublicKey) -> List[PublicKey]:
        """Resolve the provided public key to its token accounts.

        :param public_key: the :class:`PublicKey <agora.model.keys.PublicKey>` of the owner.
        :return: a list of :class:`PublicKey <agora.model.keys.PublicKey>` objects.
        """
        cached = self._get_from_cache(public_key)
        if cached:
            return cached

        def _call_resolve():
            response = self._account_stub.ResolveTokenAccounts(account_pb.ResolveTokenAccountsRequest(
                account_id=model_pb.SolanaAccountId(value=public_key.raw)
            ))
            if not response.token_accounts:
                raise NoTokenAccountsError()

            return response

        try:
            resp = retry(self._retry_strategies, _call_resolve)
            token_accounts = [PublicKey(account_id.value) for account_id in resp.token_accounts]
        except NoTokenAccountsError:
            token_accounts = []

        if token_accounts:
            self._set_in_cache(public_key, token_accounts)

        return token_accounts

    def _set_in_cache(self, public_key: PublicKey, token_accounts: List[PublicKey]):
        cache_key = self._get_cache_key(public_key)
        entry = self._create_cache_entry(token_accounts)
        self._cache.set(cache_key, entry)

    def _get_from_cache(self, public_key: PublicKey) -> List[PublicKey]:
        cache_key = self._get_cache_key(public_key)
        entry = self._cache.get(cache_key)
        return self._parse_cache_entry(entry) if entry else []

    def _get_cache_key(self, public_key: PublicKey):
        return public_key.raw

    def _create_cache_entry(self, accounts: List[PublicKey]) -> bytes:
        return b''.join([account.raw for account in accounts])

    def _parse_cache_entry(self, entry: bytes) -> List[PublicKey]:
        return [PublicKey(entry[i:i + ED25519_PUB_KEY_SIZE]) for i in range(0, len(entry), ED25519_PUB_KEY_SIZE)]
