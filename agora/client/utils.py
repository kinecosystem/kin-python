import hashlib

from agora.keys import PrivateKey


def _generate_token_account(key: PrivateKey) -> PrivateKey:
    return PrivateKey(hashlib.sha256(key.raw).digest())
