import os

import base58
from kin_base import utils as kin_utils
from nacl import signing

ED25519_PUB_KEY_SIZE = 32
ED25519_PRIV_KEY_SIZE = 64


class PublicKey:
    """PublicKey is a blockchain-agnostic representation of an ed25519 public key.

    :param public_key: The public key, in raw bytes.
    """

    def __init__(self, public_key: bytes):
        self._verify_key = signing.VerifyKey(public_key)

    def __eq__(self, other):
        if not isinstance(other, PublicKey):
            return False

        return self._verify_key == other._verify_key

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'public_key={bytes(self._verify_key)})'

    @classmethod
    def from_base58(cls, address: str) -> 'PublicKey':
        """Decodes the provided base58-encoded public address and returns a PublicKey object.

        :param address: the base58 encoded public address
        :return: a PublicKey object.
        """
        return cls(base58.b58decode(address))

    @classmethod
    def from_string(cls, address: str) -> 'PublicKey':
        """Parses the provided Stellar-encoded address and returns a PublicKey.

        :param address: A Stellar-encoded address
        :return: A PublicKey object.
        """
        if len(address) != 56:
            raise ValueError("address format not supported")

        if address[0] != "G":
            raise ValueError("provided address is not a public key")

        return cls(kin_utils.is_valid_address(address))

    @property
    def stellar_address(self) -> str:
        """Returns the Stellar-encoded address, as a string.

        :return: The Stellar-encoded string representation of the public key.
        """
        return kin_utils.encode_check('account', bytes(self._verify_key)).decode()

    @property
    def raw(self) -> bytes:
        """Returns the raw bytes of the public key.

        :return: bytes
        """
        return bytes(self._verify_key)

    def to_base58(self) -> str:
        """Returns the base58-encoded form of this public key.

        :return: the string base58-encoded public key
        """
        return base58.b58encode(self.raw).decode('utf-8')

    def verify(self, data: bytes, signature: bytes):
        """Verify the provided data and signature match this keypair's public key.
        :param data: The data that was signed.
        :param signature: The signature.
        """
        return self._verify_key.verify(data, signature)


class PrivateKey:
    """PrivateKey is a blockchain-agnostic representation of an ed25519 private key.

    :param private_key: The private key, in raw bytes.
    """

    def __init__(self, private_key: bytes):
        self._signing_key = signing.SigningKey(private_key)

    def __eq__(self, other):
        if not isinstance(other, PrivateKey):
            return False

        return self._signing_key == other._signing_key

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'private_key={bytes(self._signing_key)})'

    @classmethod
    def random(cls):
        """Returns a Private Key derived from a randomly generated seed.

        :return: A PrivateKey object.
        """
        return cls(os.urandom(32))

    @classmethod
    def from_base58(cls, seed: str) -> 'PrivateKey':
        """Decodes the provided base58-encoded seed and returns a PrivateKey object.

        :param seed: the base58-encoded seed
        :return: a PrivateKey object.
        """
        return cls(base58.b58decode(seed))

    @classmethod
    def from_string(cls, seed: str) -> 'PrivateKey':
        """Parses the provided Stellar-encoded seed and returns a Private Key.

        :param seed: A Stellar-encoded seed
        :return: A PrivateKey object.
        """
        if len(seed) != 56:
            raise ValueError("seed format not supported")

        if seed[0] != "S":
            raise ValueError("provided seed is not a private key")

        return cls(kin_utils.is_valid_secret_key(seed))

    @property
    def stellar_seed(self) -> str:
        """Returns the Stellar-encoded seed, as a string.

        :return: The Stellar-encoded string representation of the private key.
        """
        return kin_utils.encode_check('seed', bytes(self._signing_key)).decode()

    @property
    def raw(self) -> bytes:
        """Returns the raw bytes of the private key.

        :return: bytes
        """
        return bytes(self._signing_key)

    @property
    def public_key(self) -> PublicKey:
        """Returns a :class:`PublicKey <PublicKey>` object corresponding to this private key.

        :return: a :class:`PublicKey <PublicKey>`
        """
        return PublicKey(bytes(self._signing_key.verify_key))

    def to_base58(self) -> str:
        """Returns the base58-encoded form of the seed.

        :return: the string base58-encoded seed.
        """
        return base58.b58encode(self.raw).decode('utf-8')

    def sign(self, data: bytes) -> bytes:
        """Sign the provided data.

        :param data: The data to sign.
        :return: The signature.
        """
        return self._signing_key.sign(data).signature
