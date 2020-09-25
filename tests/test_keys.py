import pytest
from kin_base import Keypair

from agora.keys import PublicKey, PrivateKey


class TestKeys:
    def test_kin_keypair_compat(self):
        kp = Keypair.random()

        pub = PublicKey(kp.raw_public_key())
        assert pub.stellar_address == kp.address().decode()
        assert pub.raw == kp.raw_public_key()

        priv = PrivateKey(kp.raw_seed())
        assert priv.stellar_seed == kp.seed().decode()
        assert priv.raw == kp.raw_seed()

    def test_random(self):
        priv = PrivateKey.random()
        kp = Keypair.from_seed(priv.stellar_seed)

        assert priv.public_key.stellar_address == kp.address().decode()
        assert priv.public_key.raw == kp.raw_public_key()
        assert priv.stellar_seed == kp.seed().decode()
        assert priv.raw == kp.raw_seed()

    def test_from_string(self):
        address = "GCABWU4FHL3RGOIWCX5TOVLIAMLEU2YXXLCMHVXLDOFHKLNLGCSBRJYP"
        seed = "SCZ4KGTCMAFIJQCCJDMMKDFUB7NYV56VBNEU7BKMR4PQFUETJCWLV6GN"

        pub = PublicKey.from_string(address)
        assert pub.stellar_address == address

        priv = PrivateKey.from_string(seed)
        assert priv.stellar_seed == seed

        # Test invalid cases
        with pytest.raises(ValueError):
            PublicKey.from_string('invalidlength')

        with pytest.raises(ValueError):
            PublicKey.from_string(seed)  # not an address

        with pytest.raises(ValueError):
            PrivateKey.from_string('invalidlength')

        with pytest.raises(ValueError):
            PrivateKey.from_string(address)  # not a seed
