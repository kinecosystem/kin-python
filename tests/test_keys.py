import pytest

from agora.keys import PublicKey, PrivateKey


class TestKeys:
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

    def test_base58_roundtrip(self):
        priv = PrivateKey.random()
        assert PrivateKey.from_base58(priv.to_base58()) == priv
        assert priv.public_key.from_base58(priv.public_key.to_base58()) == priv.public_key
