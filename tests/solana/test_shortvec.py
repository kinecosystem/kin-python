import pytest

from agora.solana.shortvec import encode_length, decode_length


class TestShortVec:
    def test_shortvec_valid(self):
        for i in range(2 ** 16):
            b = bytearray()
            encode_length(b, i)

            actual, _ = decode_length(b)
            assert actual == i

    @pytest.mark.parametrize('val, encoded', [
        (0x0, bytes([0x0])),
        (0x7f, bytes([0x7f])),
        (0x80, bytes([0x80, 0x01])),
        (0xff, bytes([0xff, 0x01])),
        (0x100, bytes([0x80, 0x02])),
        (0x7fff, bytes([0xff, 0xff, 0x01])),
        (0xffff, bytes([0xff, 0xff, 0x03])),
    ])
    def test_shortvec_cross_impl(self, val, encoded):
        b = bytearray()
        n = encode_length(b, val)
        assert len(encoded) == n
        assert encoded == b

    def test_shortvec_invalid(self):
        with pytest.raises(ValueError):
            encode_length(bytearray(), 2 ** 16)
