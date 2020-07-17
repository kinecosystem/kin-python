import pytest
from kin_base import memo

from agora.model.memo import AgoraMemo, MAGIC_BYTE
from agora.model.transaction_type import TransactionType


class TestMemo(object):
    def test_new_valid(self):
        empty_fk = bytes(29)

        # Test all potential versions
        for v in range(0, 8):
            m = AgoraMemo.new(v, TransactionType.EARN, 1, b'')

            assert m.val[0] & 0x3 == MAGIC_BYTE
            assert m.version() == v
            assert m.tx_type() == TransactionType.EARN
            assert m.app_index() == 1
            assert m.foreign_key() == empty_fk

        # # Test all transaction types
        for tx_type in TransactionType:
            m = AgoraMemo.new(1, TransactionType(tx_type), 1, b'')

            assert m.val[0] & 0x3 == MAGIC_BYTE
            assert m.version() == 1
            assert m.tx_type() == tx_type
            assert m.app_index() == 1
            assert m.foreign_key() == empty_fk

        # Test all app indexes
        for app_index in range(0, 2 ** 16 - 1):
            m = AgoraMemo.new(1, TransactionType.EARN, app_index, b'')

            assert m.val[0] & 0x3 == MAGIC_BYTE
            assert m.version() == 1
            assert m.tx_type() == TransactionType.EARN
            assert m.app_index() == app_index
            assert m.foreign_key() == empty_fk

            # Test potential foreign key byte values
        for i in range(0, 256):
            fk = bytearray(29)
            for j in range(0, 29):
                fk[j] = (i + j) & 0xFF

            m = AgoraMemo.new(1, TransactionType.EARN, 2, fk)
            assert m.version() == 1
            assert m.tx_type() == TransactionType.EARN
            assert m.app_index() == 2

            actual_fk = m.foreign_key()
            assert actual_fk[:28] == fk[:28]

            # Note, because we only have 230 bits, the last byte in the memo fk
            # only has the first 6 bits of the last byte in the original fk.
            assert actual_fk[28] == fk[28] & 0x3f

        # Test a short foreign key
        fk = bytes([0, 255])
        m = AgoraMemo.new(1, TransactionType.EARN, 2, fk)

        actual_fk = m.foreign_key()
        assert actual_fk[:2] == fk
        for i in range(2, 29):
            assert actual_fk[i] == 0

    def test_new_invalid(self):
        with pytest.raises(ValueError):
            AgoraMemo.new(8, TransactionType.EARN, 1, bytes(29))

        with pytest.raises(ValueError):
            AgoraMemo.new(1, TransactionType.EARN, 1, bytes(30))

    def test_is_valid(self):
        m = AgoraMemo.new(1, TransactionType.EARN, 1, bytes(29))
        assert m.is_valid()
        assert m.is_valid_strict()

        # Invalid magic byte
        m.val[0] = MAGIC_BYTE >> 1
        assert not m.is_valid()
        assert not m.is_valid_strict()

        # Invalid transaction type
        m = AgoraMemo.new(1, TransactionType.UNKNOWN, 1, bytes(29))
        assert not m.is_valid()
        assert not m.is_valid_strict()

        # Version higher than configured
        m = AgoraMemo.new(7, TransactionType.EARN, 1, bytes(29))
        assert m.is_valid()
        assert not m.is_valid_strict()

        # Transaction type higher than configured
        m = AgoraMemo.new(1, max(TransactionType) + 1, 1, bytes(29))
        assert m.is_valid()
        assert not m.is_valid_strict()

    def test_from_base_memo(self):
        valid_memo = AgoraMemo.new(2, TransactionType.EARN, 1, bytes(29))
        strictly_valid_memo = AgoraMemo.new(1, TransactionType.EARN, 1,
                                            bytes(29))

        with pytest.raises(ValueError):
            AgoraMemo.from_base_memo(memo.TextMemo("text"))

        actual = AgoraMemo.from_base_memo(memo.HashMemo(valid_memo.val), False)
        assert actual.val == valid_memo.val

        with pytest.raises(ValueError):
            AgoraMemo.from_base_memo(memo.HashMemo(valid_memo.val), True)

        actual = AgoraMemo.from_base_memo(
            memo.HashMemo(strictly_valid_memo.val), True)
        assert actual.val == strictly_valid_memo.val

    def test_from_xdr(self):
        valid_memo = AgoraMemo.new(2, TransactionType.EARN, 1, bytes(29))
        strictly_valid_memo = AgoraMemo.new(1, TransactionType.EARN, 1,
                                            bytes(29))

        with pytest.raises(ValueError):
            AgoraMemo.from_xdr(memo.TextMemo("text").to_xdr_object())

        actual = AgoraMemo.from_xdr(
            memo.HashMemo(valid_memo.val).to_xdr_object(), False)
        assert actual.val == valid_memo.val

        with pytest.raises(ValueError):
            AgoraMemo.from_base_memo(
                memo.HashMemo(valid_memo.val).to_xdr_object(), True)

        actual = AgoraMemo.from_xdr(
            memo.HashMemo(strictly_valid_memo.val).to_xdr_object(), True)
        assert actual.val == strictly_valid_memo.val
