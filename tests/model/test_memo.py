import base64

import pytest
from kin_base import memo

from agora.model.invoice import InvoiceList, Invoice, LineItem
from agora.model.memo import AgoraMemo, MAGIC_BYTE
from agora.model.transaction_type import TransactionType


class TestMemo:
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

        # Test all transaction types
        for tx_type in list(TransactionType)[1:]:
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
        # Invalid version
        with pytest.raises(ValueError):
            AgoraMemo.new(-1, TransactionType.EARN, 1, bytes(29))

        with pytest.raises(ValueError):
            AgoraMemo.new(8, TransactionType.EARN, 1, bytes(29))

        # Invalid tx type
        with pytest.raises(ValueError):
            AgoraMemo.new(1, TransactionType.UNKNOWN, 1, bytes(29))

        with pytest.raises(ValueError):
            AgoraMemo.new(1, 2 ** 5, 1, bytes(29))

        # Invalid app index
        with pytest.raises(ValueError):
            AgoraMemo.new(1, TransactionType.NONE, -1, bytes(29))

        with pytest.raises(ValueError):
            AgoraMemo.new(1, TransactionType.NONE, 2 ** 16, bytes(29))

        # Invalid foreign key
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

        # Version higher than configured
        m = AgoraMemo.new(7, TransactionType.EARN, 1, bytes(29))
        assert m.is_valid()
        assert not m.is_valid_strict()

        # Transaction type higher than configured
        m = AgoraMemo.new(1, max(TransactionType) + 1, 1, bytes(29))
        assert m.is_valid()
        assert not m.is_valid_strict()

    def test_transaction_type_raw(self):
        for i in range(32):
            # pass int instead of TransactionType to test the values of types that don't exist yet
            m = AgoraMemo.new(0, i, 0, bytes(29))
            assert m.tx_type_raw() == i

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

    def test_cross_language(self):
        """Test parsing memos generated using the Go memo implementation.
        """
        # memo with an empty FK
        b64_encoded_memo = 'PVwrAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        hash_memo = memo.HashMemo(base64.b64decode(b64_encoded_memo))
        m = AgoraMemo.from_base_memo(hash_memo, False)
        assert m.version() == 7
        assert m.tx_type() == TransactionType.EARN
        assert m.app_index() == 51927
        assert m.foreign_key() == bytes(29)

        # memo with unknown tx type
        b64_encoded_memo = 'RQUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        hash_memo = memo.HashMemo(base64.b64decode(b64_encoded_memo))
        m = AgoraMemo.from_base_memo(hash_memo, False)
        assert m.version() == 1
        assert m.tx_type() == TransactionType.UNKNOWN
        assert m.tx_type_raw() == 10
        assert m.app_index() == 1
        assert m.foreign_key() == bytes(29)

        # memo with an invoice list hash
        b64_encoded_memo = 'ZQQAiLyJQCfEDmO0QOygz/PZOLDcbwP1FmbdtZ9E+wM='
        hash_memo = memo.HashMemo(base64.b64decode(b64_encoded_memo))

        expected_il = InvoiceList([Invoice([
            LineItem("Important Payment", 100000, description="A very important payment", sku=b'some sku')])])
        expected_fk = expected_il.get_sha_224_hash()

        m = AgoraMemo.from_base_memo(hash_memo, True)

        assert m.version() == 1
        assert m.tx_type() == TransactionType.P2P
        assert m.app_index() == 1

        # invoice hashes are only 28 bytes, so we ignore the 29th byte in the foreign key
        assert m.foreign_key()[:28] == expected_fk
