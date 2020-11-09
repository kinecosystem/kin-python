import base64
from typing import Optional

from kin_base import memo, stellarxdr

from agora.model.transaction_type import TransactionType

MAGIC_BYTE = 0x1

# The highest Agora memo version supported by this implementation.
HIGHEST_VERSION = 1


class AgoraMemo:
    """Implements the Agora memo specification as defined in github.com/kinecosystem/agora-api.

    :param val: the raw memo bytearray.
    """

    def __init__(self, val: bytearray):
        if len(val) > 32:
            raise ValueError(f'invalid memo length {len(val)}')

        self.val = val

    def __eq__(self, other):
        if not isinstance(other, AgoraMemo):
            return False

        return self.val == other.val

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'val={self.val})'

    @classmethod
    def new(cls, version: int, tx_type: TransactionType, app_index: int, foreign_key: bytes) -> 'AgoraMemo':
        """Returns an Agora memo containing the provided properties.

        :param version: The memo encoding version
        :param tx_type: The :class:`TransactionType <agora.model.transaction_type.TransactionType>` of the transaction
        :param app_index: The index of the app the transaction relates to
        :param foreign_key: An identifier in an auxiliary service that contains additional data about what the
            transaction was for

        :return: an :class:`AgoraMemo <AgoraMemo>` object
        """
        if version < 0 or version > 7:
            raise ValueError('invalid version')

        if tx_type < 0 or tx_type > 2 ** 5 - 1:
            raise ValueError('invalid transaction type')

        if app_index < 0 or app_index > 2 ** 16 - 1:
            raise ValueError('invalid app index')

        if len(foreign_key) > 29:
            raise ValueError(f'invalid foreign key length {len(foreign_key)}')

        v = version & 0xFF
        t = tx_type & 0xFF

        val = bytearray(32)
        val[0] = MAGIC_BYTE
        val[0] |= v << 2
        val[0] |= (t & 0x7) << 5

        val[1] = (t & 0x18) >> 3
        val[1] |= (app_index & 0x3f) << 2

        val[2] = (app_index & 0x3fc0) >> 6

        val[3] = (app_index & 0xc000) >> 14

        if len(foreign_key) > 0:
            val[3] |= (foreign_key[0] & 0x3f) << 2

            # Insert the rest of the fk. Since each loop references fk[n] and
            # fk[n+1], the upper bound is offset by 3 instead of 4.
            for i in range(4, 3 + len(foreign_key)):
                # apply last 2-bits of current byte
                val[i] = (foreign_key[i - 4] >> 6) & 0x3
                # apply first 6-bits of next byte
                val[i] |= (foreign_key[i - 3] & 0x3f) << 2

            # if the foreign key is less than 29 bytes, the last 2 bits of the
            # FK can be included in the memo
            if len(foreign_key) < 29:
                val[len(foreign_key) + 3] = (foreign_key[len(foreign_key) - 1]
                                             >> 6) & 0x3

        return cls(val)

    @classmethod
    def from_base_memo(cls, m: memo.Memo, strict: Optional[bool] = False) -> 'AgoraMemo':
        """Instantiates and returns an :class:`AgoraMemo <AgoraMemo>` object from a :class:`Memo <kin_base.memo.Memo>`,
        provided it is a valid (or strictly valid) Agora memo.

        :param m: A :class:`Memo <kin_base.memo.Memo>`
        :param strict: (optional). Dictates whether to strictly check validity of the memo or not. Defaults to False.
        :return: An :class:`AgoraMemo <AgoraMemo>` object.
        """
        if not isinstance(m, memo.HashMemo):
            raise ValueError('memo must be a HashMemo')

        m = cls(m.memo_hash)
        if strict:
            if not m.is_valid_strict():
                raise ValueError('memo not a valid Agora Memo')

            return m

        if not m.is_valid():
            raise ValueError('memo not a valid Agora Memo')

        return m

    @classmethod
    def from_xdr(cls, xdr: stellarxdr.Xdr.types.Memo, strict: Optional[bool] = False) -> 'AgoraMemo':
        return cls.from_base_memo(memo.xdr_to_memo(xdr), strict=strict)

    @classmethod
    def from_b64_string(cls, s: str, strict: Optional[bool] = False) -> 'AgoraMemo':
        raw = base64.b64decode(s)
        m = cls(raw)
        if strict:
            if not m.is_valid_strict():
                raise ValueError('memo not a valid Agora Memo')

            return m

        if not m.is_valid():
            raise ValueError('memo not a valid Agora Memo')

        return m

    def is_valid(self) -> bool:
        """Returns whether or not the memo is valid.

        It should be noted that there are no guarantees if the memo is valid, only if the memo is invalid. That is, this
        function may return false positives.

        Stricter validation can be done via :meth:`AgoraMemo.is_valid_strict`. However,
        :meth:`AgoraMemo.is_valid_strict` is not as forward compatible.

        :return: A bool indicating whether the memo is valid
        """
        if self.val[0] & 0x3 != MAGIC_BYTE:
            return False

        return self.tx_type_raw() != TransactionType.UNKNOWN

    def is_valid_strict(self) -> bool:
        """Returns whether or not the memo is valid checking against this implementation's supported version.

        It should be noted that there are no guarantees if the memo is valid, only if the memo is invalid. That is,
        this function may return false positives.

        :return: A bool indicating whether the memo is strictly valid
        """
        if not self.is_valid():
            return False

        if self.version() > HIGHEST_VERSION:
            return False

        return self.tx_type() != TransactionType.UNKNOWN

    def version(self) -> int:
        """Returns the memo encoding version of this memo.

        :return: the int memo encoding version
        """
        return (self.val[0] & 0x1c) >> 2

    def tx_type(self) -> TransactionType:
        """Returns the :class:`TransactionType <agora.model.transaction_type.TransactionType>` of this memo.

        :return: :class:`TransactionType <agora.model.transaction_type.TransactionType>`
        """
        try:
            return TransactionType(self.tx_type_raw())
        except ValueError:
            return TransactionType.UNKNOWN

    def tx_type_raw(self) -> int:
        """Returns the transaction type of the memo, even if is unsupported by this implementation. It should only be
        used as a fallback if the raw value is needed when :meth:`agora.memo.AgoraMemo.transaction_type.py` yields
        TransactionType.UNKNOWN.

        :return: the int value of the memo transaction type
        """
        return (self.val[0] >> 5) | (self.val[1] & 0x3) << 3

    def app_index(self) -> int:
        """Returns the app index of the memo.

        :return: the int app index
        """
        a = self.val[1] >> 2
        b = self.val[2] << 6
        c = (self.val[3] & 0x3) << 14
        return a | b | c

    def foreign_key(self) -> bytes:
        """Returns the foreign key of the memo.

        :return: the foreign key
        """
        fk = bytearray(29)
        for i in range(0, 28):
            fk[i] |= self.val[i + 3] >> 2
            fk[i] |= (self.val[i + 4] & 0x3) << 6

        fk[28] = self.val[31] >> 2

        return bytes(fk)
