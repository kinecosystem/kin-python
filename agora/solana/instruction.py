import functools
from typing import Optional, List

from agora.keys import PublicKey


@functools.total_ordering
class AccountMeta:
    """ Represents the account information required for building transactions.
    """

    def __init__(
        self, public_key: PublicKey, is_signer: Optional[bool] = False, is_writable: Optional[bool] = False,
        is_payer: Optional[bool] = False, is_program: Optional[bool] = False,
    ):
        self.public_key = public_key
        self.is_signer = is_signer
        self.is_writable = is_writable
        self.is_payer = is_payer
        self.is_program = is_program

    def __eq__(self, other):
        if not isinstance(other, AccountMeta):
            return False

        return (self.public_key == other.public_key and
                self.is_signer == other.is_signer and
                self.is_writable == other.is_writable and
                self.is_payer == other.is_payer and
                self.is_program and other.is_program)

    @classmethod
    def new(cls, pub: PublicKey, is_signer: bool) -> 'AccountMeta':
        """ Creates a new :class:`AccountMeta <AccountMeta>` representing a writable account.

        :param pub: the :class:`PublicKey <agora.model.keys.PublicKey>` of the account.
        :param is_signer: indicates whether this account is a signer.
        """
        return cls(pub, is_signer=is_signer, is_writable=True)

    @classmethod
    def new_read_only(cls, pub: PublicKey, is_signer: bool) -> 'AccountMeta':
        """ Creates a new `AccountMeta <AccountMeta` representing a read-only account.

        :param pub: the :class:`PublicKey <agora.model.keys.PublicKey>` of the account.
        :param is_signer: indicates whether this account is a signer.
        :return:
        """
        return cls(pub, is_signer=is_signer, is_writable=False)

    def __lt__(self, other):
        if not isinstance(other, AccountMeta):
            return NotImplemented

        if self.is_payer is not other.is_payer:
            return self.is_payer

        if self.is_program != other.is_program:
            return not self.is_program

        if self.is_signer != other.is_signer:
            return self.is_signer

        if self.is_writable != other.is_writable:
            return self.is_writable

        return False


class Instruction:
    """ Represents a transaction instruction.
    """

    def __init__(self, program: PublicKey, data: bytes, accounts: Optional[List[AccountMeta]] = None):
        self.program = program
        self.data = data
        self.accounts = accounts if accounts else []

    def __eq__(self, other):
        if not isinstance(other, Instruction):
            return False

        return (self.program == other.program and
                self.accounts == other.accounts and
                self.data == other.data)


class CompiledInstruction:
    """ Represents a compiled transaction instruction
    """

    def __init__(self, program_index: int, accounts: bytes, data: bytes):
        if program_index < 0 or program_index >= 256:
            raise ValueError('`program_index` must be an int in the range [0, 256)')

        self.program_index = program_index
        self.accounts = accounts
        self.data = data

    def __eq__(self, other):
        if not isinstance(other, CompiledInstruction):
            return False

        return (self.program_index == other.program_index and
                self.accounts == other.accounts and
                self.data == other.data)
