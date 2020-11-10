# todo: lock in token program key and remove token_program parameters
from enum import IntEnum
from typing import NamedTuple, Optional

from agora.keys import PublicKey, ED25519_PUB_KEY_SIZE
from agora.solana.instruction import Instruction, AccountMeta
from agora.solana.transaction import Message

# Reference: https://github.com/solana-labs/solana-program-library/blob/11b1e3eefdd4e523768d63f7c70a7aa391ea0d02/token/program/src/state.rs#L125  # noqa: E501
ACCOUNT_SIZE = 165

# RentSysVar points to the system variable "Rent"
#
# Source: https://github.com/solana-labs/solana/blob/f02a78d8fff2dd7297dc6ce6eb5a68a3002f5359/sdk/src/sysvar/rent.rs#L11
_RENT_SYS_VAR = PublicKey.from_base58('SysvarRent111111111111111111111111111111111')


class Command(IntEnum):
    INITIALIZE_MINT = 0
    INITIALIZE_ACCOUNT = 1
    INITIALIZE_MULTISIG = 2
    TRANSFER = 3
    APPROVE = 4
    REVOKE = 5
    SET_AUTHORITY = 6
    MINT_TO = 7
    BURN = 8
    CLOSE_ACCOUNT = 9
    FREEZE_ACCOUNT = 10
    THAW_ACCOUNT = 11
    TRANSFER_2 = 12
    APPROVE_2 = 13
    MINT_TO_2 = 14
    BURN_2 = 15


class AuthorityType(IntEnum):
    MintTokens = 0
    FreezeAccount = 1
    AccountHolder = 2
    CloseAccount = 3


# Reference: https://github.com/solana-labs/solana-program-library/blob/b011698251981b5a12088acba18fad1d41c3719a/token/program/src/instruction.rs#L41-L55
def initialize_account(account: PublicKey, mint: PublicKey, owner: PublicKey, token_program: PublicKey) -> Instruction:
    """
    // Accounts expected by this instruction:
    //
    //   0. `[writable]`  The account to initialize.
    //   1. `[]` The mint this account will be associated with.
    //   2. `[]` The new account's owner/multisignature.
    //   3. `[]` Rent sysvar

    :return:
    """

    return Instruction(
        token_program,
        bytes([Command.INITIALIZE_ACCOUNT]),
        [
            AccountMeta.new(account, True),
            AccountMeta.new_read_only(mint, False),
            AccountMeta.new_read_only(owner, False),
            AccountMeta.new_read_only(_RENT_SYS_VAR, False),
        ]
    )


def transfer(
    source: PublicKey, dest: PublicKey, owner: PublicKey, amount: int, token_program: PublicKey
) -> Instruction:
    """
    // Accounts expected by this instruction:
    //
    //   * Single owner/delegate
    //   0. `[writable]` The source account.
    //   1. `[writable]` The destination account.
    //   2. `[signer]` The source account's owner/delegate.
    //
    //   * Multisignature owner/delegate
    //   0. `[writable]` The source account.
    //   1. `[writable]` The destination account.
    //   2. `[]` The source account's multisignature owner/delegate.
    //   3. ..3+M `[signer]` M signer accounts.
    :return:
    """
    data = bytearray()
    data.append(Command.TRANSFER)
    data.extend(amount.to_bytes(8, 'little'))

    return Instruction(
        token_program,
        data,
        [
            AccountMeta.new(source, False),
            AccountMeta.new(dest, False),
            AccountMeta.new(owner, True),
        ]
    )


def set_authority(account: PublicKey, current_authority: PublicKey, authority_type: AuthorityType,
                  token_program: PublicKey, new_authority: Optional[PublicKey] = None) -> Instruction:
    data = bytearray([Command.SET_AUTHORITY, authority_type])
    if not new_authority:
        data.append(0)
    else:
        data.append(1)
        data.extend(new_authority.raw)

    return Instruction(
        token_program,
        data,
        [
            AccountMeta.new(account, False),
            AccountMeta.new_read_only(current_authority, True),
        ]
    )


class DecompiledInitializeAccount(NamedTuple):
    account: PublicKey
    mint: PublicKey
    owner: PublicKey


def decompile_initialize_account(m: Message, index: int, token_program: PublicKey) -> DecompiledInitializeAccount:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != token_program:
        raise ValueError('incorrect program')

    if len(i.accounts) != 4:
        raise ValueError(f'invalid number of accounts: {len(i.accounts)}')

    if len(i.data) != 1:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    if i.data[0] != Command.INITIALIZE_ACCOUNT:
        raise ValueError(f'invalid instruction data: {i.data}')

    return DecompiledInitializeAccount(
        m.accounts[i.accounts[0]],
        m.accounts[i.accounts[1]],
        m.accounts[i.accounts[2]],
    )


class DecompiledTransfer(NamedTuple):
    source: PublicKey
    dest: PublicKey
    owner: PublicKey
    amount: int


def decompile_transfer(m: Message, index: int, token_program: Optional[PublicKey] = None) -> DecompiledTransfer:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if token_program:
        if m.accounts[i.program_index] != token_program:
            raise ValueError('incorrect program')

    if len(i.accounts) != 3:
        raise ValueError(f'invalid number of accounts: {len(i.accounts)}')

    if len(i.data) != 9:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    if i.data[0] != Command.TRANSFER:
        raise ValueError(f'invalid instruction data: {i.data}')

    return DecompiledTransfer(
        m.accounts[i.accounts[0]],
        m.accounts[i.accounts[1]],
        m.accounts[i.accounts[2]],
        int.from_bytes(i.data[1:], 'little')
    )


class DecompileSetAuthority(NamedTuple):
    account: PublicKey
    current_authority: PublicKey
    authority_type: AuthorityType
    new_authority: Optional[PublicKey]


def decompile_set_authority(m: Message, index: int, token_program: PublicKey) -> DecompileSetAuthority:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != token_program:
        raise ValueError('incorrect program')

    if len(i.accounts) != 2:
        raise ValueError(f'invalid number of accounts: {len(i.accounts)}')

    if len(i.data) < 3:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    if i.data[0] != Command.SET_AUTHORITY:
        raise ValueError(f'invalid instruction data: {i.data}')

    if i.data[2] == 0 and len(i.data) != 3:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    if i.data[2] == 1 and len(i.data) != 3 + ED25519_PUB_KEY_SIZE:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    return DecompileSetAuthority(
        m.accounts[i.accounts[0]],
        m.accounts[i.accounts[1]],
        AuthorityType(i.data[1]),
        PublicKey(i.data[3:]) if i.data[2] == 1 else None,
    )
