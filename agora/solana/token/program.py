# todo: lock in token program key and remove token_program parameters
from enum import IntEnum
from typing import NamedTuple, Optional

from agora.keys import PublicKey, ED25519_PUB_KEY_SIZE
from agora.solana import system
from agora.solana.instruction import Instruction, AccountMeta
from agora.solana.transaction import Message

# Reference: https://github.com/solana-labs/solana-program-library/blob/11b1e3eefdd4e523768d63f7c70a7aa391ea0d02/token/program/src/state.rs#L125  # noqa: E501
ACCOUNT_SIZE = 165

PROGRAM_KEY = PublicKey.from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")


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
    MINT_TOKENS = 0
    FREEZE_ACCOUNT = 1
    ACCOUNT_HOLDER = 2
    CLOSE_ACCOUNT = 3


def get_command(m: Message, index: int) -> Command:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]
    if m.accounts[i.program_index] != PROGRAM_KEY:
        raise ValueError('incorrect program')

    if len(i.data) == 0:
        raise ValueError('token instruction missing data')

    return Command(i.data[0])


# Reference: https://github.com/solana-labs/solana-program-library/blob/b011698251981b5a12088acba18fad1d41c3719a/token/program/src/instruction.rs#L41-L55  # noqa: e501
def initialize_account(account: PublicKey, mint: PublicKey, owner: PublicKey) -> Instruction:
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
        PROGRAM_KEY,
        bytes([Command.INITIALIZE_ACCOUNT]),
        [
            AccountMeta.new(account, False),
            AccountMeta.new_read_only(mint, False),
            AccountMeta.new_read_only(owner, False),
            AccountMeta.new_read_only(system.RENT_SYS_VAR, False),
        ]
    )


def transfer(source: PublicKey, dest: PublicKey, owner: PublicKey, amount: int) -> Instruction:
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
        PROGRAM_KEY,
        data,
        [
            AccountMeta.new(source, False),
            AccountMeta.new(dest, False),
            AccountMeta.new(owner, True),
        ]
    )


def set_authority(
    account: PublicKey, current_authority: PublicKey, authority_type: AuthorityType,
    new_authority: Optional[PublicKey] = None
) -> Instruction:
    data = bytearray([Command.SET_AUTHORITY, authority_type])
    if not new_authority:
        data.append(0)
    else:
        data.append(1)
        data.extend(new_authority.raw)

    return Instruction(
        PROGRAM_KEY,
        data,
        [
            AccountMeta.new(account, False),
            AccountMeta.new_read_only(current_authority, True),
        ]
    )


def close_account(account: PublicKey, dest: PublicKey, owner: PublicKey) -> Instruction:
    return Instruction(
        PROGRAM_KEY,
        bytes([Command.CLOSE_ACCOUNT]),
        [
            AccountMeta.new(account, False),
            AccountMeta.new(dest, False),
            AccountMeta.new_read_only(owner, True),
        ]
    )


class DecompiledInitializeAccount(NamedTuple):
    account: PublicKey
    mint: PublicKey
    owner: PublicKey


def decompile_initialize_account(m: Message, index: int) -> DecompiledInitializeAccount:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != PROGRAM_KEY:
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


def decompile_transfer(m: Message, index: int) -> DecompiledTransfer:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != PROGRAM_KEY:
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


def decompile_set_authority(m: Message, index: int) -> DecompileSetAuthority:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != PROGRAM_KEY:
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


class DecompileCloseAccount(NamedTuple):
    account: PublicKey
    destination: PublicKey
    owner: PublicKey


def decompile_close_account(m: Message, index: int) -> DecompileCloseAccount:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != PROGRAM_KEY:
        raise ValueError('incorrect program')

    if len(i.data) != 1 or i.data[0] != Command.CLOSE_ACCOUNT:
        raise ValueError(f'invalid instruction data: {i.data}')

    # note: we do < 3 instead of != 3 in order to support multisig cases.
    if len(i.accounts) < 3:
        raise ValueError(f'invalid number of accounts: {len(i.accounts)}')

    return DecompileCloseAccount(
        m.accounts[i.accounts[0]],
        m.accounts[i.accounts[1]],
        m.accounts[i.accounts[2]],
    )
