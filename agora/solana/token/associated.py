from typing import NamedTuple, Tuple

from agora.keys import PublicKey
from agora.solana import system
from agora.solana.address import find_program_address
from agora.solana.instruction import Instruction, AccountMeta
from agora.solana.transaction import Message
from .program import PROGRAM_KEY

ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_KEY = PublicKey.from_base58('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')


def get_associated_account(wallet: PublicKey, mint: PublicKey) -> PublicKey:
    return find_program_address(
        ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_KEY,
        [
            wallet.raw,
            PROGRAM_KEY.raw,
            mint.raw,
        ],
    )


def create_associated_token_account(
    subsidizer: PublicKey, wallet: PublicKey, mint: PublicKey,
) -> Tuple[Instruction, PublicKey]:
    addr = get_associated_account(wallet, mint)
    return Instruction(
        ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_KEY,
        bytes(),
        [
            AccountMeta.new(subsidizer, True),
            AccountMeta.new(addr, False),
            AccountMeta.new_read_only(wallet, False),
            AccountMeta.new_read_only(mint, False),
            AccountMeta.new_read_only(system.PROGRAM_KEY, False),
            AccountMeta.new_read_only(PROGRAM_KEY, False),
            AccountMeta.new_read_only(system.RENT_SYS_VAR, False),
        ],
    ), addr


class DecompiledCreateAssociatedAccount(NamedTuple):
    subsidizer: PublicKey
    address: PublicKey
    owner: PublicKey
    mint: PublicKey


def decompile_create_associated_account(m: Message, index: int) -> DecompiledCreateAssociatedAccount:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_KEY:
        raise ValueError('incorrect program')

    if len(i.data) != 0:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    if len(i.accounts) != 7:
        raise ValueError(f'invalid number of accounts: {len(i.accounts)}')

    if m.accounts[i.accounts[4]] != system.PROGRAM_KEY:
        raise ValueError(f'system program key mismatch')

    if m.accounts[i.accounts[5]] != PROGRAM_KEY:
        raise ValueError(f'token program key mismatch')

    if m.accounts[i.accounts[6]] != system.RENT_SYS_VAR:
        raise ValueError(f'rent sys var mismatch')

    return DecompiledCreateAssociatedAccount(
        m.accounts[i.accounts[0]],
        m.accounts[i.accounts[1]],
        m.accounts[i.accounts[2]],
        m.accounts[i.accounts[3]],
    )
