from enum import IntEnum
from typing import NamedTuple

from agora.keys import PublicKey
from agora.solana.instruction import Instruction, AccountMeta
from agora.solana.transaction import Message

_PROGRAM_KEY = PublicKey(bytes(32))


class Command(IntEnum):
    CREATE_ACCOUNT = 0
    ASSIGN = 1
    TRANSFER = 2
    CREATE_ACCOUNT_WITH_SEED = 3
    ADVANCE_NONCE_ACCOUNT = 4
    WITHDRAW_NONCE_ACCOUNT = 5
    INITIALIZE_NONCE_ACCOUNT = 6
    AUTHORIZE_NONCE_ACCOUNT = 7
    ALLOCATE = 8
    ALLOCATE_WITH_SEED = 9
    ASSIGN_WITH_SEED = 10
    TRANSFER_WITH_SEED = 11


# Reference: https://github.com/solana-labs/solana/blob/f02a78d8fff2dd7297dc6ce6eb5a68a3002f5359/sdk/src/system_instruction.rs#L58-L72  #noqa: E501
def create_account(
    subsidizer: PublicKey, address: PublicKey, owner: PublicKey, lamports: int, size: int
) -> Instruction:
    """
    Account references
      0. [WRITE, SIGNER] Funding account
      1. [WRITE, SIGNER] New account

      CreateAccount {
        // Number of lamports to transfer to the new account
        lamports: u64,
        // Number of bytes of memory to allocate
        space: u64,

        // Address of program that will own the new account
        owner: Pubkey,
      }

    """
    data = bytearray()
    data.extend(Command.CREATE_ACCOUNT.to_bytes(4, 'little'))
    data.extend(lamports.to_bytes(8, 'little'))
    data.extend(size.to_bytes(8, 'little'))
    data.extend(owner.raw)

    return Instruction(
        _PROGRAM_KEY,
        data,
        [
            AccountMeta.new(subsidizer, True),
            AccountMeta.new(address, True),
        ],
    )


class DecompiledCreateAccount(NamedTuple):
    funder: PublicKey
    address: PublicKey
    owner: PublicKey
    lamports: int
    size: int


def decompile_create_account(m: Message, index: int) -> DecompiledCreateAccount:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]
    if m.accounts[i.program_index] != _PROGRAM_KEY:
        raise ValueError('incorrect program')

    if len(i.accounts) != 2:
        raise ValueError(f'invalid number of accounts: {len(i.accounts)}')

    if len(i.data) != 52:
        raise ValueError(f'invalid instruction data size: {len(i.data)}')

    if int.from_bytes(i.data[0:4], 'little') != Command.CREATE_ACCOUNT:
        raise ValueError(f'incorrect command')

    return DecompiledCreateAccount(
        m.accounts[i.accounts[0]],
        m.accounts[i.accounts[1]],
        PublicKey(i.data[4 + 2 * 8:]),
        int.from_bytes(i.data[4:12], 'little'),
        int.from_bytes(i.data[12:20], 'little'),
    )
