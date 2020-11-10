from typing import NamedTuple

from agora.keys import PublicKey
from agora.solana.instruction import Instruction
from agora.solana.transaction import Message

# The address of the memo program that should be used.
# todo: lock this in, or make configurable
PROGRAM_KEY = PublicKey.from_base58('Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo')


# Reference: https://github.com/solana-labs/solana-program-library/blob/master/memo/program/src/entrypoint.rs
def memo_instruction(data: str) -> Instruction:
    return Instruction(
        PROGRAM_KEY,
        bytes(data, 'utf-8'),
    )


class DecompiledMemo(NamedTuple):
    data: bytes


def decompile_memo(m: Message, index: int) -> DecompiledMemo:
    if index >= len(m.instructions):
        raise ValueError(f"instruction doesn't exist at {index}")

    i = m.instructions[index]

    if m.accounts[i.program_index] != PROGRAM_KEY:
        raise ValueError('incorrect program')

    return DecompiledMemo(i.data)
