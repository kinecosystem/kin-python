from typing import List, Optional

import base58

from agora.keys import PublicKey, ED25519_PUB_KEY_SIZE, PrivateKey
from agora.solana import shortvec
from agora.solana.instruction import CompiledInstruction, Instruction, AccountMeta

SIGNATURE_LENGTH = 64
HASH_LENGTH = 32
MAX_TX_SIZE = 1232


class Header:
    def __init__(self, num_signatures: int, num_read_only_signed: int, num_read_only: int):
        for val in [num_signatures, num_read_only_signed, num_read_only]:
            if val < 0 or val >= 256:
                raise ValueError('`num_signatures`, `num_read_only_signed`, and `num_read_only` must each be an int '
                                 'in the range [0, 256)')

        self.num_signatures = num_signatures
        self.num_read_only_signed = num_read_only_signed
        self.num_read_only = num_read_only

    def __eq__(self, other):
        if not isinstance(other, Header):
            return False

        return (self.num_signatures == other.num_signatures and
                self.num_read_only_signed == other.num_read_only_signed and
                self.num_read_only == other.num_read_only)


class Message:
    def __init__(self, header: Header, accounts: List[PublicKey], recent_blockhash: bytes,
                 instructions: List[CompiledInstruction]):
        self.header = header
        self.accounts = accounts
        self.recent_blockhash = recent_blockhash
        self.instructions = instructions

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False

        return (self.header == other.header and
                all(account == other.accounts[idx] for idx, account in enumerate(self.accounts)) and
                self.recent_blockhash == other.recent_blockhash and
                self.instructions == other.instructions)

    @classmethod
    def unmarshal(cls, b: bytes) -> 'Message':
        # Header
        num_signatures = b[0]
        num_read_only_signed = b[1]
        num_read_only = b[2]
        b = b[3:]

        # Accounts
        accounts_length, offset = shortvec.decode_length(b)
        accounts = []
        for _ in range(accounts_length):
            accounts.append(PublicKey(b[offset: offset + ED25519_PUB_KEY_SIZE]))
            offset += ED25519_PUB_KEY_SIZE
        b = b[offset:]

        # Recent Blockhash
        recent_blockhash = b[:HASH_LENGTH]
        b = b[HASH_LENGTH:]

        # Instructions
        instructions_length, offset = shortvec.decode_length(b)
        b = b[offset:]
        instructions = []
        for i in range(instructions_length):
            program_index = b[0]
            if program_index >= accounts_length:
                raise ValueError(f'program index out of range: {i}:{program_index}')
            b = b[1:]

            # Account Indices
            account_length, offset = shortvec.decode_length(b)
            b = b[offset:]
            instruction_accounts = b[:account_length]
            for account_index in instruction_accounts:
                if account_index >= accounts_length:
                    raise ValueError(f'instruction account out of range: {account_index}')
            b = b[account_length:]

            # Data
            data_length, offset = shortvec.decode_length(b)
            b = b[offset:]
            data = b[:data_length]
            b = b[data_length:]

            instructions.append(CompiledInstruction(program_index, instruction_accounts, data))

        return cls(Header(num_signatures, num_read_only_signed, num_read_only), accounts, recent_blockhash,
                   instructions)

    def marshal(self) -> bytes:
        b = bytearray()

        # Header
        b.append(self.header.num_signatures)
        b.append(self.header.num_read_only_signed)
        b.append(self.header.num_read_only)

        # Accounts
        shortvec.encode_length(b, len(self.accounts))
        for a in self.accounts:
            b.extend(a.raw)

        # Recent Blockhash
        b.extend(self.recent_blockhash)

        # Instructions
        shortvec.encode_length(b, len(self.instructions))
        for i in self.instructions:
            b.append(i.program_index)

            # Accounts
            shortvec.encode_length(b, len(i.accounts))
            b.extend(i.accounts)

            # Data
            shortvec.encode_length(b, len(i.data))
            b.extend(i.data)

        return bytes(b)


class Transaction:
    def __init__(self, signatures: List[bytes], message: Message):
        self.signatures = signatures
        self.message = message

    def __eq__(self, other):
        if not isinstance(other, Transaction):
            return False

        return (self.signatures == other.signatures and
                self.message == other.message)

    def __str__(self):
        signatures = ''.join([f'  {base58.b58encode(s)}\n' for s in self.signatures])
        account_ids = ''.join([f'    {a.to_base58()}\n' for a in self.message.accounts])
        instructions = ''.join([
            f'    {i}:\n'
            f'      ProgramIndex: {instruction.program_index}\n'
            f'      Accounts: {instruction.accounts}'
            f'      Data: {instruction.data}' for i, instruction in enumerate(self.message.instructions)
        ])

        return f'Signatures:\n{signatures}' \
               f'Message:\n' \
               f'  Header:\n' \
               f'    NumSignatures: {self.message.header.num_signatures}\n' \
               f'    NumReadOnly: {self.message.header.num_read_only}\n' \
               f'    NumReadOnlySigned: {self.message.header.num_read_only_signed}\n' \
               f'  Accounts:\n{account_ids}' \
               f'  Instructions:\n{instructions}'

    @classmethod
    def new(cls, payer: PublicKey, instructions: List[Instruction]):
        accounts = [AccountMeta(payer, is_signer=True, is_writable=True, is_payer=True)]

        # Extract all unique accounts from the instructions
        for i in instructions:
            accounts.append(AccountMeta(i.program, is_program=True))
            accounts += i.accounts

        # Sort the AccountMeta objects based on:
        #   1. Payer is always the first account / signer.
        #   2. All signers are before non-signers.
        #   3. Writable accounts before read-only accounts
        #   4. Programs last
        accounts = sorted(_filter_unique(accounts))
        account_ids = [account.public_key for account in accounts]

        header = Header(0, 0, 0)
        for account in accounts:
            if account.is_writable and account.is_signer:
                header.num_signatures += 1

            if not account.is_writable:
                if account.is_signer:
                    header.num_read_only_signed += 1
                else:
                    header.num_read_only += 1

        compiled_instructions = []
        for i in instructions:
            account_indices = bytearray()
            for a in i.accounts:
                account_indices.append(_index_of(account_ids, a.public_key))

            compiled_instructions.append(CompiledInstruction(
                _index_of(account_ids, i.program),
                account_indices,
                i.data
            ))

        for i in range(0, len(account_ids)):
            if len(account_ids[i].raw) == 0:
                account_ids[i] = bytearray(ED25519_PUB_KEY_SIZE)

        return Transaction([bytes(SIGNATURE_LENGTH)] * (header.num_signatures + header.num_read_only_signed),
                           Message(header, account_ids, bytes(HASH_LENGTH), compiled_instructions))

    @classmethod
    def unmarshal(cls, b: bytes) -> 'Transaction':
        sig_length, offset = shortvec.decode_length(b)

        signatures = []
        for i in range(sig_length):
            signatures.append(b[offset:offset + SIGNATURE_LENGTH])
            offset += SIGNATURE_LENGTH

        return cls(signatures, Message.unmarshal(b[offset:]))

    def get_signature(self) -> Optional[bytes]:
        """Returns the first (payer) Transaction signature

        :return: The signature, if present, or None
        """
        if len(self.signatures) > 0 and self.signatures[0] != bytes(SIGNATURE_LENGTH):
            return self.signatures[0]
        return None

    def set_blockhash(self, blockhash: bytes):
        self.message.recent_blockhash = blockhash

    def sign(self, signers: List[PrivateKey]):
        if len(signers) > len(self.signatures):
            raise ValueError('too many signers')

        message_bytes = self.message.marshal()
        for s in signers:
            pub = s.public_key
            idx = _index_of(self.message.accounts, pub)
            if idx < 0:
                raise ValueError(f'signing account {base58.b58encode(pub.raw)} is not in the account list')
            if idx >= len(self.signatures):
                raise ValueError(f'signing account {base58.b58encode(pub.raw)} is not in the list of signers')

            self.signatures[idx] = s.sign(message_bytes)

    def marshal(self) -> bytes:
        b = bytearray()

        # Signatures
        shortvec.encode_length(b, len(self.signatures))

        for s in self.signatures:
            b.extend(s)

        # Message
        b.extend(self.message.marshal())

        return bytes(b)


def _filter_unique(accounts: List[AccountMeta]) -> List[AccountMeta]:
    filtered = []
    for i in range(0, len(accounts)):
        exists = False
        for j in range(0, len(filtered)):
            if accounts[i].public_key == filtered[j].public_key:
                # Promote existing account to writable/signer/payer if applicable
                if accounts[i].is_writable:
                    filtered[j].is_writable = True
                if accounts[i].is_signer:
                    filtered[j].is_signer = True
                if accounts[i].is_payer:
                    filtered[j].is_payer = True
                exists = True

        if not exists:
            filtered.append(accounts[i])

    return filtered


def _index_of(l: List[PublicKey], item: PublicKey) -> int:
    for idx, val in enumerate(l):
        if val.raw == item.raw:
            return idx

    return -1
