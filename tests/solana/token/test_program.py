from agora.keys import PrivateKey
from agora.solana.token import Command, initialize_account, decompile_initialize_account, transfer, decompile_transfer
from agora.solana.token.program import set_authority, AuthorityType, decompile_set_authority
from agora.solana.transaction import Transaction
from tests.utils import generate_keys

_token_program = PrivateKey.random().public_key


class TestTokenProgram:
    def test_initialize_account(self):
        public_keys = [key.public_key for key in generate_keys(3)]
        instruction = initialize_account(public_keys[0], public_keys[1], public_keys[2], _token_program)

        assert instruction.data == bytes([Command.INITIALIZE_ACCOUNT])
        assert instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        for i in range(1, 4):
            assert not instruction.accounts[i].is_signer
            assert not instruction.accounts[i].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_initialize_account(tx.message, 0, _token_program)
        assert decompiled.account == public_keys[0]
        assert decompiled.mint == public_keys[1]
        assert decompiled.owner == public_keys[2]

    def test_transfer(self):
        public_keys = [key.public_key for key in generate_keys(3)]
        instruction = transfer(public_keys[0], public_keys[1], public_keys[2], 123456789, _token_program)

        assert instruction.data[0] == Command.TRANSFER
        assert instruction.data[1:] == (123456789).to_bytes(8, 'little')

        assert not instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        assert not instruction.accounts[1].is_signer
        assert instruction.accounts[1].is_writable
        assert instruction.accounts[2].is_signer
        assert instruction.accounts[2].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_transfer(tx.message, 0, _token_program)
        assert decompiled.source == public_keys[0]
        assert decompiled.dest == public_keys[1]
        assert decompiled.owner == public_keys[2]
        assert decompiled.amount == 123456789

    def test_set_authority(self):
        public_keys = [key.public_key for key in generate_keys(3)]

        # With no new authority
        instruction = set_authority(public_keys[0], public_keys[1], AuthorityType.AccountHolder, _token_program)

        assert instruction.data[0] == Command.SET_AUTHORITY
        assert instruction.data[1] == AuthorityType.AccountHolder
        assert instruction.data[2] == 0

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_set_authority(tx.message, 0, _token_program)
        assert decompiled.account == public_keys[0]
        assert decompiled.current_authority == public_keys[1]
        assert decompiled.authority_type == AuthorityType.AccountHolder
        assert not decompiled.new_authority

        # With new authority
        instruction = set_authority(public_keys[0], public_keys[1], AuthorityType.CloseAccount, _token_program,
                                    new_authority=public_keys[2])

        assert instruction.data[0] == Command.SET_AUTHORITY
        assert instruction.data[1] == AuthorityType.CloseAccount
        assert instruction.data[2] == 1
        assert instruction.data[3:] == public_keys[2].raw

        assert not instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        assert instruction.accounts[1].is_signer
        assert not instruction.accounts[1].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_set_authority(tx.message, 0, _token_program)
        assert decompiled.account == public_keys[0]
        assert decompiled.current_authority == public_keys[1]
        assert decompiled.authority_type == AuthorityType.CloseAccount
        assert decompiled.new_authority == public_keys[2]
