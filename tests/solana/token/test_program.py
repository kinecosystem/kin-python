from agora.solana.token.program import Command, initialize_account, decompile_initialize_account, transfer, \
    decompile_transfer, set_authority, AuthorityType, decompile_set_authority, close_account, decompile_close_account
from agora.solana.transaction import Transaction
from tests.utils import generate_keys


class TestTokenProgram:
    def test_initialize_account(self):
        public_keys = [key.public_key for key in generate_keys(3)]
        instruction = initialize_account(public_keys[0], public_keys[1], public_keys[2])

        assert instruction.data == bytes([Command.INITIALIZE_ACCOUNT])
        assert not instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        for i in range(1, 4):
            assert not instruction.accounts[i].is_signer
            assert not instruction.accounts[i].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_initialize_account(tx.message, 0)
        assert decompiled.account == public_keys[0]
        assert decompiled.mint == public_keys[1]
        assert decompiled.owner == public_keys[2]

    def test_transfer(self):
        public_keys = [key.public_key for key in generate_keys(3)]
        instruction = transfer(public_keys[0], public_keys[1], public_keys[2], 123456789)

        assert instruction.data[0] == Command.TRANSFER
        assert instruction.data[1:] == (123456789).to_bytes(8, 'little')

        assert not instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        assert not instruction.accounts[1].is_signer
        assert instruction.accounts[1].is_writable
        assert instruction.accounts[2].is_signer
        assert instruction.accounts[2].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_transfer(tx.message, 0)
        assert decompiled.source == public_keys[0]
        assert decompiled.dest == public_keys[1]
        assert decompiled.owner == public_keys[2]
        assert decompiled.amount == 123456789

    def test_set_authority(self):
        public_keys = [key.public_key for key in generate_keys(3)]

        # With no new authority
        instruction = set_authority(
            public_keys[0],
            public_keys[1],
            AuthorityType.ACCOUNT_HOLDER,
        )

        assert instruction.data[0] == Command.SET_AUTHORITY
        assert instruction.data[1] == AuthorityType.ACCOUNT_HOLDER
        assert instruction.data[2] == 0

        assert not instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        assert instruction.accounts[1].is_signer
        assert not instruction.accounts[1].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_set_authority(tx.message, 0)
        assert decompiled.account == public_keys[0]
        assert decompiled.current_authority == public_keys[1]
        assert decompiled.authority_type == AuthorityType.ACCOUNT_HOLDER
        assert not decompiled.new_authority

        # With new authority
        instruction = set_authority(public_keys[0], public_keys[1], AuthorityType.CLOSE_ACCOUNT,
                                    new_authority=public_keys[2])

        assert instruction.data[0] == Command.SET_AUTHORITY
        assert instruction.data[1] == AuthorityType.CLOSE_ACCOUNT
        assert instruction.data[2] == 1
        assert instruction.data[3:] == public_keys[2].raw

        assert not instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        assert instruction.accounts[1].is_signer
        assert not instruction.accounts[1].is_writable

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_set_authority(tx.message, 0)
        assert decompiled.account == public_keys[0]
        assert decompiled.current_authority == public_keys[1]
        assert decompiled.authority_type == AuthorityType.CLOSE_ACCOUNT
        assert decompiled.new_authority == public_keys[2]

    def test_close_account(self):
        public_keys = [key.public_key for key in generate_keys(3)]

        instruction = close_account(public_keys[0], public_keys[1], public_keys[2])

        assert len(instruction.data) == 1
        assert instruction.data[0] == Command.CLOSE_ACCOUNT

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_close_account(tx.message, 0)
        assert decompiled.account == public_keys[0]
        assert decompiled.destination == public_keys[1]
        assert decompiled.owner == public_keys[2]
