from agora.solana.system import Command, create_account, decompile_create_account
from agora.solana.transaction import Transaction
from tests.utils import generate_keys


class TestSystemProgram:
    def test_create_account(self):
        public_keys = [key.public_key for key in generate_keys(3)]
        instruction = create_account(public_keys[0], public_keys[1], public_keys[2], 12345, 67890)

        assert len(instruction.data) == 52
        assert instruction.data[0:4] == Command.CREATE_ACCOUNT.to_bytes(4, 'little')
        assert instruction.data[4:12] == (12345).to_bytes(8, 'little')
        assert instruction.data[12:20] == (67890).to_bytes(8, 'little')
        assert instruction.data[20:] == public_keys[2].raw

        tx = Transaction.unmarshal(Transaction.new(public_keys[0], [instruction]).marshal())
        decompiled = decompile_create_account(tx.message, 0)
        assert decompiled.funder == public_keys[0]
        assert decompiled.address == public_keys[1]
        assert decompiled.owner == public_keys[2]
        assert decompiled.lamports == 12345
        assert decompiled.size == 67890
