from agora.keys import PublicKey
from agora.solana import system
from agora.solana.token import PROGRAM_KEY
from agora.solana.token.associated import get_associated_account, create_associated_token_account, \
    decompile_create_associated_account
from agora.solana.transaction import Transaction
from tests.utils import generate_keys


class TestAssociatedTokenProgram:
    def test_get_associated_account(self):
        # Values generated from taken from spl code.
        wallet = PublicKey.from_base58('4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM')
        mint = PublicKey.from_base58('8opHzTAnfzRpPEx21XtnrVTX28YQuCpAjcn1PczScKh')

        expected = PublicKey.from_base58('H7MQwEzt97tUJryocn3qaEoy2ymWstwyEk1i9Yv3EmuZ')

        actual = get_associated_account(wallet, mint)
        assert actual == expected

    def test_create_associated_account(self):
        keys = [key.public_key for key in generate_keys(3)]

        expected_addr = get_associated_account(keys[1], keys[2])

        instruction, addr = create_associated_token_account(keys[0], keys[1], keys[2])
        assert addr == expected_addr

        assert len(instruction.data) == 0
        assert len(instruction.accounts) == 7

        assert instruction.accounts[0].is_signer
        assert instruction.accounts[0].is_writable
        assert not instruction.accounts[1].is_signer
        assert instruction.accounts[1].is_writable

        for i in range(2, len(instruction.accounts)):
            assert not instruction.accounts[i].is_signer
            assert not instruction.accounts[i].is_writable

        assert instruction.accounts[4].public_key == system.PROGRAM_KEY
        assert instruction.accounts[5].public_key == PROGRAM_KEY
        assert instruction.accounts[6].public_key == system.RENT_SYS_VAR

        tx = Transaction.unmarshal(Transaction.new(keys[0], [instruction]).marshal())
        decompiled = decompile_create_associated_account(tx.message, 0)
        assert decompiled.subsidizer == keys[0]
        assert decompiled.owner == keys[1]
        assert decompiled.mint == keys[2]
