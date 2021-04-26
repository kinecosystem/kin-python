import base64

import pytest

from agora.keys import PrivateKey, PublicKey
from agora.solana.instruction import Instruction, AccountMeta
from agora.solana.transaction import Transaction
# Taken from:
# https://github.com/solana-labs/solana/blob/14339dec0a960e8161d1165b6a8e5cfb73e78f23/sdk/src/transaction.rs#L523
from tests.utils import generate_keys

_RUST_GENERATED = 'AUc7Cbu+gZalFSGeSFdukHhP7oSGaSdmdNEd5ZokaSysdoMWfIOzjrAbdaBZZuDMAfyNAogAJdrhgVya+jthsgoBAAEDnON0wdcmjhYIDuXvd10F2qEjAyEAJGSe/CGhYbk+WWMBAQEEBQYHCAkJCQkJCQkJCQkJCQkJCQkIBwYFBAEBAQICAgQFBgcICQEBAQEBAQEBAQEBAQEBCQgHBgUEAgICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAgIAAQMBAgM='  # noqa: E501

# The above example does not have the correct public key encoded in the keypair.
# This is the above example with the correctly generated keypair.
_RUST_GENERATED_ADJUSTED = 'ATMfBMZ8phHEheLph8K9TJhRKhnE4qNZvWiXdUdJRmlTCRsQjWmW2CkQJeRHBCcsqFm2gynjL40M9mTe0Dxp4QIBAAEDfEya6wnC7f3Cv53qnOEywwIJ928rIdqAlfXYI1adXroBAQEEBQYHCAkJCQkJCQkJCQkJCQkJCQkIBwYFBAEBAQICAgQFBgcICQEBAQEBAQEBAQEBAQEBCQgHBgUEAgICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAgIAAQMBAgM='  # noqa: E501


class TestTransaction:
    def test_transaction_cross_impl(self):
        pk = PrivateKey(bytes([48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 255, 101, 36, 24, 124, 23,
                               167, 21, 132, 204, 155, 5, 185, 58, 121, 75]))
        program_id = PublicKey(bytes([2, 2, 2, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 8, 7, 6,
                                      5, 4, 2, 2, 2]))
        to = PublicKey(bytes([1, 1, 1, 4, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 8, 7, 6, 5, 4, 1,
                              1, 1]))

        tx = Transaction.new(
            pk.public_key,
            [
                Instruction(
                    program_id,
                    bytes([1, 2, 3]),
                    [AccountMeta.new(pk.public_key, True), AccountMeta.new(to, False)],
                ),
            ],
        )
        tx.sign([pk])

        generated = base64.b64decode(_RUST_GENERATED_ADJUSTED)
        assert tx.marshal() == generated
        assert Transaction.unmarshal(generated) == tx

    def test_transaction_missing_blockhash(self):
        payer, program = generate_keys(2)
        tx = Transaction.new(
            payer.public_key,
            [Instruction(
                program.public_key,
                bytes([1, 2, 3]),
                [
                    AccountMeta.new(payer.public_key, True),
                ],
            )],
        )
        assert Transaction.unmarshal(tx.marshal()) == tx

    def test_transaction_invalid_accounts(self):
        keys = generate_keys(2)
        tx = Transaction.new(
            keys[0].public_key,
            [Instruction(
                keys[1].public_key,
                bytes([1, 2, 3]),
                [
                    AccountMeta.new(keys[0].public_key, True)
                ],
            )],
        )
        tx.message.instructions[0].program_index = 2  # invalid index
        with pytest.raises(ValueError):
            Transaction.unmarshal(tx.marshal())

        tx = Transaction.new(
            keys[0].public_key,
            [Instruction(
                keys[1].public_key,
                bytes([1, 2, 3]),
                [
                    AccountMeta.new(keys[0].public_key, True)
                ],
            )],
        )
        tx.message.instructions[0].accounts = bytes([2])  # invalid index
        with pytest.raises(ValueError):
            Transaction.unmarshal(tx.marshal())

    # TODO: verify this with other impls
    def test_transaction_duplicate_keys(self):
        payer, program = generate_keys(2)
        keys = generate_keys(4)
        data = bytes([1, 2, 3])

        # Key[0]: ReadOnlySigner -> WritableSigner
        # Key[1]: ReadOnly       -> ReadOnlySigner
        # Key[2]: Writable       -> Writable       (ReadOnly,noop)
        # Key[3]: WritableSigner -> WritableSigner (ReadOnly,noop)

        tx = Transaction.new(
            payer.public_key,
            [
                Instruction(
                    program.public_key,
                    data,
                    [
                        AccountMeta.new_read_only(keys[0].public_key, True),  # 0 ReadOnlySigner
                        AccountMeta.new_read_only(keys[1].public_key, False),  # 1 ReadOnly
                        AccountMeta.new(keys[2].public_key, False),  # Writable
                        AccountMeta.new(keys[3].public_key, True),  # WritableSigner
                        # Upgrade keys [0] and [1]
                        AccountMeta.new(keys[0].public_key, False),  # Writable (promote to WritableSigner)
                        AccountMeta.new_read_only(keys[1].public_key, True),  # Signer (promote to ReadOnlySigner)
                        # 'Downgrade' keys [2] and [3] (should be noop)
                        AccountMeta.new_read_only(keys[2].public_key, False),  # ReadOnly; still Writable
                        AccountMeta.new_read_only(keys[3].public_key, False)  # Readonly; still a WritableSigner
                    ],
                ),
            ]
        )

        # Intentionally sign out of order to ensure ordering is fixed
        tx.sign([keys[0], keys[1], keys[3], payer])

        assert len(tx.signatures) == 4
        assert len(tx.message.accounts) == 6
        assert tx.message.header.num_signatures == 4
        assert tx.message.header.num_read_only_signed == 1
        assert tx.message.header.num_read_only == 1

        message = tx.message.marshal()
        for idx, key in enumerate([payer, keys[0], keys[3], keys[1]]):
            key.public_key.verify(message, tx.signatures[idx])

        expected_keys = [payer, keys[0], keys[3], keys[1], keys[2], program]
        for idx, account in enumerate(expected_keys):
            assert tx.message.accounts[idx] == account.public_key

        assert tx.message.instructions[0].program_index == 5
        assert tx.message.instructions[0].data == data
        assert tx.message.instructions[0].accounts == bytes([1, 3, 4, 2, 1, 3, 4, 2])

    def test_transaction_single_instruction(self):
        payer, program = generate_keys(2)
        keys = generate_keys(4)
        data = bytes([1, 2, 3])

        tx = Transaction.new(
            payer.public_key,
            [Instruction(
                program.public_key,
                data,
                [
                    AccountMeta.new_read_only(keys[0].public_key, True),
                    AccountMeta.new_read_only(keys[1].public_key, False),
                    AccountMeta.new(keys[2].public_key, False),
                    AccountMeta.new(keys[3].public_key, True),
                ],
            )],
        )

        tx.sign([keys[0], keys[3], payer])

        assert len(tx.signatures) == 3
        assert len(tx.message.accounts) == 6
        assert tx.message.header.num_signatures == 3
        assert tx.message.header.num_read_only_signed == 1
        assert tx.message.header.num_read_only == 2

        message = tx.message.marshal()

        payer.public_key.verify(message, tx.signatures[0])
        keys[3].public_key.verify(message, tx.signatures[1])
        keys[0].public_key.verify(message, tx.signatures[2])

        expected_keys = [payer, keys[3], keys[0], keys[2], keys[1], program]
        for idx, key in enumerate(expected_keys):
            assert tx.message.accounts[idx] == key.public_key

        assert tx.message.instructions[0].program_index == 5
        assert tx.message.instructions[0].data == data
        assert tx.message.instructions[0].accounts == bytes([2, 4, 3, 1])

    def test_transaction_multi_instruction(self):
        payer, program, program2 = generate_keys(3)
        keys = generate_keys(6)

        data = bytes([1, 2, 3])
        data2 = bytes([3, 4, 5])

        # Key[0]: ReadOnlySigner -> WritableSigner
        # Key[1]: ReadOnly       -> WritableSigner
        # Key[2]: Writable       -> Writable(ReadOnly, noop)
        # Key[3]: WritableSigner -> WritableSigner(ReadOnly, noop)
        # Key[4]: n / a            -> WritableSigner
        # Key[5]: n / a            -> ReadOnly

        tx = Transaction.new(
            payer.public_key,
            [
                Instruction(
                    program.public_key,
                    data,
                    [
                        AccountMeta.new_read_only(keys[0].public_key, True),  # ReadOnlySigner
                        AccountMeta.new_read_only(keys[1].public_key, False),  # ReadOnly
                        AccountMeta.new(keys[2].public_key, False),  # Writable
                        AccountMeta.new(keys[3].public_key, True),  # WritableSigner
                    ],
                ),
                Instruction(
                    program2.public_key,
                    data2,
                    [
                        # Ensure keys don't get downgraded in permissions
                        AccountMeta.new_read_only(keys[3].public_key, False),  # ReadOnly, still WriteableSigner
                        AccountMeta.new_read_only(keys[2].public_key, False),  # ReadOnly, still Writable
                        # Ensure upgrading works
                        AccountMeta.new(keys[0].public_key, False),  # Writable (promote to WritableSigner)
                        AccountMeta.new(keys[1].public_key, True),  # WritableSigner (promote to WritableSigner)
                        # Ensure other accounts get added
                        AccountMeta.new(keys[4].public_key, True),  # WritableSigner
                        AccountMeta.new_read_only(keys[5].public_key, False),  # ReadOnly
                    ],
                ),
            ]
        )

        tx.sign([payer, keys[0], keys[1], keys[3], keys[4]])

        assert len(tx.signatures) == 5
        assert len(tx.message.accounts) == 9
        assert tx.message.header.num_signatures == 5
        assert tx.message.header.num_read_only_signed == 0
        assert tx.message.header.num_read_only == 3

        message = tx.message.marshal()
        for idx, key in enumerate([payer, keys[0], keys[1], keys[3], keys[4]]):
            key.public_key.verify(message, tx.signatures[idx])

        expected_keys = [payer, keys[0], keys[1], keys[3], keys[4], keys[2], keys[5], program, program2]
        for idx, account in enumerate(expected_keys):
            assert tx.message.accounts[idx] == account.public_key

        assert tx.message.instructions[0].program_index == 7
        assert tx.message.instructions[0].data == data
        assert tx.message.instructions[0].accounts == bytes([1, 2, 5, 3])

        assert tx.message.instructions[1].program_index == 8
        assert tx.message.instructions[1].data == data2
        assert tx.message.instructions[1].accounts == bytes([3, 5, 1, 2, 4, 6])
