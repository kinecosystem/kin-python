import base64
import uuid
from typing import Tuple, List

import pytest
from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.keys import PublicKey, PrivateKey
from agora.model import parse_transaction, TransactionType, AgoraMemo, InvoiceList, Invoice
from agora.solana import token, memo, system
from agora.solana.token import AuthorityType
from tests.utils import generate_keys


class TestParseTransaction:
    def test_transfers_no_invoices(self):
        keys = [priv.public_key for priv in generate_keys(5)]

        tx = solana.Transaction.new(
            keys[0],
            [
                token.transfer(keys[1], keys[2], keys[3], 10),
                token.transfer(keys[2], keys[3], keys[4], 20),
            ],
        )
        creations, payments = parse_transaction(tx)
        assert len(creations) == 0

        for i in range(2):
            assert payments[i].sender == keys[1 + i]
            assert payments[i].destination == keys[2 + i]
            assert payments[i].tx_type == TransactionType.UNKNOWN
            assert payments[i].quarks == (1 + i) * 10
            assert not payments[i].invoice
            assert not payments[i].memo

    def test_transfers_with_invoices(self):
        keys = [priv.public_key for priv in generate_keys(5)]

        # Single memo
        memo_instruction, il = self._get_invoice_memo_instruction(TransactionType.SPEND, 10, 2)
        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction,
                token.transfer(keys[1], keys[2], keys[3], 10),
                token.transfer(keys[2], keys[3], keys[4], 20)
            ],
        )
        creations, payments = parse_transaction(tx, il)
        assert len(creations) == 0

        for i in range(2):
            assert payments[i].sender == keys[1 + i]
            assert payments[i].destination == keys[2 + i]
            assert payments[i].tx_type == TransactionType.SPEND
            assert payments[i].quarks == (1 + i) * 10
            assert payments[i].invoice == Invoice.from_proto(il.invoices[i])
            assert not payments[i].memo

        # Multiple memos
        memo_instruction_1, il1 = self._get_invoice_memo_instruction(TransactionType.SPEND, 10, 1)
        memo_instruction_2, il2 = self._get_invoice_memo_instruction(TransactionType.P2P, 10, 1)

        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction_1,
                token.transfer(keys[1], keys[2], keys[3], 10),
                memo_instruction_2,
                token.transfer(keys[2], keys[3], keys[4], 20),
            ],
        )
        creations, payments = parse_transaction(tx, il1)
        assert len(creations) == 0

        expected_invoices = [il1.invoices[0], None]
        expected_types = [TransactionType.SPEND, TransactionType.P2P]
        for i in range(2):
            assert payments[i].sender == keys[1 + i]
            assert payments[i].destination == keys[2 + i]
            assert payments[i].tx_type == expected_types[i]
            assert payments[i].quarks == (1 + i) * 10
            if expected_invoices[i]:
                assert payments[i].invoice == Invoice.from_proto(expected_invoices[i])
            else:
                assert not payments[i].invoice
            assert not payments[i].memo

    def test_with_text_memo(self):
        keys = [priv.public_key for priv in generate_keys(5)]

        # transfers with single memo
        tx = solana.Transaction.new(
            keys[0],
            [
                memo.memo_instruction('1-test'),
                token.transfer(keys[1], keys[2], keys[3], 10),
                token.transfer(keys[2], keys[3], keys[4], 20),
            ]
        )
        creations, payments = parse_transaction(tx)
        assert len(creations) == 0

        for i in range(2):
            assert payments[i].sender == keys[1 + i]
            assert payments[i].destination == keys[2 + i]
            assert payments[i].tx_type == TransactionType.UNKNOWN
            assert payments[i].quarks == (1 + i) * 10
            assert not payments[i].invoice
            assert payments[i].memo == '1-test'

        # transfers with multiple memos
        expected_memos = ['1-test-alpha', '1-test-beta']
        tx = solana.Transaction.new(
            keys[0],
            [
                memo.memo_instruction(expected_memos[0]),
                token.transfer(keys[1], keys[2], keys[3], 10),
                memo.memo_instruction(expected_memos[1]),
                token.transfer(keys[2], keys[3], keys[4], 20),
            ]
        )
        creations, payments = parse_transaction(tx)
        assert len(creations) == 0

        for i in range(2):
            assert payments[i].sender == keys[1 + i]
            assert payments[i].destination == keys[2 + i]
            assert payments[i].tx_type == TransactionType.UNKNOWN
            assert payments[i].quarks == (1 + i) * 10
            assert not payments[i].invoice
            assert payments[i].memo == expected_memos[i]

        # sender create
        create_instructions, addr = self._generate_create(keys[0], keys[1], keys[2])

        inputs = []
        for i in range(2):
            instructions = create_instructions.copy()
            instructions.append(memo.memo_instruction('1-test'))
            instructions.append(token.transfer(keys[3], keys[4], keys[1], 10))

        for idx, i in enumerate(inputs):
            creations, payments = parse_transaction(i)
            assert len(creations) == 1
            assert len(payments) == 1

            assert creations[0].owner == keys[1]
            assert creations[0].address == addr

            assert payments[0].sender == keys[3]
            assert payments[0].destination == keys[4]
            assert payments[0].tx_type == TransactionType.UNKNOWN
            assert payments[0].quarks == 10
            assert not payments[0].invoice
            assert payments[0].memo == '1-test'

    def test_create_without_account_holder_auth(self):
        keys = [priv.public_key for priv in generate_keys(3)]

        create_instructions, addr = self._generate_create(keys[0], keys[1], keys[2])
        create_assoc_instruction, assoc = token.create_associated_token_account(keys[0], keys[1], keys[2])
        txs = [
            solana.Transaction.new(
                keys[0],
                create_instructions[:3],
            ),
            solana.Transaction.new(
                keys[0],
                [
                    create_assoc_instruction,
                    token.set_authority(assoc, assoc, token.AuthorityType.CLOSE_ACCOUNT, new_authority=keys[0]),
                ]
            )
        ]

        for idx, tx in enumerate(txs):
            creations, payments = parse_transaction(tx)
            assert len(creations) == 1
            assert len(payments) == 0

            if idx == 0:
                # Randomly generated in _generate_create
                assert creations[0].owner
                assert creations[0].address == addr
            else:
                assert creations[0].owner == keys[1]
                assert creations[0].address == assoc

    def test_create_without_close_authority(self):
        keys = [priv.public_key for priv in generate_keys(3)]

        create_instructions, addr = self._generate_create(keys[0], keys[1], keys[2])
        create_assoc_instruction, assoc = token.create_associated_token_account(keys[0], keys[1], keys[2])
        txs = [
            solana.Transaction.new(
                keys[0],
                create_instructions[:2],
            ),
            solana.Transaction.new(
                keys[0],
                [
                    create_assoc_instruction,
                ],
            )
        ]

        for tx in txs:
            with pytest.raises(ValueError) as e:
                parse_transaction(tx)
            assert 'SetAuthority(Close)' in str(e)

    def test_invalid_memo_combinations(self):
        keys = [priv.public_key for priv in generate_keys(5)]

        # invalid transaction type combinations
        memo_instruction1, _ = self._get_invoice_memo_instruction(TransactionType.EARN, 10, 1)
        for tx_type in [TransactionType.SPEND, TransactionType.P2P]:
            memo_instruction2, _ = self._get_invoice_memo_instruction(tx_type, 10, 1)
            tx = solana.Transaction.new(
                keys[0],
                [
                    memo_instruction1,
                    token.transfer(keys[1], keys[2], keys[3], 10),
                    memo_instruction2,
                    token.transfer(keys[2], keys[3], keys[4], 20),
                ]
            )

            with pytest.raises(ValueError) as e:
                parse_transaction(tx)
            assert 'cannot mix' in str(e)

        # mixed app IDs
        tx = solana.Transaction.new(
            keys[0],
            [
                memo.memo_instruction('1-kik'),
                memo.memo_instruction('1-kin'),
            ]
        )

        with pytest.raises(ValueError) as e:
            parse_transaction(tx)
        assert 'app IDs' in str(e)

        # mixed app indices
        memo_instruction1, _ = self._get_invoice_memo_instruction(TransactionType.EARN, 10, 1)
        memo_instruction2, _ = self._get_invoice_memo_instruction(TransactionType.EARN, 11, 1)
        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction1,
                memo_instruction2,
            ]
        )

        with pytest.raises(ValueError) as e:
            parse_transaction(tx)
        assert 'app indexes' in str(e)

        # no memos match the invoice list
        il = self._generate_invoice_list(2)
        memo_instruction, il2 = self._get_invoice_memo_instruction(TransactionType.EARN, 10, 1)
        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction,
                token.transfer(keys[1], keys[2], keys[3], 10),
                memo_instruction,
                token.transfer(keys[2], keys[3], keys[4], 20),
            ]
        )

        with pytest.raises(ValueError) as e:
            parse_transaction(tx, il)
        assert 'exactly one' in str(e)

        # too many memos match the invoice list
        memo_instruction, il = self._get_invoice_memo_instruction(TransactionType.EARN, 10, 2)
        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction,
                token.transfer(keys[1], keys[2], keys[3], 10),
                memo_instruction,
                token.transfer(keys[2], keys[3], keys[4], 20),
            ]
        )

        with pytest.raises(ValueError) as e:
            parse_transaction(tx, il)
        assert 'exactly one' in str(e)

        # too many transfers for the invoice list
        memo_instruction, il = self._get_invoice_memo_instruction(TransactionType.EARN, 10, 1)
        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction,
                token.transfer(keys[1], keys[2], keys[3], 10),
                memo_instruction,
                token.transfer(keys[2], keys[3], keys[4], 20),
            ]
        )

        with pytest.raises(ValueError) as e:
            parse_transaction(tx, il)
        assert 'sufficient invoices' in str(e)

        # too few transfers for the invoice list
        memo_instruction, il = self._get_invoice_memo_instruction(TransactionType.EARN, 10, 2)
        tx = solana.Transaction.new(
            keys[0],
            [
                memo_instruction,
                token.transfer(keys[1], keys[2], keys[3], 10),
            ]
        )

        with pytest.raises(ValueError) as e:
            parse_transaction(tx, il)
        assert 'does not match number of transfers referencing the invoice list' in str(e)

    def test_with_invalid_instructions(self):
        keys = [priv.public_key for priv in generate_keys(5)]
        invalid_instructions = [
            token.set_authority(keys[1], keys[2], AuthorityType.ACCOUNT_HOLDER, new_authority=keys[3]),
            token.initialize_account(keys[1], keys[2], keys[3]),
            system.create_account(keys[1], keys[2], keys[3], 10, 10),
        ]

        for i in invalid_instructions:
            tx = solana.Transaction.new(
                keys[0],
                [
                    token.transfer(keys[1], keys[2], keys[3], 10),
                    i,
                ]
            )

            with pytest.raises(ValueError):
                parse_transaction(tx)

    @staticmethod
    def _get_invoice_memo_instruction(
        tx_type: TransactionType, app_index: int, transfer_count: int
    ) -> Tuple[solana.Instruction, model_pb2.InvoiceList]:
        il = TestParseTransaction._generate_invoice_list(transfer_count)
        m = AgoraMemo.new(1, tx_type, app_index, InvoiceList.from_proto(il).get_sha_224_hash())
        return memo.memo_instruction(base64.b64encode(m.val).decode('utf-8')), il

    @staticmethod
    def _generate_create(
        subsidizer: PublicKey, wallet: PublicKey, mint: PublicKey
    ) -> Tuple[List[solana.Instruction], PublicKey]:
        addr = token.get_associated_account(wallet, mint)
        pub = PrivateKey.random().public_key

        instructions = [
            system.create_account(subsidizer, addr, token.PROGRAM_KEY, 10, token.ACCOUNT_SIZE),
            token.initialize_account(addr, mint, pub),
            token.set_authority(addr, pub, token.AuthorityType.CLOSE_ACCOUNT, subsidizer),
            token.set_authority(addr, pub, token.AuthorityType.ACCOUNT_HOLDER, wallet)
        ]
        return instructions, addr

    @staticmethod
    def _generate_invoice_list(transfer_count: int):
        return model_pb2.InvoiceList(
            invoices=[
                model_pb2.Invoice(
                    items=[
                        model_pb2.Invoice.LineItem(title=str(uuid.uuid4()))
                    ]
                ) for _ in range(transfer_count)
            ]
        )
