import base64
from typing import Tuple

import pytest

from agora import solana
from agora.keys import PrivateKey, PublicKey
from agora.solana import token
from agora.webhook.create_account import CreateAccountRequest, CreateAccountResponse
from tests.utils import generate_keys

_SIGNING_KEY = PrivateKey.random()


class TestCreateAccountRequest:
    def test_from_json_kin_4(self):
        tx, owner, assoc = _generate_create_tx()

        data = {
            'solana_transaction': base64.b64encode(tx.marshal()),
        }

        req = CreateAccountRequest.from_json(data)
        assert req.creation.address == assoc
        assert req.creation.owner == owner

    def test_from_json_invalid(self):
        with pytest.raises(ValueError) as e:
            CreateAccountRequest.from_json({})
        assert 'solana_transaction' in str(e)

        keys = [key.public_key for key in generate_keys(4)]
        tx = solana.Transaction.new(
            keys[0],
            [
                token.transfer(
                    keys[1],
                    keys[2],
                    keys[3],
                    20,
                ),
            ]
        )

        with pytest.raises(ValueError) as e:
            CreateAccountRequest.from_json({
                'solana_transaction': base64.b64encode(tx.marshal())
            })
        assert 'unexpected payments' in str(e)

        tx = solana.Transaction.new(
            keys[0],
            []
        )
        with pytest.raises(ValueError) as e:
            CreateAccountRequest.from_json({
                'solana_transaction': base64.b64encode(tx.marshal())
            })
        assert 'expected exactly 1 creation' in str(e)

        create_assoc_instruction1, assoc1 = token.create_associated_token_account(keys[0], keys[1], keys[2])
        create_assoc_instruction2, assoc2 = token.create_associated_token_account(keys[0], keys[1], keys[2])
        tx = solana.Transaction.new(
            keys[0],
            [
                create_assoc_instruction1,
                token.set_authority(assoc1, assoc1, token.AuthorityType.CLOSE_ACCOUNT, new_authority=keys[0]),
                create_assoc_instruction2,
                token.set_authority(assoc2, assoc2, token.AuthorityType.CLOSE_ACCOUNT, new_authority=keys[0]),
            ]
        )
        with pytest.raises(ValueError) as e:
            CreateAccountRequest.from_json({
                'solana_transaction': base64.b64encode(tx.marshal())
            })
        assert 'expected exactly 1 creation' in str(e)


class TestCreateAccountResponse:
    def test_sign(self):
        tx, owner, assoc = _generate_create_tx()
        resp = CreateAccountResponse(tx)
        resp.sign(_SIGNING_KEY)

        _SIGNING_KEY.public_key.verify(resp.transaction.message.marshal(), resp.transaction.signatures[0])

    def test_reject(self):
        tx, _, _ = _generate_create_tx()
        resp = CreateAccountResponse(tx)
        assert not resp.rejected

        resp.reject()
        assert resp.rejected


# Returns transaction, owner, and assoc
def _generate_create_tx() -> Tuple[solana.Transaction, PublicKey, PublicKey]:
    keys = [key.public_key for key in generate_keys(2)]
    create_assoc_instruction, assoc = token.create_associated_token_account(_SIGNING_KEY.public_key, keys[0], keys[1])
    return solana.Transaction.new(
        _SIGNING_KEY.public_key,
        [
            create_assoc_instruction,
            token.set_authority(assoc, assoc, token.AuthorityType.CLOSE_ACCOUNT, new_authority=_SIGNING_KEY.public_key),
        ]
    ), keys[0], assoc
