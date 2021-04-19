from typing import List

import base58
import pytest

from agora.keys import PublicKey, PrivateKey
from agora.solana.address import create_program_address, MAX_SEED_LENGTH, InvalidPublicKeyError, find_program_address

_PROGRAM_ID = PublicKey.from_base58('BPFLoader1111111111111111111111111111111111')
# The typo here was taken directly from the Solana test case,
# which was used to derive the expected outputs.
_PUBLIC_KEY = base58.b58decode('SeedPubey1111111111111111111111111111111111')


class TestCreateProgramAddress:
    def test_create_program_address_max_seed_length(self):
        max_seed = bytes(MAX_SEED_LENGTH)
        exceeded_seed = bytes(MAX_SEED_LENGTH + 1)

        with pytest.raises(ValueError):
            create_program_address(_PROGRAM_ID, [exceeded_seed])

        with pytest.raises(ValueError):
            create_program_address(_PROGRAM_ID, ['short seed'.encode(), exceeded_seed])

        assert create_program_address(_PROGRAM_ID, [max_seed])

    @pytest.mark.parametrize(
        'expected, seeds',
        [
            ('3gF2KMe9KiC6FNVBmfg9i267aMPvK37FewCip4eGBFcT', [bytes(), bytes([1])]),
            ('7ytmC1nT1xY4RfxCV2ZgyA7UakC93do5ZdyhdF3EtPj7', ['☉'.encode()]),
            ('HwRVBufQ4haG5XSgpspwKtNd3PC9GM9m1196uJW36vds', ['Talking'.encode(), 'Squirrels'.encode()]),
            ('GUs5qLUfsEHkcMB9T38vjr18ypEhRuNWiePW2LoK4E3K', [_PUBLIC_KEY]),
        ]
    )
    def test_create_program_address_success(self, expected: str, seeds: List[bytes]):
        address = create_program_address(_PROGRAM_ID, seeds)
        assert address.to_base58() == expected

    def test_create_program_address_seeds(self):
        a = create_program_address(_PROGRAM_ID, ['Talking'.encode()])
        b = create_program_address(_PROGRAM_ID, ['Talking'.encode(), 'Squirrels'.encode()])
        assert a.raw != b.raw

    def test_create_program_address_invalid(self, mocker):
        invalid_key = PrivateKey.random().public_key.raw
        mock_hashlib = mocker.patch('agora.solana.address.hashlib')
        mock_hashlib.sha256.return_value.digest.return_value = invalid_key

        with pytest.raises(InvalidPublicKeyError):
            create_program_address(_PROGRAM_ID, ['Lil\''.encode(), 'Bits'.encode()])


class TestFindProgramAddress:
    def test_find_program_address(self):
        for i in range(1000):
            assert find_program_address(PrivateKey.random().public_key, ['Lil\''.encode(), 'Bits'.encode()])
