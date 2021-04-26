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

    @pytest.mark.parametrize(
        'program_id, expected',
        [
            (
                "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM",
                "Bn9pAWUXWc5Kd849xTkQcHqiCbHUEizLFn4r5Cf8XYnd",
            ),
            (
                "8opHzTAnfzRpPEx21XtnrVTX28YQuCpAjcn1PczScKh",
                "oDvUHiiGdMo31xYzjefAzUekWH8EbCKrxgs2FkyTs1S",
            ),
            (
                "CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3",
                "B2vBn2bmF9GuaGkebrm8oUqDC34pE6m4bagjNcVE6msv",
            ),
            (
                "GcdayuLaLyrdmUu324nahyv33G5poQdLUEZ1nEytDeP",
                "2mN5Nfq9v1EwTV9FPTHPESZ3XiZce9wi5PQoULFuxvev",
            ),
            (
                "LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj",
                "9CqF6oTZtW5zSeoLnZRoQmj3s2tXGPqifM1W8Z8LVE1z",
            ),
            (
                "QRSsyMWN1yHT9ir42bgNZUNZ4PdEhcSWCrL2AryKpy5",
                "FwBDYafabYZLDC8FwaDCsLxWkKnaQxKuQv3afDAGiXJ8",
            ),
            (
                "UKrXU5bFrTzrqqpZXs8GVDbp4xPweiM65ADXNAy3ddR",
                "2Y1miPDc3BkHVdNFeFTtRkiw8nbptrBqboJkbqxk5SFt",
            ),
            (
                "YEGAxog9gxiGXxo538aAQxq55XAebpFfwU72ZUxmSHm",
                "5jeaj2d8T2hjU63h2chjtSnuUmjti6qZK7oi6jwTspoo",
            ),
            (
                "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7",
                "6brHYNpseuh39WW3Md5WxTyw12kqumR4tTyZqzkyPWZP",
            ),
            (
                "g35TxFqwMx95vCk63fTxGTHb6ei4W24qg5t2x6xD3cT",
                "ESVKwnyn9DEkNcR5ZnHFbMK66nCArc9dChFCULstzLy5",
            ),
            (
                "jwV7SyvqCSrVcKibYvurCCWr7DUmT7yRYPmY9QwvrGo",
                "69BytoSYkhMovVk8gfGUwhf9P8HSnrcYhaoWY2dgmrPE",
            ),
            (
                "oqtkwi1j2wZuJSh74CMk7wk77nFUQDt1Qhf3Liweew9",
                "EfwG5mLknsUXPLHkUp1doxgN1W4Azr3gkZ1Zu6w6AxdF",
            ),
            (
                "skJQSS6csSHJzZfcZToe3gyN8M2BMKnbH1YYY2wNTbV",
                "Cw2qpvCaoPGxEJypW7rW5obTKSTLpCDRN7TgrrVugkfC",
            ),
            (
                "wei3wABWhvzigge84jFXySCd8untJRhB9KS3jLw6GFq",
                "8jztcAvddJNqK1ZjwcRkfWYAkfJW7dBbwoxZt7HSNg1G",
            ),
            (
                "21Z7hRtGQYRi8NocdZzhRuBRt9UZbFXbm1dKYvevp4vB",
                "9PPbRbNP3rqwzk16r7NDBzk1YDfo9EpWDWSqCYLn5eaF",
            ),
            (
                "25TXLvcMJNvRY4vb95G9Kpvf9A3LJCdWLswD47xvXsaX",
                "2rXxCqDNwia2f245koA11w7NoyNhNH4PwhSVLwpeBVRf",
            ),
            (
                "29MvzRLSCDR8wm3ZeaXbDkftQAc719jQvkF6ZKGvFgEs",
                "8habU8xKFCDeJNg9No6prtCY1Lq2px5bqWEyudy1SScW",
            ),
            (
                "2DGLdv4X63urMTAYA5o37gR7fBAsi6qKWcYz4WauyUuD",
                "7CPuXK4rdxhNqPUtTjvJ2peNEgVbBCzPV89SVK8boWai",
            ),
            (
                "2HAkHQnbytQZm9HWfb4V1cALvBjeR3wE6UrsZhtuhHZZ",
                "5U8dYpWb2W1s3ptdNhJJAkyf2JaRUxFAzVEnZmSP2t8X",
            ),
            (
                "2M59vuWgsiuHAqQVB6KvuXuaBCJR8138gMAm4uCuR6Du",
                "E5dLtHAM353EPnHyuZ32sKREn26VW4Y8bzb2KQJTBHQh",
            ),
        ]
    )
    def test_find_program_address_ref(self, program_id, expected):
        """Test with addresses generated by rust impl
        """
        pid = PublicKey.from_base58(program_id)
        exp = PublicKey.from_base58(expected)

        actual = find_program_address(pid, ['Lil\''.encode(), 'Bits'.encode()])
        assert actual == exp
