import decimal

from kin_base import utils

_KIN_TO_QUARKS = decimal.Decimal(10 ** 5)
_PRECISION = decimal.Decimal(10 ** -5)


def kin_to_quarks(kin: float) -> int:
    """Converts a kin amount to quarks, with rounding. Uses the ROUND_HALF_UP method.

    :param kin: An amount, in Kin.
    :return: A integer quark amount.
    """
    return int((decimal.Decimal(kin) * _KIN_TO_QUARKS).quantize(decimal.Decimal('0.00001'),
                                                                rounding=decimal.ROUND_HALF_UP).to_integral_value())


def quarks_to_kin(quarks: int) -> float:
    """Converts an amount of quarks to kin.

    :param quarks: An amount, in quarks.
    :return: A float Kin amount.
    """
    return float((decimal.Decimal(quarks) / _KIN_TO_QUARKS))


def quarks_to_kin_str(quarks: int) -> str:
    """Converts an integer quark amount into a string Kin amount.

    :param quarks: An amount, in quarks.
    :return: A string Kin amount.
    """
    return "{:.5f}".format(quarks_to_kin(quarks))


def public_key_to_address(public_key: bytes) -> str:
    """Returns a raw ed25519 public key encoded as a strkey.

    :param public_key: The public key, in raw bytes, of an account.
    :return: The public key encoded as a strkey.
    """
    return utils.encode_check('account', public_key).decode()
