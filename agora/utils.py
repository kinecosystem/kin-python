import base64
import decimal
import sys
from typing import Tuple

from kin_base import transaction_envelope as te, transaction
from kin_base.stellarxdr import Xdr as Xdr_kin

_KIN_USER_AGENT_HEADER = 'kin-user-agent'
_KIN_TO_QUARKS = decimal.Decimal(10 ** 5)
_PRECISION = decimal.Decimal('0.00001')


def partition(l, size):
    """
    Partition the provided list into a list of sub-lists of the provided size. The last sub-list may be smaller if the
    length of the originally provided list is not evenly divisible by `size`.

    :param l: the list to partition
    :param size: the size of each sub-list

    :return: a list of sub-lists
    """
    return [l[i:i + size] for i in range(0, len(l), size)]


def user_agent(version) -> Tuple[str, str]:
    return (
        _KIN_USER_AGENT_HEADER,
        f'KinSDK/{version} python/{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}-'
        f'{sys.version_info.releaselevel}'
    )


def kin_to_quarks(kin: str) -> int:
    """Converts a string kin amount to quarks. If the provided Kin amount contains more than 5 decimal places (i.e.
    it contains an inexact number of quarks), additional decimal places will be ignored.

    For example, passing in a value of "0.000009" will result in a value of 0 quarks being returned.

    :param kin: A string Kin amount.
    :return: An integer quark amount.
    """
    rounded = decimal.Decimal(kin).quantize(_PRECISION, decimal.ROUND_DOWN)
    return int((rounded * _KIN_TO_QUARKS).to_integral_value())


def quarks_to_kin(quarks: int) -> str:
    """Converts an integer quark amount into a string Kin amount.

    :param quarks: An amount, in quarks.
    :return: A string Kin amount.
    """
    kin = (decimal.Decimal(quarks) / _KIN_TO_QUARKS)
    return str(kin)


def envelope_from_xdr(network_id: str, xdr: bytes) -> te.TransactionEnvelope:
    """Create a new TransactionEnvelope from an XDR string.

    :param network_id: The network ID to instantiate the TransactionEnvelope with.
    :param xdr: The XDR string
    :return: a TransactionEnvelope
    """
    xdr_decoded = base64.b64decode(xdr)
    env = Xdr_kin.StellarXDRUnpacker(xdr_decoded)
    te_xdr_object = env.unpack_TransactionEnvelope()
    signatures = te_xdr_object.signatures
    tx_xdr_object = te_xdr_object.tx
    tx = transaction.Transaction.from_xdr_object(tx_xdr_object)
    env = te.TransactionEnvelope(tx, signatures=signatures, network_id=network_id)

    return env
