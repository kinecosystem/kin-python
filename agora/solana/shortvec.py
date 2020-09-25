from typing import Tuple

_MAX_UINT16 = 2 ** 16 - 1


def encode_length(b: bytearray, length: int) -> int:
    """ Encodes the specified length into the byte array.

    :param b: The byte array to encode the len into.
    :param length: The length to encode. Must not exceed 2**16-1.
    :return: The number of bytes written to the array.
    """
    if length > _MAX_UINT16:
        raise ValueError(f'len exceeds {_MAX_UINT16}')

    written = 0

    while True:
        val = length & 0x7f
        length >>= 7
        if length == 0:
            b.append(val)
            written += 1

            return written

        val |= 0x80
        b.append(val)
        written += 1


def decode_length(b: bytes) -> Tuple[int, int]:
    """ Decodes a shortvec-encoded length from the provided bytes

    :param b: The provided bytes
    :return: The length decoded from the provided bytes and how many bytes it used.
    """

    offset = 0
    length = 0

    while offset < len(b):
        val = b[offset]
        length |= (val & 0x7f) << (offset * 7)
        offset += 1

        if (val & 0x80) == 0:
            break

    if offset > 3:
        raise ValueError(f'invalid size: {offset} (max 3)')

    return length, offset
