import hashlib
from typing import List, Optional

from pure25519.basic import decodepoint, NotOnCurve

from agora.keys import PublicKey

MAX_SEEDS = 16
MAX_SEED_LENGTH = 32
MAX_UINT8 = 2 ** 8 - 1


class InvalidPublicKeyError(Exception):
    """
    Raised when an invalid public key is generated.
    """

    def __init__(self):
        super().__init__('invalid public key')


def create_program_address(program: PublicKey, seeds: List[bytes]) -> PublicKey:
    """Mirrors the implementation of the Solana SDK's CreateProgramAddress. ProgramAddresses are public keys that
    _do not_ lie on the ed25519 curve to ensure that there is no associated private key. In the event that the program
    and seed parameters result in a valid Public key, InvalidPublicKeyError is raised.

    Reference:
    https://github.com/solana-labs/solana/blob/5548e599fe4920b71766e0ad1d121755ce9c63d5/sdk/program/src/pubkey.rs#L158

    :return :class:`PublicKey <agora.keys.PublicKey>`
    """
    if len(seeds) > MAX_SEEDS:
        raise ValueError('too many seeds')

    sha256 = hashlib.sha256()
    for s in seeds:
        if len(s) > MAX_SEED_LENGTH:
            raise ValueError('max seed length exceeded')

        sha256.update(s)

    for v in [program.raw, "ProgramDerivedAddress".encode()]:
        sha256.update(v)

    h = sha256.digest()
    pub = h[:32]

    # Following the Solana SDK, we want to _reject_ the generated public key if it's a a valid point on the ed25519 curve
    try:
        decodepoint(pub)
    except NotOnCurve:
        return PublicKey(pub)

    raise InvalidPublicKeyError()


def find_program_address(program: PublicKey, seeds: List[bytes]) -> Optional[PublicKey]:
    """FindProgramAddress mirrors the implementation of the Solana SDK's FindProgramAddress. Its primary use case (for
    Kin and Agora) is for deriving associated accounts.

    return: :class:`PublicKey <agora.keys.PublicKey>`
    """
    bump_seed = bytes([MAX_UINT8])
    for i in range(MAX_UINT8):
        try:
            pub = create_program_address(program, seeds + [bump_seed])
        except InvalidPublicKeyError:
            bump_seed = bytes([bump_seed[0] - 1])
            continue

        return pub

    return None
