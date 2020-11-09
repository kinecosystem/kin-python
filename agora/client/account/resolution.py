from enum import IntEnum


class AccountResolution(IntEnum):
    """Used to indicate which type of account resolution should be used if a transaction on Kin 4 fails due to an
    account being unavailable.

    EXACT: No account resolution will be used.
    PREFERRED:
        When used for a sender key in a payment or earn request, if Agora is able to resolve the original sender public
        key to a set of token accounts, the original sender will be used as the owner in the Solana transfer
        instruction and the first resolved token account will be used as the sender.

        When used for a destination key in a payment or earn request, if Agora is able to resolve the destination key to
        a set of token accounts, the first resolved token account will be used as the destination in the Solana transfer
        instruction.
    """
    EXACT = 0
    PREFERRED = 1
