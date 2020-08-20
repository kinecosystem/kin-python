from enum import IntEnum


class TransactionType(IntEnum):
    """The type of a transaction.
    """
    UNKNOWN = -1
    NONE = 0
    EARN = 1
    SPEND = 2
    P2P = 3
