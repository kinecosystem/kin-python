from enum import Enum


class Environment(Enum):
    """An Agora Environment.
    """

    # Interacts with the production Kin blockchain.
    PRODUCTION = 1

    # Interacts with the test Kin blockchain.
    TEST = 2
