from typing import Optional


class AccountInfo:
    """The information of a Kin account.

    :param account_id: The ID of the account.
    :param balance: The balance of the account, in quarks.
    :param sequence_number: (optional) The current sequence number of the account. Only present on Stellar accounts.
    """

    def __init__(self, account_id: bytes, balance: int, sequence_number: Optional[int] = None):
        self.account_id = account_id
        self.balance = balance
        self.sequence_number = sequence_number
