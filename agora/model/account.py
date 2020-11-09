from typing import Optional

from agoraapi.account.v3 import account_service_pb2 as account_pb
from agoraapi.account.v4 import account_service_pb2 as account_pb_v4


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

    @classmethod
    def from_proto(cls, proto: account_pb.AccountInfo) -> 'AccountInfo':
        return cls(proto.account_id.value, proto.balance, sequence_number=proto.sequence_number)

    @classmethod
    def from_proto_v4(cls, proto: account_pb_v4.AccountInfo) -> 'AccountInfo':
        return cls(proto.account_id.value, proto.balance)
