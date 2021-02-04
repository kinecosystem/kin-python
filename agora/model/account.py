from typing import Optional

from agoraapi.account.v3 import account_service_pb2 as account_pb
from agoraapi.account.v4 import account_service_pb2 as account_pb_v4


class AccountInfo:
    """The information of a Kin account.

    :param account_id: The ID of the account.
    :param balance: The balance of the account, in quarks.
    """

    def __init__(self, account_id: bytes, balance: int):
        self.account_id = account_id
        self.balance = balance

    @classmethod
    def from_proto(cls, proto: account_pb.AccountInfo) -> 'AccountInfo':
        return cls(proto.account_id.value, proto.balance)

    @classmethod
    def from_proto_v4(cls, proto: account_pb_v4.AccountInfo) -> 'AccountInfo':
        return cls(proto.account_id.value, proto.balance)
