from typing import Optional

from agoraapi.account.v4 import account_service_pb2 as account_pb_v4

from agora.keys import PublicKey


class AccountInfo:
    """The information of a Kin account.

    :param account_id: The ID of the account.
    :param balance: The balance of the account, in quarks. Included only if account info was requested.
    :param owner: The owner of the account, included only if it is a token account.
    :param close_authority: The close authority of the account, included only if it is a token account.
    """

    def __init__(
        self, account_id: PublicKey, balance: Optional[int] = None, owner: Optional[PublicKey] = None,
        close_authority: Optional[PublicKey] = None
    ):
        self.account_id = account_id
        self.balance = balance
        self.owner = owner
        self.close_authority = close_authority

    @classmethod
    def from_proto(cls, proto: account_pb_v4.AccountInfo) -> 'AccountInfo':
        return cls(
            PublicKey(proto.account_id.value),
            proto.balance,
            PublicKey(proto.owner.value) if proto.owner and proto.owner.value else None,
            PublicKey(proto.close_authority.value) if proto.close_authority and proto.close_authority.value else None,
        )
