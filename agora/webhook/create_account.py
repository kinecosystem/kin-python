import base64

from agora import solana
from agora.keys import PrivateKey
from agora.model import Creation
from agora.model.utils import parse_transaction


class CreateAccountRequest:
    """A create account request received from Agora.

    :param creation: The :class:`Creation <agora.model.creation.Creation>` an app client is requesting the server to
        verify.
    :param transaction: The :class:`Transaction <agora.solana.transaction.Transaction>` object.
    """

    def __init__(self, creation: Creation, transaction: solana.Transaction):
        self.creation = creation
        self.transaction = transaction

    @classmethod
    def from_json(cls, data: dict):
        kin_version = data.get('kin_version', 4)
        if kin_version != 4:
            raise ValueError(f'unsupported kin version {kin_version}')

        tx_string = data.get('solana_transaction', "")
        if not tx_string:
            raise ValueError('`solana_transaction` is required')

        tx = solana.Transaction.unmarshal(base64.b64decode(tx_string))
        creations, payments = parse_transaction(tx)
        if len(payments) != 0:
            raise ValueError('unexpected payments present')
        if len(creations) != 1:
            raise ValueError(f'expected exactly 1 creation, got {len(creations)}')

        return cls(creations[0], tx)


class CreateAccountResponse:
    def __init__(self, transaction: solana.Transaction):
        self.rejected = False
        self.transaction = transaction

    def sign(self, private_key: PrivateKey):
        if len(self.transaction.signatures) > len(self.transaction.message.accounts):
            raise ValueError('invalid transaction: more signers than accounts')

        # Check to see if our public key corresponds to a signer before signing
        if private_key.public_key == self.transaction.message.accounts[0]:
            self.transaction.sign([private_key])

    def reject(self):
        self.rejected = True
