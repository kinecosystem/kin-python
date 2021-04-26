import base64
from typing import List, Optional

from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.error import InvoiceErrorReason, OperationInvoiceError
from agora.keys import PrivateKey
from agora.model import InvoiceList, ReadOnlyPayment, parse_transaction, Creation


class SignTransactionRequest:
    """A sign transaction request received from Agora.

    :param payments: A list of :class:`ReadOnlyPayment <agora.model.payment.ReadOnlyPayment>` that an app client is
        requesting the server to sign.
    :param transaction: The :class:`Transaction <agora.solana.transaction.Transaction>` object.
    """

    def __init__(
        self, creations: List[Creation], payments: List[ReadOnlyPayment], transaction: solana.Transaction,
    ):
        self.creations = creations
        self.payments = payments
        self.transaction = transaction

    @classmethod
    def from_json(cls, data: dict):
        il_str = data.get('invoice_list')
        if il_str:
            proto_il = model_pb2.InvoiceList()
            proto_il.ParseFromString(base64.b64decode(il_str))
            il = InvoiceList.from_proto(proto_il)
        else:
            il = None

        tx_string = data.get('solana_transaction', "")
        if not tx_string:
            raise ValueError('`solana_transaction` is required on Kin 4 transactions')

        tx = solana.Transaction.unmarshal(base64.b64decode(tx_string))
        creations, payments = parse_transaction(tx, il)
        return cls(creations, payments, tx)

    def get_tx_id(self) -> Optional[bytes]:
        """Returns the transaction id of the transaction in the sign transaction request, if available. The id is
        a 32-byte hash for Stellar transactions and a 64-byte hash for Solana transactions.

        :return: The transaction id, in bytes, or None if the transaction id is not available.
        """
        return self.transaction.get_signature()


class SignTransactionResponse:
    """A response to a sign transaction request received from Agora.
    """

    def __init__(self, transaction: solana.Transaction):
        self.invoice_errors = []
        self.rejected = False
        self.transaction = transaction

    def sign(self, private_key: PrivateKey):
        """Signs the transaction envelope with the provided account private key. No-op on Kin 4 transactions.

        :param private_key: The account :class:`PrivateKey <agora.keys.PrivateKey>`
        """
        if len(self.transaction.signatures) > len(self.transaction.message.accounts):
            raise ValueError('invalid transaction: more signers than accounts')

        # check to see if our public key corresponds to a signer
        if private_key.public_key == self.transaction.message.accounts[0]:
            self.transaction.sign([private_key])

    def reject(self):
        """Marks that the sign transaction request is rejected.
        """
        self.rejected = True

    def mark_invoice_error(self, idx: int, reason: InvoiceErrorReason):
        """Marks that the payment at the provided index was rejected for the provided reason.

        :param idx: The index of the payment.
        :param reason: The :class:`InvoiceErrorReason <agora.error.InvoiceErrorReason>` the payment was rejected.
        :return:
        """
        self.rejected = True
        self.invoice_errors.append(OperationInvoiceError(idx, reason))
