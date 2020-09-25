from typing import Optional, List

from agoraapi.common.v3 import model_pb2 as model_pb

from agora.error import TransactionErrors
from agora.keys import PrivateKey, PublicKey
from agora.model import TransactionData, AccountInfo, InvoiceList

_GRPC_TIMEOUT_SECONDS = 10


class SubmitTransactionResult:
    def __init__(self, tx_hash: Optional[bytes] = None,
                 invoice_errors: Optional[List[model_pb.InvoiceError]] = None,
                 tx_error: Optional[TransactionErrors] = None):
        self.tx_hash = tx_hash if tx_hash else bytes(32)
        self.invoice_errors = invoice_errors if invoice_errors else []
        self.tx_error = tx_error


class InternalClient:
    """A low level client used for interacting with Agora APIs directly. The API for this client is _not_ stable and is
    not intended for general use. It is only exposed in case there needs to be low level access to Agora (beyond the
    gRPC directly). However, there is no stability guarantees between releases, or during a migration event.
    """

    def get_blockchain_version(self) -> int:
        """Get the blockchain version to use.

        :return: the blockchain version
        """
        raise NotImplementedError()

    def create_account(self, private_key: PrivateKey):
        """Submit a request to Agora to create an account.

        :param private_key: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account to create
        """
        raise NotImplementedError()

    def get_account_info(self, public_key: PublicKey) -> AccountInfo:
        """Get the info of an account from Agora.

        :param public_key: The :class:`PublicKey <agora.model.keys.PublicKey>` of the account to request the info for.
        :return: A :class:`AccountInfo <agora.model.account.AccountInfo>` object.
        """
        raise NotImplementedError()

    def get_transaction(self, tx_hash: bytes) -> TransactionData:
        """Get a transaction from Agora.

        :param tx_hash: The hash of the transaction, in bytes.
        :return: A :class:`TransactionData <agora.model.transaction.TransactionData>` object.
        """
        raise NotImplementedError()

    def submit_transaction(self, tx_bytes: bytes, invoice_list: Optional[InvoiceList]) -> SubmitTransactionResult:
        """Submit a transaction to Agora.

        :param tx_bytes: The transaction envelope xdr, in bytes.
        :param invoice_list: (optional) An :class:`InvoiceList <agora.model.invoice.InvoiceList>` to associate with the
            transaction
        :return: A :class:`SubmitTransactionResult <agora.client.internal.SubmitTransactionResult>` object.
        """
        raise NotImplementedError()
