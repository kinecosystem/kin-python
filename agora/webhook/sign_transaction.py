import base64
from typing import List, Optional

import kin_base
from agoraapi.common.v3 import model_pb2
from kin_base import transaction_envelope as te

from agora import KIN_2_PROD_NETWORK, KIN_2_TEST_NETWORK, solana
from agora.client import Environment
from agora.error import InvoiceErrorReason, OperationInvoiceError
from agora.keys import PrivateKey
from agora.model import InvoiceList, ReadOnlyPayment
from agora.utils import envelope_from_xdr


class SignTransactionRequest:
    """A sign transaction request received from Agora.

    :param payments: A list of :class:`ReadOnlyPayment <agora.model.payment.ReadOnlyPayment>` that an app client is
        requesting the server to sign.
    :param kin_version: The version of Kin this transaction is using.
    :param envelope: (optional) The :class:`TransactionEnvelope <kin_base.transaction_envelope.TransactionEnvelope>`
        object. Only set on Stellar transactions.

        Note: for Kin 2 transactions, Kin amounts inside the envelope will appear to be 100x larger than they are in
        reality. This is due to the fact that the `kin_base` module (which is used to parse the Stellar envelope XDR
        string) assumes a smallest denomination of 1e-5, but Kin 2 has a smallest denomination of 1e-7. An accurate
        representation of the amounts can be found inside `payments`.
    :param transaction: (optional) The :class:`Transaction <agora.solana.transaction.Transaction>` object. Only set on
        Solana transactions.
    """

    def __init__(
        self, payments: List[ReadOnlyPayment], kin_version: int, envelope: Optional[te.TransactionEnvelope] = None,
        transaction: [solana.Transaction] = None,
    ):
        self.payments = payments
        self.kin_version = kin_version
        self.envelope = envelope
        self.transaction = transaction

    @classmethod
    def from_json(cls, data: dict, environment: Environment):
        kin_version = data.get('kin_version')
        if not kin_version:
            kin_version = 3

        il_str = data.get('invoice_list')
        if il_str:
            proto_il = model_pb2.InvoiceList()
            proto_il.ParseFromString(base64.b64decode(il_str))
            il = InvoiceList.from_proto(proto_il)
        else:
            il = None

        if kin_version == 4:
            tx_string = data.get('solana_transaction', "")
            if not tx_string:
                raise ValueError('`solana_transaction` is required on Kin 4 transactions')

            tx = solana.Transaction.unmarshal(base64.b64decode(tx_string))
            return cls(ReadOnlyPayment.payments_from_transaction(tx, il), kin_version, transaction=tx)
        else:
            # Kin 2 or Kin 3 transaction
            envelope_xdr = data.get('envelope_xdr', "")
            if len(envelope_xdr) == 0:
                raise ValueError('envelope_xdr is required')

            if kin_version == 2:
                network_id = KIN_2_PROD_NETWORK if environment == Environment.PRODUCTION else KIN_2_TEST_NETWORK
                env = envelope_from_xdr(network_id, envelope_xdr)
            else:
                network_id = 'PUBLIC' if environment == Environment.PRODUCTION else 'TESTNET'
                env = envelope_from_xdr(network_id, envelope_xdr)

            return cls(ReadOnlyPayment.payments_from_envelope(env, il, kin_version=kin_version), kin_version,
                       envelope=env)

    def get_tx_hash(self) -> Optional[bytes]:
        """Returns the transaction hash of the transaction being signed, if it is a Stellar transaction.

        This method has been deprecated. New code should use :method:`SignTransactionRequest.get_tx_id`
        instead.

        :return: The transaction hash, in bytes, or None if no transaction envelope is available.
        """
        return self.envelope.hash_meta() if self.envelope else None

    def get_tx_id(self) -> Optional[bytes]:
        """Returns the transaction id of the transaction in the sign transaction request, if available. The id is
        a 32-byte hash for Stellar transactions and a 64-byte hash for Solana transactions.

        :return: The transaction id, in bytes, or None if the transaction id is not available.
        """
        if self.transaction:
            return self.transaction.get_signature()
        if self.envelope:
            return self.envelope.hash_meta()


class SignTransactionResponse:
    """A response to a sign transaction request received from Agora. 
    
    :param envelope: (optional) The :class:`TransactionEnvelope <kin_base.transaction_envelope.TransactionEnvelope>`
        object. Only set on Stellar transactions.
    """

    def __init__(self, envelope: Optional[te.TransactionEnvelope] = None):
        self.envelope = envelope
        self.invoice_errors = []
        self.rejected = False

    def sign(self, private_key: PrivateKey):
        """Signs the transaction envelope with the provided account private key. No-op on Kin 4 transactions.

        :param private_key: The account :class:`PrivateKey <agora.model.keys.PrivateKey>`
        """
        if self.envelope:
            kp = kin_base.Keypair.from_raw_seed(private_key.raw)
            self.envelope.sign(kp)

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

    def to_json(self):
        if self.rejected:
            resp = {}
            if self.invoice_errors:
                resp['invoice_errors'] = [e.to_json() for e in self.invoice_errors]
            return resp

        resp = {}
        if self.envelope:
            resp['envelope_xdr'] = self.envelope.xdr().decode()

        return resp
