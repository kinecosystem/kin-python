import base64
from typing import List, Optional

import kin_base
from agoraapi.common.v3 import model_pb2
from kin_base import transaction_envelope as te

from agora.error import InvoiceErrorReason, OperationInvoiceError
from agora.model.invoice import InvoiceList
from agora.model.keys import PrivateKey
from agora.model.payment import ReadOnlyPayment


class SignTransactionRequest:
    """A sign transaction request received from Agora.

    :param payments: A list of :class:`ReadOnlyPayment <agora.model.payment.ReadOnlyPayment>` that an app client is
        requesting the server to sign.
    :param kin_version: The version of Kin this transaction is using.
    :param envelope: (optional) The :class:`TransactionEnvelope <kin_base.transaction_envelope.TransactionEnvelope>`
        object. Only set on Stellar transactions.
    """

    def __init__(
        self, payments: List[ReadOnlyPayment], kin_version: int, envelope: Optional[te.TransactionEnvelope] = None,
    ):
        self.payments = payments
        self.kin_version = kin_version
        self.envelope = envelope

    @classmethod
    def from_json(cls, data: dict):
        envelope_xdr = data.get('envelope_xdr', "")
        if len(envelope_xdr) == 0:
            raise ValueError('envelope_xdr is required')
        env = te.TransactionEnvelope.from_xdr(envelope_xdr)

        kin_version = data.get('kin_version')
        if not kin_version:
            raise ValueError('kin_version is required')

        il_str = data.get('invoice_list')
        if il_str:
            proto_il = model_pb2.InvoiceList()
            proto_il.ParseFromString(base64.b64decode(il_str))
            il = InvoiceList.from_proto(proto_il)
        else:
            il = None

        return cls(ReadOnlyPayment.payments_from_envelope(env, il), kin_version, envelope=env)

    def get_tx_hash(self) -> bytes:
        """Returns the transaction hash of the transaction being signed.

        :return: The transaction hash, in bytes.
        """
        return self.envelope.hash_meta()


class SignTransactionResponse:
    """A response to a sign transaction request received from Agora. 
    
    :param envelope: (optional) The :class:`TransactionEnvelope <kin_base.transaction_envelope.TransactionEnvelope>`
        object.
    """

    def __init__(self, envelope: te.TransactionEnvelope):
        self.envelope = envelope
        self.invoice_errors = []
        self.rejected = False

    def sign(self, private_key: PrivateKey):
        """Signs the transaction envelope with the provided account private key.

        :param private_key: The account :class:`PrivateKey <agora.model.keys.PrivateKey`
        """
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

        return {
            'envelope_xdr': self.envelope.xdr().decode()
        }
