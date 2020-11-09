from typing import Optional, List

from agoraapi.common.v3 import model_pb2
from kin_base import transaction_envelope as te, operation, memo

from agora import solana
from agora.keys import PrivateKey, PublicKey
from agora.model.invoice import Invoice
from agora.model.memo import AgoraMemo
from agora.model.transaction_type import TransactionType
from agora.utils import kin_to_quarks


class Payment:
    """The :class:`Payment <Payment>` object, which represents a payment that will get submitted.

    :param sender: The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the account from which funds will be sent.
    :param destination: The :class:`PublicKey <agora.model.keys.PublicKey>` of the account to which funds will be sent.
    :param tx_type: The :class:`TransactionType <agora.model.transaction_type.TransactionType>` of this payment.
    :param quarks: The amount being sent.
    :param channel: (optional) The :class:`PrivateKey <agora.model.keys.PrivateKey>` of the channel account that will be
        used as the source of the transaction. If unset, the `sender` will be used as the transaction source.

        On Stellar, this is where the transaction fee and sequence number is taken/chosen from. This field is irrelevant
        for transactions on Kin 4.
    :param invoice: (optional) An :class:`Invoice <agora.model.invoice.Invoice>` to associate with this payment. Only
        one of invoice or memo should be set.
    :param memo: (optional) The text memo to include with the transaction. Only one of invoice or memo should be set.
    :param subsidizer: (optional) The subsidizer to use for the create account transaction. The subsidizer will be
            used both as the payer of the transaction. Only applicable for Kin 4 transactions.
    """

    def __init__(
        self, sender: PrivateKey, destination: PublicKey, tx_type: TransactionType, quarks: int,
        channel: Optional[PrivateKey] = None, invoice: Optional[Invoice] = None, memo: Optional[str] = None,
        subsidizer: Optional[PrivateKey] = None,
    ):
        self.sender = sender
        self.destination = destination
        self.tx_type = tx_type
        self.quarks = quarks
        self.channel = channel
        self.subsidizer = subsidizer

        if invoice and memo:
            raise ValueError('only one of `invoice` or `memo` can be set, not both')

        self.invoice = invoice
        self.memo = memo

    def __eq__(self, other):
        if not isinstance(other, Payment):
            return False

        return (self.sender == other.sender and
                self.destination == other.destination and
                self.tx_type == other.tx_type and
                self.quarks == other.quarks and
                self.channel == other.channel and
                self.invoice == other.invoice and
                self.memo == other.memo and
                self.subsidizer == other.subsidizer)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'sender={self.sender!r}, destination={self.destination!r}, tx_type={self.tx_type!r}, ' \
               f'quarks={self.quarks}, channel={self.channel!r}, invoice={self.invoice!r}, memo={self.memo!r}), ' \
               f'subsidizer={self.subsidizer!r}'


class ReadOnlyPayment:
    """The :class:`ReadOnlyPayment <ReadOnlyPayment>` object, which represents a payment that was retrieved from
    history.

    :param sender: The :class:`PublicKey <agora.model.keys.PublicKey>` of the sending account.
    :param destination: The :class:`PublicKey <agora.model.keys.PublicKey>` of the destination account.
    :param tx_type: The type of this payment.
    :param quarks: The amount of the payment.
    :param invoice: (optional) The :class:`Invoice <agora.model.invoice.Invoice>` associated with this payment. Only one
        of invoice or memo will be set.
    :param memo: (optional) The text memo associated with this transaction. Only one of invoice or memo will be set.
    """

    def __init__(
        self, sender: PublicKey, destination: PublicKey, tx_type: TransactionType, quarks: int,
        invoice: Optional[Invoice] = None, memo: Optional[str] = None
    ):
        self.sender = sender
        self.destination = destination
        self.tx_type = tx_type
        self.quarks = quarks
        self.invoice = invoice
        self.memo = memo

    def __eq__(self, other):
        if not isinstance(other, ReadOnlyPayment):
            return False

        return (self.sender == other.sender and
                self.destination == other.destination and
                self.tx_type == other.tx_type and
                self.quarks == other.quarks and
                self.invoice == other.invoice and
                self.memo == other.memo)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'sender={self.sender!r}, destination={self.destination!r}, tx_type={self.tx_type!r}, ' \
               f'quarks={self.quarks}, invoice={self.invoice!r}, memo={self.memo!r})'

    @classmethod
    def payments_from_transaction(
        cls, tx: solana.Transaction, invoice_list: Optional[model_pb2.InvoiceList] = None
    ) -> List['ReadOnlyPayment']:
        """Returns a list of read only payments from a Solana transaction.

        :param tx: The transaction.
        :param invoice_list: (optional) A protobuf invoice list associated with the transaction.
        :return: A List of :class:`ReadOnlyPayment <ReadOnlyPayment>` objects.
        """
        text_memo = None
        agora_memo = None
        start_index = 0
        program_idx = tx.message.instructions[0].program_index
        if tx.message.accounts[program_idx] == solana.MEMO_PROGRAM_KEY:
            decompiled_memo = solana.decompile_memo(tx.message, 0)
            start_index = 1
            memo_data = decompiled_memo.data.decode('utf-8')
            try:
                agora_memo = AgoraMemo.from_b64_string(memo_data)
            except ValueError:
                text_memo = memo_data

        transfer_count = (len(tx.message.instructions) - 1 if (text_memo or agora_memo)
                          else len(tx.message.instructions))
        if invoice_list and invoice_list.invoices and len(invoice_list.invoices) != transfer_count:
            raise ValueError(f'number of invoices ({len(invoice_list.invoices)}) does not match number of non-memo '
                             f'transaction instructions ({transfer_count})')

        payments = []
        for idx, op in enumerate(tx.message.instructions[start_index:]):
            try:
                decompiled_transfer = solana.decompile_transfer(tx.message, idx + start_index)
            except ValueError as e:
                continue

            inv = invoice_list.invoices[idx] if invoice_list and invoice_list.invoices else None
            payments.append(ReadOnlyPayment(
                sender=decompiled_transfer.source,
                destination=decompiled_transfer.dest,
                tx_type=agora_memo.tx_type() if agora_memo else TransactionType.UNKNOWN,
                quarks=decompiled_transfer.amount,
                invoice=Invoice.from_proto(inv) if inv else None,
                memo=text_memo if text_memo else None,
            ))

        return payments

    @classmethod
    def payments_from_envelope(
        cls, envelope: te.TransactionEnvelope, invoice_list: Optional[model_pb2.InvoiceList] = None,
        kin_version: Optional[int] = 3, ) -> List['ReadOnlyPayment']:
        """Returns a list of read only payments from a transaction envelope.

        :param envelope: A :class:`TransactionEnvelope <kin_base.transaction_envelope.TransactionEnvelope>.
        :param invoice_list: (optional) A protobuf invoice list associated with the transaction.
        :param kin_version: (optional) The version of Kin to parse payments for.
        :return: A List of :class:`ReadOnlyPayment <ReadOnlyPayment>` objects.
        """
        if invoice_list and invoice_list.invoices and len(invoice_list.invoices) != len(envelope.tx.operations):
            raise ValueError(f'number of invoices ({len(invoice_list.invoices)}) does not match number of transaction '
                             f'operations ({len(envelope.tx.operations)})')

        tx = envelope.tx

        text_memo = None
        agora_memo = None
        if isinstance(tx.memo, memo.HashMemo):
            try:
                agora_memo = AgoraMemo.from_base_memo(tx.memo, False)
            except ValueError:
                pass
        elif isinstance(tx.memo, memo.TextMemo):
            text_memo = tx.memo

        payments = []
        for idx, op in enumerate(envelope.tx.operations):
            # Currently, only payment operations are supported in this method. Eventually, create account and merge
            # account operations could potentially be supported, but currently this is primarily only used for payment
            # operations
            if not isinstance(op, operation.Payment):
                continue

            # Only Kin payment operations are supported in this method.
            if kin_version == 2 and (op.asset.type != 'credit_alphanum4' or op.asset.code != 'KIN'):
                continue

            inv = invoice_list.invoices[idx] if invoice_list and invoice_list.invoices else None

            # Inside the kin_base module, the base currency has been 'scaled' by a factor of 100 from
            # Stellar (i.e., the smallest denomination used is 1e-5 instead of 1e-7). However, Kin 2 uses the minimum
            # Stellar denomination of 1e-7.
            #
            # When parsing an XDR transaction, `kin_base` assumes a smallest denomination of 1e-5. Therefore, for Kin 2
            # transactions, we must divide the resulting amounts by 100 to account for the 100x scaling factor.
            payments.append(ReadOnlyPayment(
                sender=PublicKey.from_string(op.source if op.source else tx.source.decode()),
                destination=PublicKey.from_string(op.destination),
                tx_type=agora_memo.tx_type() if agora_memo else TransactionType.UNKNOWN,
                quarks=int(kin_to_quarks(op.amount) / 100) if kin_version == 2 else kin_to_quarks(op.amount),
                invoice=Invoice.from_proto(inv) if inv else None,
                memo=text_memo.text.decode() if text_memo else None,
            ))

        return payments
