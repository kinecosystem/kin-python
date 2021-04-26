from typing import Optional, List, Tuple

from agoraapi.common.v3 import model_pb2

from agora import solana
from agora.solana import memo, token, system
from .creation import Creation
from .invoice import InvoiceList, Invoice
from .memo import AgoraMemo
from .payment import ReadOnlyPayment
from .transaction_type import TransactionType


def parse_transaction(
    tx: solana.Transaction, invoice_list: Optional[model_pb2.InvoiceList] = None
) -> Tuple[List[Creation], List[ReadOnlyPayment]]:
    """Parses payments and creations from a Solana transaction.

    :param tx: The transaction.
    :param invoice_list: (optional) A protobuf invoice list associated with the transaction.
    :return: A Tuple containing a List of :class:`ReadOnlyPayment <agora.model.payment.ReadOnlyPayment>` objects and a
        List of :class:`Creation <agora.model.creation.Creation>` objects.
    """
    payments = []
    creations = []

    invoice_hash = None
    if invoice_list:
        invoice_hash = InvoiceList.from_proto(invoice_list).get_sha_224_hash()

    text_memo = None
    agora_memo = None

    il_ref_count = 0
    invoice_transfers = 0

    has_earn = False
    has_spend = False
    has_p2p = False

    app_index = 0
    app_id = None

    i = 0
    while i < len(tx.message.instructions):
        if _is_memo(tx, i):
            decompiled_memo = solana.decompile_memo(tx.message, i)
            memo_data = decompiled_memo.data.decode('utf-8')

            # Attempt to pull out an app ID or app index from the memo data.
            #
            # If either are set, then we ensure that it's either the first value for the transaction, or that it's the
            # same as a previously parsed one.
            #
            # Note: if both an app id and app index get parsed, we do not verify that they match to the same app. We
            # leave that up to the user of this SDK.
            try:
                agora_memo = AgoraMemo.from_b64_string(memo_data)
            except ValueError:
                text_memo = memo_data

            if text_memo:
                try:
                    parsed_id = app_id_from_text_memo(text_memo)
                except ValueError:
                    i += 1
                    continue

                if app_id and parsed_id != app_id:
                    raise ValueError('multiple app IDs')

                app_id = parsed_id
                i += 1
                continue

            # From this point on we can assume we have an agora memo
            fk = agora_memo.foreign_key()
            if invoice_hash and fk[:28] == invoice_hash and fk[28] == 0:
                il_ref_count += 1

            if 0 < app_index != agora_memo.app_index():
                raise ValueError('multiple app indexes')

            app_index = agora_memo.app_index()
            if agora_memo.tx_type() == TransactionType.EARN:
                has_earn = True
            elif agora_memo.tx_type() == TransactionType.SPEND:
                has_spend = True
            elif agora_memo.tx_type() == TransactionType.P2P:
                has_p2p = True

        elif _is_system(tx, i):
            create = system.decompile_create_account(tx.message, i)
            if create.owner != token.PROGRAM_KEY:
                raise ValueError('System::CreateAccount must assign owner to the SplToken program')
            if create.size != token.ACCOUNT_SIZE:
                raise ValueError('invalid size in System::CreateAccount')

            i += 1
            if i == len(tx.message.instructions):
                raise ValueError('missing SplToken::InitializeAccount instruction')

            initialize = token.decompile_initialize_account(tx.message, i)
            if create.address != initialize.account:
                raise ValueError('SplToken::InitializeAccount address does not match System::CreateAccount address')

            i += 1
            if i == len(tx.message.instructions):
                raise ValueError('missing SplToken::SetAuthority(Close) instruction')

            close_authority = token.decompile_set_authority(tx.message, i)
            if close_authority.authority_type != token.AuthorityType.CLOSE_ACCOUNT:
                raise ValueError('SplToken::SetAuthority must be of type Close following an initialize')
            if close_authority.account != create.address:
                raise ValueError('SplToken::SetAuthority(Close) authority must be for the created account')

            if close_authority.new_authority != create.funder:
                raise ValueError('SplToken::SetAuthority has incorrect new authority')

            # Changing of the account holder is optional
            i += 1
            if i == len(tx.message.instructions):
                creations.append(Creation(initialize.owner, initialize.account))
                break

            try:
                account_holder = token.decompile_set_authority(tx.message, i)
            except ValueError:
                creations.append(Creation(initialize.owner, initialize.account))
                continue

            if account_holder.authority_type != token.AuthorityType.ACCOUNT_HOLDER:
                raise ValueError('SplToken::SetAuthority must be of type AccountHolder following a close authority')
            if account_holder.account != create.address:
                raise ValueError('SplToken::SetAuthority(AccountHolder) must be for the created account')

            creations.append(Creation(account_holder.new_authority, initialize.account))
        elif _is_spl_assoc(tx, i):
            create = token.decompile_create_associated_account(tx.message, i)

            i += 1
            if i == len(tx.message.instructions):
                raise ValueError('missing SplToken::SetAuthority(Close) instruction')

            close_authority = token.decompile_set_authority(tx.message, i)
            if close_authority.authority_type != token.AuthorityType.CLOSE_ACCOUNT:
                raise ValueError('SplToken::SetAuthority must be of type Close following an assoc creation')

            if close_authority.account != create.address:
                raise ValueError('SplToken::SetAuthority(Close) authority must be for the created account')

            if close_authority.new_authority != create.subsidizer:
                raise ValueError('SplToken::SetAuthority has incorrect new authority')

            creations.append(Creation(create.owner, create.address))
        elif _is_spl(tx, i):
            cmd = token.get_command(tx.message, i)
            if cmd == token.Command.TRANSFER:
                transfer = token.decompile_transfer(tx.message, i)

                # TODO: maybe don't need this check here?
                # Ensure that the transfer doesn't reference the subsidizer
                if transfer.owner == tx.message.accounts[0]:
                    raise ValueError('cannot transfer from a subsidizer-owned account')

                inv = None
                if agora_memo:
                    fk = agora_memo.foreign_key()
                    if invoice_hash and fk[:28] == invoice_hash and fk[28] == 0:
                        # If the number of parsed transfers matching this invoice is >= the number of invoices,
                        # raise an error
                        if invoice_transfers >= len(invoice_list.invoices):
                            raise ValueError(
                                f'invoice list doesn\'t have sufficient invoices for this transaction (parsed: {invoice_transfers}, invoices: {len(invoice_list.invoices)})')
                        inv = invoice_list.invoices[invoice_transfers]
                        invoice_transfers += 1

                payments.append(ReadOnlyPayment(
                    transfer.source,
                    transfer.dest,
                    tx_type=agora_memo.tx_type() if agora_memo else TransactionType.UNKNOWN,
                    quarks=transfer.amount,
                    invoice=Invoice.from_proto(inv) if inv else None,
                    memo=text_memo if text_memo else None
                ))
            elif cmd != token.Command.CLOSE_ACCOUNT:
                # closures are valid, but otherwise the instruction is not supported
                raise ValueError(f'unsupported instruction at {i}')
        else:
            raise ValueError(f'unsupported instruction at {i}')

        i += 1

    if has_earn and (has_spend or has_p2p):
        raise ValueError('cannot mix earns with P2P/spends')

    if invoice_list and il_ref_count != 1:
        raise ValueError(f'invoice list does not match to exactly one memo in the transaction (matched {il_ref_count})')

    if invoice_list and len(invoice_list.invoices) != invoice_transfers:
        raise ValueError(f'invoice count ({len(invoice_list.invoices)}) does not match number of transfers referencing '
                         f'the invoice list ({invoice_transfers})')

    return creations, payments


def _is_memo(tx: solana.Transaction, index: int) -> bool:
    return tx.message.accounts[tx.message.instructions[index].program_index] == memo.PROGRAM_KEY


def _is_spl(tx: solana.Transaction, index: int) -> bool:
    return tx.message.accounts[tx.message.instructions[index].program_index] == token.PROGRAM_KEY


def _is_spl_assoc(tx: solana.Transaction, index: int) -> bool:
    return tx.message.accounts[tx.message.instructions[index].program_index] == \
           token.ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_KEY


def _is_system(tx: solana.transaction, index: int) -> bool:
    return tx.message.accounts[tx.message.instructions[index].program_index] == system.PROGRAM_KEY


def app_id_from_text_memo(text_memo: str) -> str:
    parts = text_memo.split('-')
    if len(parts) < 2:
        raise ValueError('no app id in memo')

    if parts[0] != "1":
        raise ValueError('no app id in memo')

    if not is_valid_app_id(parts[1]):
        raise ValueError('no valid app id in memo')

    return parts[1]


def is_valid_app_id(app_id: str) -> bool:
    if len(app_id) < 3 or len(app_id) > 4:
        return False

    if not app_id.isalnum():
        return False

    return True
