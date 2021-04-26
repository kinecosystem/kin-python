import logging
import os
from typing import List

import base58
from flask import Flask, request

from agora.client import Environment
from agora.error import InvoiceErrorReason
from agora.keys import PrivateKey
from agora.webhook.events import Event
from agora.webhook.handler import WebhookHandler, AGORA_HMAC_HEADER, APP_USER_ID_HEADER, APP_USER_PASSKEY_HEADER
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

webhook_secret = os.environ.get("WEBHOOK_SECRET")
webhook_seed = os.environ.get("WEBHOOK_SEED")
webhook_private_key = PrivateKey.from_string(webhook_seed)

webhook_handler = WebhookHandler(Environment.TEST, webhook_secret)


@app.route('/events', methods=['POST'])
def events():
    status_code, body = webhook_handler.handle_events(
        _handle_events,
        request.headers.get(AGORA_HMAC_HEADER),
        request.data.decode('utf-8'),
    )
    return body, status_code


@app.route('/sign_transaction', methods=["POST"])
def sign_transaction():
    user_id = request.headers.get(APP_USER_ID_HEADER)
    user_passkey = request.headers.get(APP_USER_PASSKEY_HEADER)

    logging.debug(f'Received sign transaction request for <`{user_id}`,`{user_passkey}`>')

    status_code, body = webhook_handler.handle_sign_transaction(
        _sign_transaction,
        request.headers.get(AGORA_HMAC_HEADER),
        request.data.decode('utf-8'),
    )
    return body, status_code


def _handle_events(received_events: List[Event]):
    for event in received_events:
        if not event.transaction_event:
            logging.debug(f'received event: {event}')
            continue

        logging.debug(f'transaction completed: {event.transaction_event.tx_id.hex()}')


def _sign_transaction(req: SignTransactionRequest, resp: SignTransactionResponse):
    for idx, payment in enumerate(req.payments):
        # Double check that the transaction crafter isn't trying to impersonate us
        if payment.sender == webhook_private_key.public_key:
            logging.warning('rejecting: payment sender is webhook address')
            resp.reject()
            return

        # In this example, we don't want to sign transactions that are not sending Kin to the webhook account. Other
        # application use cases may not have this restrictions
        if payment.dest != webhook_private_key.public_key:
            logging.warning(f'rejecting: bad destination {payment.destination.stellar_address}, '
                            f'expected {webhook_private_key.public_key.stellar_address}')
            resp.mark_invoice_error(idx, InvoiceErrorReason.WRONG_DESTINATION)

        # If the transaction crafter submitted an invoice, make sure the line item SKUs are set.
        #
        # Note: the SKU is optional, but we simulate a rejection here for testing.
        # Applications may wish to cross-check their own databases for the item being purchased. If the user has already
        # purchased said 'item', they may wish to use mark the invoice error as InvoiceErrorReason.ALREADY_PAID.
        if payment.invoice:
            for line_item in payment.invoice.items:
                if not line_item.sku:
                    logging.warning('rejecting: invoice missing sku')
                    resp.mark_invoice_error(idx, InvoiceErrorReason.SKU_NOT_FOUND)

    tx_id = base58.b58encode(req.get_tx_id())
    if resp.rejected:
        logging.warning(f'transaction rejected: {tx_id} ({len(req.payments)} payments)')
        return

    logging.debug(f'transaction approved: {tx_id} ({len(req.payments)} payments)')

    # Note: This allows Agora to forward the transaction to the blockchain. However, it does not indicate that it will
    # be submitted successfully, or that the transaction will be successful. For example, the sender may have
    # insufficient funds.
    #
    # Backends may keep track of the transaction themselves using SignTransactionRequest.get_tx_hash() and rely on
    # either the Events webhook or polling to get the transaction status.
    resp.sign(webhook_private_key)
    return


if __name__ == '__main__':
    app.run(port=int(os.environ.get('PORT', 8080)))
