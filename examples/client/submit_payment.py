import argparse

import kin_base

from agora.client.client import Client, RetryConfig
from agora.client.environment import Environment
from agora.error import Error, TransactionError
from agora.model.invoice import Invoice, LineItem
from agora.model.payment import Payment
from agora.model.transaction_type import TransactionType


def submit_payment(p: Payment):
    """Submits a payment and prints the result.
    """
    try:
        tx_hash = client.submit_payment(p)
        print("transaction successfully submitted with hash: {}".format(tx_hash.hex()))
    except Error as e:
        print("transaction failed: {}".format(repr(e)))
        if isinstance(e, TransactionError):
            print("tx_error={}, len(op_errors)={}".format(repr(e.tx_error), len(e.op_errors)))
            for op_error in e.op_errors:
                print("op_error={}".format(repr(op_error)))


ap = argparse.ArgumentParser()
ap.add_argument("-s", "--sender", required=True, help="The private seed of the sender account")
ap.add_argument("-d", "--destination", required=True, help="The public address of the destination account")
args = vars(ap.parse_args())

retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
client = Client(Environment.TEST, 1, retry_config=retry_config)  # 1 is the test app index

source_kp = kin_base.Keypair.from_seed(args['sender'])
dest_kp = kin_base.Keypair.from_address(args['destination'])

# Send a payment of 1 Kin
payment = Payment(source_kp.raw_seed(), dest_kp.raw_public_key(), TransactionType.EARN, 100000)
submit_payment(payment)

# Send a payment of 1 Kin with a text memo
payment = Payment(source_kp.raw_seed(), dest_kp.raw_public_key(), TransactionType.EARN, 100000,
                  memo='1-test')
submit_payment(payment)

# Send payment of 1 Kin with an invoice
invoice = Invoice([LineItem("Test Payment", 100000, description="This is a description of the payment",
                            sku=b'some sku')])
payment = Payment(source_kp.raw_seed(), dest_kp.raw_public_key(), TransactionType.EARN, 100000,
                  invoice=invoice)
submit_payment(payment)
