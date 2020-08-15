import argparse

from agora.client import Client, RetryConfig, Environment
from agora.error import Error, TransactionErrors
from agora.model import Invoice, LineItem, Payment, TransactionType, PrivateKey, PublicKey
from agora.utils import kin_to_quarks


def submit_payment(p: Payment):
    """Submits a payment and prints the result.
    """
    try:
        tx_hash = client.submit_payment(p)
        print("transaction successfully submitted with hash: {}".format(tx_hash.hex()))
    except Error as e:
        print("transaction failed: {}".format(repr(e)))
        if isinstance(e, TransactionErrors):
            print("tx_error={}, len(op_errors)={}".format(repr(e.tx_error), len(e.op_errors)))
            for op_error in e.op_errors:
                print("op_error={}".format(repr(op_error)))


ap = argparse.ArgumentParser()
ap.add_argument("-s", "--sender", required=True, help="The private seed of the sender account")
ap.add_argument("-d", "--destination", required=True, help="The public address of the destination account")
args = vars(ap.parse_args())

retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
client = Client(Environment.TEST, 1, retry_config=retry_config)  # 1 is the test app index

source = PrivateKey.from_string(args['sender'])
dest = PublicKey.from_string(args['destination'])

# Send a payment of 1 Kin
payment = Payment(source, dest, TransactionType.EARN, kin_to_quarks("1"))
submit_payment(payment)

# Send a payment of 1 Kin with a text memo
payment = Payment(source, dest, TransactionType.EARN, kin_to_quarks("1"),
                  memo='1-test')
submit_payment(payment)

# Send payment of 1 Kin with an invoice
invoice = Invoice([LineItem("Test Payment", 100000, description="This is a description of the payment",
                            sku=b'some sku')])
payment = Payment(source, dest, TransactionType.EARN, kin_to_quarks("1"),
                  invoice=invoice)
submit_payment(payment)
