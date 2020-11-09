import argparse

from agora.client import Client, Environment
from agora.error import Error, TransactionErrors
from agora.keys import PrivateKey, PublicKey
from agora.model import Invoice, LineItem, Payment, TransactionType
from agora.utils import kin_to_quarks


def submit_payment(p: Payment):
    """Submits a payment and prints the result.
    """
    try:
        tx_hash = client.submit_payment(p)
        print(f'transaction successfully submitted with hash: {tx_hash.hex()}')
    except Error as e:
        print(f'transaction failed: {repr(e)}')
        if isinstance(e, TransactionErrors):
            print(f'tx_error={repr(e.tx_error)}, len(op_errors)={len(e.op_errors)}')
            for op_error in e.op_errors:
                print(f'op_error={repr(op_error)}')


ap = argparse.ArgumentParser()
ap.add_argument('-s', '--sender', required=True, help='The private seed of the sender account')
ap.add_argument('-d', '--destination', required=True, help='The public address of the destination account')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 1)  # 1 is the test app index

source = PrivateKey.from_string(args['sender'])
dest = PublicKey.from_string(args['destination'])

# Send a payment of 1 Kin
payment = Payment(source, dest, TransactionType.EARN, kin_to_quarks('1'))
submit_payment(payment)

# Send a payment of 1 Kin with a text memo
payment = Payment(source, dest, TransactionType.EARN, kin_to_quarks('1'),
                  memo='1-test')
submit_payment(payment)

# Send payment of 1 Kin with an invoice
invoice = Invoice([LineItem('Test Payment', 100000, description='This is a description of the payment',
                            sku=b'some sku')])
payment = Payment(source, dest, TransactionType.EARN, kin_to_quarks('1'),
                  invoice=invoice)
submit_payment(payment)

client.close()
