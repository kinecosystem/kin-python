import argparse

from agora.client import Client, Environment
from agora.keys import PrivateKey, PublicKey
from agora.model import Earn, Invoice, LineItem
from agora.utils import kin_to_quarks

ap = argparse.ArgumentParser()
ap.add_argument('-s', '--sender', required=True, help='The private seed of the sender account')
ap.add_argument('-d', '--destinations', required=True,
                help='A comma-delimited list of account public addresses to send earns to (e.g. add1,addr2,add3')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 1)  # 1 is the test app index

source = PrivateKey.from_string(args['sender'])
destinations = [PublicKey.from_string(addr) for addr in args['destinations'].split(',')]

# Send an earn batch with 1 Kin each
earns = [Earn(dest, kin_to_quarks('1')) for idx, dest in enumerate(destinations)]
batch_result = client.submit_earn_batch(source, earns)
print(f'{len(batch_result.succeeded)} succeeded, {len(batch_result.failed)} failed')
for result in batch_result.succeeded:
    print(f'Sent 1 kin to {result.earn.destination.stellar_address} in transaction {result.tx_id.hex()}')
for result in batch_result.failed:
    print(
        f'Failed to send 1 kin to {result.earn.destination.stellar_address} in transaction {result.tx_id.hex()} '
        f'(error: {repr(result.error)})')

# Send an earn batch of earns with 1 Kin each, with invoices
earns = [Earn(dest, kin_to_quarks('1'), invoice=Invoice([LineItem(f'Payment {idx}', kin_to_quarks('1'))]))
         for idx, dest in enumerate(destinations)]
batch_result = client.submit_earn_batch(source, earns)
print(f'{len(batch_result.succeeded)} succeeded, {len(batch_result.failed)} failed')
for result in batch_result.succeeded:
    print(f'Sent 1 kin to {result.earn.destination.stellar_address} in transaction {result.tx_id.hex()}',
          )
for result in batch_result.failed:
    print(
        f'Failed to send 1 kin to {result.earn.destination.stellar_address} in transaction {result.tx_id.hex()} '
        f'(error: {repr(result.error)})')

client.close()
