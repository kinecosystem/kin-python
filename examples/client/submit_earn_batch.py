import argparse
import uuid

from agora.client import Client, Environment
from agora.keys import PrivateKey, PublicKey
from agora.model import Earn, Invoice, LineItem
from agora.model.earn import EarnBatch
from agora.utils import kin_to_quarks

ap = argparse.ArgumentParser()
ap.add_argument('-s', '--sender', required=True, help='The base58-encoded private seed of the sender account')
ap.add_argument('-d', '--destinations', required=True,
                help='A comma-delimited list of base58-encoded account addresses to send earns to '
                     '(e.g. add1,addr2,add3)')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 1)  # 1 is the test app index

source = PrivateKey.from_base58(args['sender'])
destinations = [PublicKey.from_base58(addr) for addr in args['destinations'].split(',')]

# Send an earn batch with 1 Kin each
earns = [Earn(dest, kin_to_quarks('1')) for idx, dest in enumerate(destinations)]
batch_result = client.submit_earn_batch(EarnBatch(source, earns))
if batch_result.tx_error:
    print(f'{batch_result.tx_id} failed with error {repr(batch_result.tx_error)}')

    if batch_result.earn_errors:
        for e in batch_result.earn_errors:
            print(f'earn {e.earn_index} failed with error {repr(e.error)}')
else:
    print(f'{batch_result.tx_id} submitted')

# Send an earn batch of earns with 1 Kin each, with invoices
earns = [Earn(dest, kin_to_quarks('1'), invoice=Invoice([LineItem(f'Payment {idx}', kin_to_quarks('1'))]))
         for idx, dest in enumerate(destinations)]
batch_result = client.submit_earn_batch(EarnBatch(source, earns))
if batch_result.tx_error:
    print(f'{batch_result.tx_id} failed with error {repr(batch_result.tx_error)}')

    if batch_result.earn_errors:
        for e in batch_result.earn_errors:
            print(f'earn {e.earn_index} failed with error {repr(e.error)}')
else:
    print(f'{batch_result.tx_id} submitted')

# Send earn batch with dedupe_id
batch = EarnBatch(source, earns, dedupe_id=uuid.uuid4().bytes)
try:
    batch_result = client.submit_earn_batch(batch)
except Exception as e:
    # Safe to resubmit as is since dedupe_id was set
    batch_result = client.submit_earn_batch(batch)

if batch_result.tx_error:
    print(f'{batch_result.tx_id} failed with error {repr(batch_result.tx_error)}')

    if batch_result.earn_errors:
        for e in batch_result.earn_errors:
            print(f'earn {e.earn_index} failed with error {repr(e.error)}')
else:
    print(f'{batch_result.tx_id} submitted')

client.close()
