import argparse

import kin_base

from agora.client import Client, RetryConfig, Environment
from agora.model import Earn, Invoice, LineItem
from agora.utils import public_key_to_address

ap = argparse.ArgumentParser()
ap.add_argument("-s", "--sender", required=True, help="The private seed of the sender account")
ap.add_argument("-d", "--destinations", required=True,
                help="A comma-delimited list of account public addresses to send earns to (e.g. add1,addr2,add3")
args = vars(ap.parse_args())

retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
client = Client(Environment.TEST, 1, retry_config=retry_config)  # 1 is the test app index

source_kp = kin_base.Keypair.from_seed(args['sender'])

dest_kps = [kin_base.Keypair.from_address(addr) for addr in args['destinations'].split(',')]

# Send an earn batch with 1 Kin each
earns = [Earn(dest_kp.raw_public_key(), 100000) for idx, dest_kp in enumerate(dest_kps)]
batch_result = client.submit_earn_batch(source_kp.raw_seed(), earns)
print("{} succeeded, {} failed".format(len(batch_result.succeeded), len(batch_result.failed)))
for result in batch_result.succeeded:
    print("Sent 1 kin to {} in transaction {}".format(
        public_key_to_address(result.earn.destination),
        result.tx_hash.hex(),
    ))
for result in batch_result.failed:
    print("Failed to send 1 kin to {} in transaction {} (error: {})".format(
        public_key_to_address(result.earn.destination),
        result.tx_hash.hex(),
        repr(result.error),
    ))

# Send an earn batch of earns with 1 Kin each, with invoices
earns = [Earn(dest_kp.raw_public_key(), 100000, invoice=Invoice([LineItem("Payment {}".format(idx), 100000)]))
         for idx, dest_kp in enumerate(dest_kps)]
batch_result = client.submit_earn_batch(source_kp.raw_seed(), earns)
print("{} succeeded, {} failed".format(len(batch_result.succeeded), len(batch_result.failed)))
for result in batch_result.succeeded:
    print("Sent 1 kin to {} in transaction {}".format(
        public_key_to_address(result.earn.destination),
        result.tx_hash.hex()),
    )
for result in batch_result.failed:
    print("Failed to send 1 kin to {} in transaction {} (error: {})".format(
        public_key_to_address(result.earn.destination),
        result.tx_hash.hex(),
        repr(result.error),
    ))
