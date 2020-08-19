import argparse

from agora.client import Client, RetryConfig, Environment
from agora.model import Earn, Invoice, LineItem, PrivateKey, PublicKey
from agora.utils import kin_to_quarks

ap = argparse.ArgumentParser()
ap.add_argument("-s", "--sender", required=True, help="The private seed of the sender account")
ap.add_argument("-d", "--destinations", required=True,
                help="A comma-delimited list of account public addresses to send earns to (e.g. add1,addr2,add3")
args = vars(ap.parse_args())

retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
client = Client(Environment.TEST, 1, retry_config=retry_config)  # 1 is the test app index

source = PrivateKey.from_string(args['sender'])
destinations = [PublicKey.from_string(addr) for addr in args['destinations'].split(',')]

# Send an earn batch with 1 Kin each
earns = [Earn(dest, kin_to_quarks("1")) for idx, dest in enumerate(destinations)]
batch_result = client.submit_earn_batch(source, earns)
print("{} succeeded, {} failed".format(len(batch_result.succeeded), len(batch_result.failed)))
for result in batch_result.succeeded:
    print("Sent 1 kin to {} in transaction {}".format(
        result.earn.destination.stellar_address,
        result.tx_hash.hex(),
    ))
for result in batch_result.failed:
    print("Failed to send 1 kin to {} in transaction {} (error: {})".format(
        result.earn.destination.stellar_address,
        result.tx_hash.hex(),
        repr(result.error),
    ))

# Send an earn batch of earns with 1 Kin each, with invoices
earns = [Earn(dest, kin_to_quarks("1"), invoice=Invoice([LineItem("Payment {}".format(idx), kin_to_quarks("1"))]))
         for idx, dest in enumerate(destinations)]
batch_result = client.submit_earn_batch(source, earns)
print("{} succeeded, {} failed".format(len(batch_result.succeeded), len(batch_result.failed)))
for result in batch_result.succeeded:
    print("Sent 1 kin to {} in transaction {}".format(
        result.earn.destination.stellar_address,
        result.tx_hash.hex()),
    )
for result in batch_result.failed:
    print("Failed to send 1 kin to {} in transaction {} (error: {})".format(
        result.earn.destination.stellar_address,
        result.tx_hash.hex(),
        repr(result.error),
    ))

client.close()
