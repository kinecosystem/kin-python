import argparse

import base58

from agora.client import Client, Environment
from agora.error import AccountExistsError, Error, TransactionErrors
from agora.keys import PrivateKey, PublicKey
from agora.model import Payment, TransactionType, Earn
from agora.solana import Commitment


def submit_payment(p: Payment):
    """Submits a payment and prints the result.
    """
    try:
        return client.submit_payment(p)
    except Error as e:
        print(f'transaction failed: {repr(e)}')
        if isinstance(e, TransactionErrors):
            print(f'tx_error={repr(e.tx_error)}, len(op_errors)={len(e.op_errors)}')
            for op_error in e.op_errors:
                print(f'op_error={repr(op_error)}')


ap = argparse.ArgumentParser()
ap.add_argument('-s', '--sender', required=True, help='The base58-encoded private seed of the sender account')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 0, kin_version=4)

sender = PrivateKey(base58.b58decode(args['sender']))
sender_addr = base58.b58encode(sender.public_key.raw).decode('utf-8')

try:
    client.create_account(sender)
    print('account created')
except AccountExistsError:
    print(f'account {sender_addr} already exists')

print(f'balance: {client.get_balance(sender.public_key)}')

print(f'requesting airdrop for {sender_addr}')
airdrop_resp = client._internal_client.request_airdrop(sender.public_key, int(3e5))

print(f'funded {sender_addr}')

# use airdrop source as destination for the following transactions
airdrop_source = PublicKey(base58.b58decode("DemXVWQ9DXYsGFpmjFXxki3PE1i3VoHQtqxXQFx38pmU"))

# Send a payment of 1 Kin
tx_id = submit_payment(Payment(sender, airdrop_source, TransactionType.NONE, int(1e5)))
print(f'submitted: {base58.b58encode(tx_id)}')

tx_data = client.get_transaction(tx_id)
print(repr(tx_data))

# Send a payment of 1 Kin with a text memo
tx_id = submit_payment(Payment(sender, airdrop_source, TransactionType.NONE, int(1e5), memo='somememo'))
print(f'submitted: {base58.b58encode(tx_id)}')

tx_data = client.get_transaction(tx_id)
print(repr(tx_data))

print(f'balance: {client.get_balance(sender.public_key)}')

# Send earn batch
earns = [Earn(airdrop_source, int(1e5)) for i in range(0, 5)]
batch_result = client.submit_earn_batch(sender, earns)
print(f'{len(batch_result.succeeded)} succeeded, {len(batch_result.failed)} failed')
for result in batch_result.succeeded:
    print(f'Sent 1 kin to {result.earn.destination.stellar_address} in transaction '
          f'{base58.b58encode(result.transaction_id)}')
for result in batch_result.failed:
    print(f'Failed to send 1 kin to {result.earn.destination.stellar_address} in transaction '
          f'{base58.b58encode(result.transaction_id)} (error: {repr(result.error)})')

print(f'balance: {client.get_balance(sender.public_key, commitment=Commitment.ROOT)}')

# The client should be closed once it is no longer needed.
client.close()
