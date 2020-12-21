import argparse
import uuid

import base58

from agora.client import Client, Environment
from agora.error import AccountExistsError, Error, TransactionErrors
from agora.keys import PrivateKey, PublicKey
from agora.model import Payment, TransactionType, Earn
from agora.model.earn import EarnBatch


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

sender = PrivateKey.from_base58(args['sender'])
sender_addr = sender.public_key.to_base58()

try:
    client.create_account(sender)
    print('account created')
except AccountExistsError:
    print(f'account {sender_addr} already exists')

token_accounts = client.resolve_token_accounts(sender.public_key)
print(f'{sender_addr} token accounts: {[a.to_base58() for a in token_accounts]}')

token_account = token_accounts[0]
print(f'balance: {client.get_balance(token_account)}')

# Note: the airdrop service is only available when using Environment.TEST.
print(f'requesting airdrop for {token_account.to_base58()}')
airdrop_resp = client._internal_client.request_airdrop(token_account, int(7e5))

print(f'funded {token_account.to_base58()}')

# use airdrop source as destination for the following transactions
airdrop_source = PublicKey.from_base58("DemXVWQ9DXYsGFpmjFXxki3PE1i3VoHQtqxXQFx38pmU")

# Send a payment of 1 Kin
tx_id = submit_payment(Payment(sender, airdrop_source, TransactionType.NONE, int(1e5)))
print(f'submitted: {base58.b58encode(tx_id)}')

tx_data = client.get_transaction(tx_id)
print(repr(tx_data))

# Send a payment of 1 Kin with a text memo
tx_id = submit_payment(Payment(sender, airdrop_source, TransactionType.NONE, int(1e5), memo='somememo'))
print(f'submitted: {base58.b58encode(tx_id)}')

# Send a payment of 1 Kin using dedupe ID
payment = Payment(sender, airdrop_source, TransactionType.NONE, int(1e5), dedupe_id=uuid.uuid4().bytes)
try:
    tx_id = submit_payment(payment)
except Exception as e:
    # Safe to retry as is since dedupe_id was set
    tx_id = submit_payment(payment)

print(f'submitted: {base58.b58encode(tx_id)}')

tx_data = client.get_transaction(tx_id)
print(repr(tx_data))

# Send earn batch
earns = [Earn(airdrop_source, int(1e5)) for i in range(0, 5)]
batch_result = client.submit_earn_batch(EarnBatch(sender, earns))
if batch_result.tx_error:
    print(f'{batch_result.tx_id} failed with error {repr(batch_result.tx_error)}')

    if batch_result.earn_errors:
        for e in batch_result.earn_errors:
            print(f'earn {e.earn_index} failed with error {repr(e.error)}')
else:
    print(f'{batch_result.tx_id} submitted')

# Send earn batch with dedupe_id
batch = EarnBatch(sender, earns, dedupe_id=uuid.uuid4().bytes)
try:
    batch_result = client.submit_earn_batch(batch)
except Exception as e:
    # Safe to retry as is since dedupe_id was set
    batch_result = client.submit_earn_batch(batch)

if batch_result.tx_error:
    print(f'{batch_result.tx_id} failed with error {repr(batch_result.tx_error)}')

    if batch_result.earn_errors:
        for e in batch_result.earn_errors:
            print(f'earn {e.earn_index} failed with error {repr(e.error)}')
else:
    print(f'{batch_result.tx_id} submitted')

# The client should be closed once it is no longer needed.
client.close()
