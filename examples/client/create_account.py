import argparse

from agora.client import Client, Environment
from agora.error import AccountExistsError
from agora.keys import PrivateKey

ap = argparse.ArgumentParser()
ap.add_argument('-s', '--seed', required=True, help='The base58-encoded private seed of the account to create')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 1)  # 1 is the test app index

private_key = PrivateKey.from_base58(args['seed'])
addr = private_key.public_key.to_base58()
print(f'creating account with address {addr}')

try:
    client.create_account(private_key)
    print('account created')
except AccountExistsError:
    print(f'account {private_key.public_key.to_base58()} already exists')

token_accounts = client.resolve_token_accounts(private_key.public_key)
for token_account in token_accounts:
    print(f'balance of {token_account.to_base58()}: {client.get_balance(token_account)}')

client.close()
