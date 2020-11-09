import argparse

from agora.client import Client, RetryConfig, Environment
from agora.error import AccountExistsError
from agora.keys import PrivateKey

ap = argparse.ArgumentParser()
ap.add_argument('-s', '--seed', required=True, help='The private seed of the account to create')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 1)  # 1 is the test app index

private_key = PrivateKey.from_string(args['seed'])
print(f'creating account with address {private_key.public_key.stellar_address}')

try:
    client.create_account(private_key)
    print('account created')
except AccountExistsError:
    print(f'account {private_key.public_key.stellar_address} already exists')

client.close()
