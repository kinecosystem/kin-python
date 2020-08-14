import argparse

from agora.client import Client, RetryConfig, Environment
from agora.error import AccountExistsError
from agora.model import PrivateKey

ap = argparse.ArgumentParser()
ap.add_argument("-s", "--seed", required=True, help="The private seed of the account to create")
args = vars(ap.parse_args())

retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
client = Client(Environment.TEST, 1, retry_config=retry_config)  # 1 is the test app index

private_key = PrivateKey.from_string(args['seed'])
print("creating account with address {}".format(private_key.public_key.address))

try:
    client.create_account(private_key)
    print("account created")
except AccountExistsError:
    print("account {} already exists".format(private_key.public_key.address))
