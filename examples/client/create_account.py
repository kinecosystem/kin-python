import argparse

import kin_base

from agora.client import Client, RetryConfig, Environment
from agora.error import AccountExistsError

ap = argparse.ArgumentParser()
ap.add_argument("-s", "--seed", required=True, help="The private seed of the account to create")
args = vars(ap.parse_args())

retry_config = RetryConfig(max_retries=0, min_delay=0, max_delay=0, max_nonce_refreshes=0)
client = Client(Environment.TEST, 1, retry_config=retry_config)  # 1 is the test app index

kp = kin_base.Keypair.from_seed(args['seed'])
print("creating account with address {}".format(kp.address()))

try:
    client.create_account(kp.raw_seed())
    print("account created")
except AccountExistsError:
    print("account {} already exists".format(kp.address()))
