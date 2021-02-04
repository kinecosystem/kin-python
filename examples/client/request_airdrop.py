import argparse

from agora.client import Client, Environment
from agora.keys import PublicKey
from agora.utils import kin_to_quarks

ap = argparse.ArgumentParser()
ap.add_argument('-s', '--destination', required=True,
                help='The base58-encoded Kin token account address of the airdrop destination account')
args = vars(ap.parse_args())

client = Client(Environment.TEST, 1)  # 1 is the test app index

dest = PublicKey.from_base58(args['destination'])

print(f'requesting airdrop for {dest.to_base58()}')
# Note: the airdrop service is only available when using Environment.TEST.
airdrop_resp = client.request_airdrop(dest, kin_to_quarks("5"))

print(f'funded {dest.to_base58()} with {5} Kin')

# The client should be closed once it is no longer needed.
client.close()
