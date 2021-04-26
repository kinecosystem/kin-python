# Kin Python SDK

The Kin Python SDK enables developers use Kin inside their backend servers. It contains support for blockchain actions 
such as creating accounts and sending payments, as well a webhook handler class to assist with implementing Agora webhooks. 

## Requirements
Python 3.6 or higher

## Installation
```
pip install kin-sdk-v2
```

## Overview
The SDK contains two main components: the `Client` and the `WebhookHandler`. The `Client` is used for blockchain
actions, such as creating accounts sending payments, while the `WebhookHandler` is meant for developers who wish to make
use of Agora Webhooks. It is recommended that developers read the [website documentation](https://docs.kin.org) prior to using this SDK.



## Client
The main component of this library is the `Client` class, which facilitates access to the Kin blockchain. 

### Initialization
At a minimum, the client needs to be instantiated with an `Environment`.

```python
from agora.client import Client, Environment 

client = Client(Environment.TEST)
```

Apps with [registered](https://docs.kin.org/app-registration) app indexes should initialize the client with their index:
```python
from agora.client import Client, Environment

client = Client(Environment.TEST, app_index=1)
```

### Usage

The following outlines some example usages of the client. See the [documentation](https://docs.kin.org/python/api) for more details.
 
#### Create an Account
The `create_account` method creates an account with the provided private key.

To create a new account, first generate a new private key, then submit it using `create_account`:
```python
from agora.client import Client, Environment
from agora.keys import PrivateKey

client = Client(Environment.TEST, app_index=1)

private_key = PrivateKey.random()
client.create_account(private_key)
```

#### Get a Transaction
The `get_transaction` method gets transaction data by transaction id.
```python
from agora.client import Client, Environment

client = Client(Environment.TEST, app_index=1)

# tx_id is either a 32-byte Stellar transaction hash or a 64-byte Solana transaction signature 
tx_id = b'<txid>'
transaction_data = client.get_transaction(tx_id)
```

#### Get an Account Balance
The `get_balance` method gets the balance of the provided account, in [quarks](https://docs.kin.org/terms-and-concepts#quark).
```python
from agora.keys import PrivateKey
from agora.client import Client, Environment

client = Client(Environment.TEST, app_index=1)
public_key = PrivateKey.random().public_key
balance = client.get_balance(public_key)
``` 

#### Submit a Payment
The `submit_payment` method submits the provided payment to Agora.
```python
from agora.client import Client, Environment
from agora.keys import PrivateKey, PublicKey
from agora.model import Payment, TransactionType
from agora.utils import kin_to_quarks

client = Client(Environment.TEST, app_index=1)
sender = PrivateKey.from_string('SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
dest = PublicKey.from_string('GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
payment = Payment(sender, dest, TransactionType.EARN, kin_to_quarks("1"))

tx_hash = client.submit_payment(payment)
```

#### Submit an Earn Batch
The `submit_earn_batch` method submits a batch of earns to Agora from a single account. It batches the earns into fewer 
transactions where possible and submits as many transactions as necessary to submit all the earns.
```python
from agora.client import Client, Environment
from agora.keys import PublicKey, PrivateKey
from agora.model import Earn, EarnBatch
from agora.utils import kin_to_quarks

client = Client(Environment.TEST, app_index=1)
sender = PrivateKey.from_string('SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
dest1 = PublicKey.from_string('GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX1')
dest2 = PublicKey.from_string('GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX2')

# Send two earns of 1 Kin each
earns = [
    Earn(dest1, kin_to_quarks("1")),
    Earn(dest2, 100000),  # also equivalent to 1 Kin
    ...
]
batch = EarnBatch(sender, earns)

batch_earn_result = client.submit_earn_batch(batch)
```

### Examples
A few examples for creating an account and different ways of submitting payments and batched earns can be found in `examples/client`.

## Webhook Handler
The `WebhookHandler` class is designed to assist developers with implementing the [Agora webhooks](https://docs.kin.org/how-it-works#webhooks). 

Only apps that have been assigned an [app index](https://docs.kin.org/app-registration) can make use of Agora webhooks.   

### Initialization
The `WebhookHandler` must be instantiated with the app's configured [webhook secret](https://docs.kin.org/agora/webhook#authentication).
```python
from agora.client import Environment
from agora.webhook.handler import WebhookHandler

webhook_handler = WebhookHandler(Environment.TEST, 'mysecret')
```  

### Usage
Currently, `WebhookHandler` contains support for the following webhooks:
- [Events](https://docs.kin.org/how-it-works#events), with `handle_events`
- [Sign Transaction](https://docs.kin.org/how-it-works#sign-transaction), with `handle_sign_transaction`

#### Events Webhook
To use the `WebhookHandler` with the Events webhook, developers should define a function that accepts a list of events and processes them in some way:
```python
from typing import List

from agora.webhook.events import Event


def process_events(events: List[Event]) -> None:
    # some processing logic
    return
``` 

This function can be used with `WebhookHandler.handle_events` inside your events endpoint logic as follows:
```python
from typing import List

from agora.client import Environment
from agora.webhook import WebhookHandler, AGORA_HMAC_HEADER
from agora.webhook.events import Event

webhook_handler = WebhookHandler(Environment.TEST, 'mysecret')


def process_events(events: List[Event]) -> None:
    # some processing logic
    return


# This will vary depending on which framework is used.
def events_endpoint_func(request):
    status_code, request_body = webhook_handler.handle_events(
        process_events,
        request.headers.get(AGORA_HMAC_HEADER),
        request.body,
    )
    
    # respond using provided status_code and request_body  
```

#### Sign Transaction Webhook 
The sign transaction webhook is used to sign Kin 3 transactions with a whitelisted Kin 3 account to remove fees. On Kin 4, the webhook can be used to simply approve or reject transactions submitted by mobile clients. 

To use the `WebhookHandler` with the Sign Transaction webhook, developers should define a function that accepts a sign transaction request and response object and verifies the request in some way and modifies the response object as needed:
```python
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse

def verify_request(req: SignTransactionRequest, resp: SignTransactionResponse) -> None:
    # verify the transaction inside `req`, and modify `resp` as needed.
    return
```

This function can be used with `WebhookHandler.sign_transaction` inside your sign transaction endpoint logic as follows:
```python
from agora.client import Environment
from agora.webhook import WebhookHandler, AGORA_HMAC_HEADER
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse

webhook_handler = WebhookHandler(Environment.TEST, 'mysecret')

def verify_request(req: SignTransactionRequest, resp: SignTransactionResponse) -> None:
    # verify the transaction inside `req`, and modify `resp` as needed (e.g. by calling `sign`).
    return

# This will vary depending on which framework is used.
def sign_tx_endpoint_func(request):
    status_code, request_body = webhook_handler.handle_sign_transaction(
        verify_request,
        request.headers.get(AGORA_HMAC_HEADER),
        request.body,
    )
    
    # respond using provided status_code and request_body  
```

### Example Code
A simple example Flask server implementing both the Events and Sign Transaction webhooks can be found in `examples/webhook/app.py`. To run it, first install all required dependencies (it is recommended that you use a virtual environment):
```
make deps
make deps-dev
```

Next, run it as follows from the root directory (it will run on port 8080):
```
export WEBHOOK_SECRET=yoursecrethere
export WEBHOOK_SEED=SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

python -m examples.webhook.app
``` 

## API Reference

The API reference can be found [here](https://docs.kin.org/python/api).
