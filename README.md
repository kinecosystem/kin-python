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
use of Agora Webhooks. For a high-level overview of how to integrate Kin and make use of Agora, please refer to the [website documentation](https://docs.kin.org).

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

Additional options include:
- `whitelist_key`: The private key of an account that will be used to co-sign all transactions.
- `grpc_channel`: A specific `grpc.Channel` to use. Cannot be set if `endpoint` is set.
- `endpoint`: A specific endpoint to use in the client. Cannot be set if `grpc_channel` is set.
- `retry_config`: A custom `agora.client.RetryConfig` to configure how the client retries requests.

### Usage
#### Create an Account
The `create_account` method creates an account with the provided private key.

To create a new account, first generate a new private key:
```python
from agora.model import PrivateKey

private_key = PrivateKey.random()
```

Next, submit it using `create_account`:
```python
client.create_account(private_key)
```

#### Get a Transaction
The `get_transaction` method gets transaction data by transaction hash.
```python
tx_hash = b'txhash'
transaction_data = client.get_transaction(tx_hash)
```

#### Get an Account Balance
The `get_balance` method gets the balance of the provided account, in [quarks](https://docs.kin.org/terms-and-concepts#quark).
```python
from agora.model import PrivateKey
from agora.client import Client, Environment

client = Client(Environment.TEST, app_index=1)
public_key = PrivateKey.random().public_key
balance = client.get_balance(public_key)
``` 

#### Submit a Payment
The `submit_payment` method submits the provided payment to Agora.
```python
from agora.client import Client, Environment
from agora.model import Payment, TransactionType, PrivateKey, PublicKey
from agora.utils import kin_to_quarks

client = Client(Environment.TEST, app_index=1)
sender = PrivateKey.from_string('SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
dest = PublicKey.from_string('GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
payment = Payment(sender, dest, TransactionType.EARN, kin_to_quarks("1"))

tx_hash = client.submit_payment(payment)
```

A `Payment` has the following required properties:
- `sender`: The private key of the account from which the payment will be sent.
- `destination`: The public key of the account to which the payment will be sent.
- `payment_type`: The transaction type of the payment.
- `quarks`: The amount of the payment, in [quarks](https://docs.kin.org/terms-and-concepts#quark).

Additionally, it has some optional properties:
- `source`: The private key of a source account to use for the transaction. If unset, `sender` will be used as the transaction source.
- `invoice`: An [Invoice](https://docs.kin.org/how-it-works#invoices) to associate with this payment. Cannot be set if `memo` is set.
- `memo` A text memo to include in the transaction. Cannot be set if `invoice` is set.

#### Submit an Earn Batch
The `submit_earn_batch` method submits a batch of earns to Agora from a single account. It batches the earns into fewer 
transactions where possible and submits as many transactions as necessary to submit all the earns.
```python
from agora.client import Client, Environment
from agora.model import Earn, PrivateKey, PublicKey
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

batch_earn_result = client.submit_earn_batch(sender, earns)
```

A single `Earn` has the following properties:
- `destination`: The public key of the account to which the earn will be sent.
- `quarks`: The amount of the earn, in [quarks](https://docs.kin.org/terms-and-concepts#quark).
- `invoice`: (optional) An [Invoice](https://docs.kin.org/how-it-works#invoices) to associate with this earn.

The `submit_earn_batch` method has the following parameters:
- `sender`:  The private key of the account from which the earns will be sent.
- `earns`: The list of earns to send.
- `source`: (optional): The private key of an account to use as the transaction source. If not set, `sender` will be used as the source.
- `memo`: (optional) A text memo to include in the transaction. Cannot be used if the earns have invoices associated with them.

### Examples
A few examples for creating an account and different ways of submitting payments and batched earns can be found in `examples/client`.

## Webhook Handler
The `WebhookHandler` class is designed to assist developers with implementing the [Agora webhooks](https://docs.kin.org/how-it-works#webhooks). 

Only apps that have been assigned an [app index](https://docs.kin.org/app-registration) can make use of Agora webhooks.   

### Initialization
The `WebhookHandler` must be instantiated with the app's configured [webhook secret](https://docs.kin.org/agora/webhook#authentication).
```python
from agora.webhook.handler import WebhookHandler

webhook_handler = WebhookHandler('mysecret')
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

from agora.webhook import WebhookHandler, AGORA_HMAC_HEADER
from agora.webhook.events import Event

webhook_handler = WebhookHandler('mysecret')


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

`WebhookHandler.handle_events` takes in the following mandatory parameters:
- `f`: A function that accepts a list of Events. Any return value will be ignored.
- `signature`: The base64-encoded signature included as the `X-Agora-HMAC-SHA256` header in the HTTP request (see the [Agora Webhook Reference](https://docs.kin.org/agora/webhook) for more details).
- `req_body`: The string request body.

#### Sign Transaction Webhook 
To use the `WebhookHandler` with the Sign Transaction webhook, developers should define a function that accepts a sign transaction request and response object and verifies the request in some way and modifies the response object as needed:
```python
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse

def verify_request(req: SignTransactionRequest, resp: SignTransactionResponse) -> None:
    # verify the transaction inside `req`, and modify `resp` as needed.
    return
```

This function can be used with `WebhookHandler.sign_transaction` inside your sign transaction endpoint logic as follows:
```python
from agora.webhook import WebhookHandler, AGORA_HMAC_HEADER
from agora.webhook.sign_transaction import SignTransactionRequest, SignTransactionResponse

webhook_handler = WebhookHandler('mysecret')

def verify_request(req: SignTransactionRequest, resp: SignTransactionResponse) -> None:
    # verify the transaction inside `req`, and modify `resp` as needed.
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

`WebhookHandler.handle_sign_transaction` takes in the following mandatory parameters:
- `f`: A function that takes in a SignTransactionRequest and a SignTransactionResponse. Any return value will be ignored.
- `signature`: The base64-encoded signature included as the `X-Agora-HMAC-SHA256` header in the HTTP request (see the [Agora Webhook Reference](https://docs.kin.org/agora/webhook) for more details).
- `req_body`: The string request body.

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
