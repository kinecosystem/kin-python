# Changelog

## Unreleased
- Remove Stellar (Kin 2 & Kin 3) support
    - Only Kin 4 and v4 Agora APIs are supported
    - `Client.__init__` no longer accepts `kin_version`, `whitelist_key` and `desired_kin_version`
    - `AccountInfo` no longer has `sequence_number`
    - Removed `channel` from `Payment` and `EarnBatch`
    - Removed `envelope`, `kin_version` and `get_tx_hash()` from `SignTransactionRequest`
    - Removed `envelope` from `SignTransactionResponse`
    - Removed `kin_version` and `stellar_event` from `TransactionEvent`
- Add sender create support for `Client.submit_payment`
- Add `merge_token_accounts` to `Client`
- Add create account webhook support
- Add creation parsing to `SigntransactionRequest`
- `SignTransactionResponse.sign` now signs Solana transactions

## [0.6.1](https://github.com/kinecosystem/kin-python/releases/tag/0.6.1)
- Bump agora-api and grpcio version

## [0.6.0](https://github.com/kinecosystem/kin-python/releases/tag/0.6.0)
- Expose `request_airdrop` on `Client` for Kin 4

## [0.5.0](https://github.com/kinecosystem/kin-python/releases/tag/0.5.0)
- Add `dedupe_id` support on payments (`Client.submit_payment`) and earn batches (`Client.submit_earn_batch`)
- `Client.submit_earn_batch` now supports submitting only a single transaction and up to 15 earns
- `BatchEarnResult` has been replaced with `EarnBatchResult`, whichcontains `TxID`, `TxError` and `EarnErrors` due to the above changes
- `Client.submit_earn_batch` now takes in an `earn_batch` argument instead of separate `sender`, `earns`, `channel`, `memo`, and `subsidizer` args
- Add `payment_errors` to `TransactionErrors`
- Add `AccountNotFoundError` to the default non-retriable error list. This should the decrease
  latencies in situations where a Resolve() is required by about 8 seconds (with the
  default retry configuration)

## [0.4.7](https://github.com/kinecosystem/kin-python/releases/tag/0.4.7)
- Fix invoice list parsing in events webhook handler

## [0.4.6](https://github.com/kinecosystem/kin-python/releases/tag/0.4.6)
- Add optional `account_resolution` parameter to `Client.get_balance` 

## [0.4.5](https://github.com/kinecosystem/kin-python/releases/tag/0.4.5)
- Create new accounts with different token account address

## [0.4.4](https://github.com/kinecosystem/kin-python/releases/tag/0.4.4)
- Reduce token account cache size
- Do not throw exception for setting channel on Kin 4 payments
- Check for duplicate signers for Stellar transactions
- Include read-only signers in Solana transaction `num_signatures` header

## [0.4.3](https://github.com/kinecosystem/kin-python/releases/tag/0.4.3)
- Fix uploaded wheel to remove `agora/model/keys.py` 

## [0.4.2](https://github.com/kinecosystem/kin-python/releases/tag/0.4.2)
- Call v3 `GetTransaction` API for Kin 2 & 3

## [0.4.1](https://github.com/kinecosystem/kin-python/releases/tag/0.4.1)
- Bugfix: fix production Kin 3 envelope parsing in `SignTransactionRequest.from_json`

## [0.4.0](https://github.com/kinecosystem/kin-python/releases/tag/0.4.0)
- Add Kin 4 support
- Move `agora.model.keys` to `agora.keys`
- Rename `tx_hash` to `tx_id` in `Client.get_transaction`, `TransactionData`, `EarnResult`, and 'TransactionEvent'
- Add `default_commitment` parameter to `Client` constructor
- Add optional `commitment` parameter to `Client` methods (`create_account`, `get_balance`, `get_transaction`, `submit_payment`, `submit_earn_batch`)
- Add optional `subsidizer` parameter to `Payment`, `Client.create_account` and `Client.submit_earn_batch`
- Add optional `sender_resolution` and `dest_resolution` parameters to `Client.submit_payment` and `Client.submit_earn_batch`
- Rename `StellarData` to `StellarEvent`, `TransactionEvent.stellar_data` to `TransactionEvent.stellar_event`, and fix `TransactionEvent.from_json` to match production
- Deprecate `SignTransactionRequest.get_tx_hash()` and replace with `SignTransactionRequest.get_tx_id()`.

## [0.3.3](https://github.com/kinecosystem/kin-python/releases/tag/0.3.3)
- Add Kin 2 support

## [0.3.2](https://github.com/kinecosystem/kin-python/releases/tag/0.3.2)
- Bugfix: fix metadata format

## [0.3.1](https://github.com/kinecosystem/kin-python/releases/tag/0.3.1)
- Add user-agent metadata to Agora requests

## [0.3.0](https://github.com/kinecosystem/kin-python/releases/tag/0.3.0)
- Rename `source` in `Payment` and `Client.submit_earn_batch` to `channel` for clarity
- Adjust `BadNonceError` handling

## [0.2.0](https://github.com/kinecosystem/kin-python/releases/tag/0.2.0)
- Add `close()` method to `Client` for cleaning up connection-related resources
- Add `__repr__` methods to models
- Add a `NONE` transaction type

## [0.1.0](https://github.com/kinecosystem/kin-python/releases/tag/0.1.0)
- Initial release with Kin 3 support
