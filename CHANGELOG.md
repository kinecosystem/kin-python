# Changelog

## Unreleased

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
