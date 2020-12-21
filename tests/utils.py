from typing import List, Optional

from kin_base.stellarxdr import StellarXDR_const as xdr_const, \
    StellarXDR_pack as xdr_pack, StellarXDR_type as xdr_type

from agora.keys import PrivateKey, PublicKey


def generate_keys(amount) -> List[PrivateKey]:
    return [PrivateKey.random() for _ in range(amount)]


def gen_account_id() -> xdr_type.AccountID:
    private_key = PrivateKey.random()

    return xdr_type.AccountID(
        type=xdr_const.PUBLIC_KEY_TYPE_ED25519,
        ed25519=private_key.public_key.raw,
    )


def gen_account_id_from_address(address: str) -> xdr_type.AccountID:
    public_key = PublicKey.from_string(address)

    return xdr_type.AccountID(
        type=xdr_const.PUBLIC_KEY_TYPE_ED25519,
        ed25519=public_key.raw,
    )


def gen_text_memo(text: bytes) -> xdr_type.Memo:
    return xdr_type.Memo(
        type=xdr_const.MEMO_TEXT,
        text=text,
    )


def gen_hash_memo(memo_hash: bytes) -> xdr_type.Memo:
    return xdr_type.Memo(
        type=xdr_const.MEMO_HASH,
        hash=memo_hash,
    )


def gen_tx_envelope_xdr(
    src: xdr_type.AccountID, seq: int, operations: List[xdr_type.Operation],
    memo: xdr_type.Memo, fee: int = 0, v: int = 0
) -> bytes:
    """Generate a transaction envelope xdr with the provided parameters.

    :return bytes
    """
    ext = xdr_pack.nullclass()
    ext.v = v

    envelope = xdr_type.TransactionEnvelope(
        tx=xdr_type.Transaction(
            sourceAccount=src,
            fee=fee,
            seqNum=seq,
            timeBounds=[xdr_type.TimeBounds(
                minTime=0,
                maxTime=0,
            )],
            memo=memo,
            operations=operations,
            ext=ext,
        ),
        signatures=[
            xdr_type.DecoratedSignature(
                hint=b'xxxx',
                signature=b'signature'
            )
        ]
    )
    xdr_envelope = xdr_pack.StellarXDRPacker()
    xdr_envelope.pack_TransactionEnvelope(envelope)

    return xdr_envelope.get_buffer()


def gen_create_op(
    src: xdr_type.AccountID, dest: xdr_type.AccountID
) -> xdr_type.Operation:
    """Generate a create account operation.
    """
    body = xdr_pack.nullclass()
    body.type = xdr_const.CREATE_ACCOUNT
    body.createAccountOp = xdr_type.CreateAccountOp(destination=dest, startingBalance=10)

    return xdr_type.Operation(
        sourceAccount=[src],
        body=body,
    )


def gen_payment_op(
    dest: xdr_type.AccountID, src: Optional[xdr_type.AccountID] = None,
    amount: int = 10
) -> xdr_type.Operation:
    """Generate a payment operation.
    """
    body = xdr_pack.nullclass()
    body.type = xdr_const.PAYMENT
    body.paymentOp = xdr_type.PaymentOp(
        destination=dest,
        asset=xdr_type.Asset(xdr_const.ASSET_TYPE_NATIVE),
        amount=amount,
    )

    return xdr_type.Operation(
        sourceAccount=[src] if src else [],
        body=body,
    )


def gen_kin_2_payment_op(
    dest: xdr_type.AccountID, src: Optional[xdr_type.AccountID] = None,
    raw_amount: int = 1000
) -> xdr_type.Operation:
    """Generate a payment operation.
    """
    body = xdr_pack.nullclass()
    body.type = xdr_const.PAYMENT

    alphaNum4 = xdr_pack.nullclass()
    alphaNum4.assetCode = b'KIN'

    # the test Kin 2 blockchain asset issuer
    alphaNum4.issuer = gen_account_id_from_address('GBC3SG6NGTSZ2OMH3FFGB7UVRQWILW367U4GSOOF4TFSZONV42UJXUH7')

    body.paymentOp = xdr_type.PaymentOp(
        destination=dest,
        asset=xdr_type.Asset(
            type=xdr_const.ASSET_TYPE_CREDIT_ALPHANUM4,
            alphaNum4=alphaNum4,
        ),
        amount=raw_amount,
    )

    return xdr_type.Operation(
        sourceAccount=[src] if src else [],
        body=body,
    )


def gen_merge_op(
    src: xdr_type.AccountID, dest: xdr_type.AccountID
) -> xdr_type.Operation:
    """Generate a merge operation.
    """
    body = xdr_pack.nullclass()
    body.type = xdr_const.ACCOUNT_MERGE
    body.destination = dest

    return xdr_type.Operation(
        sourceAccount=[src],
        body=body,
    )


def gen_result_xdr(
    tx_result_code: int,
    op_results: List[xdr_type.OperationResult],
    fee: int = 0,
    v: int = 0
) -> bytes:
    """Generates a result XDR with the provided parameters.

    :return bytes
    """
    result = xdr_pack.nullclass()
    result.code = tx_result_code
    result.results = op_results

    ext = xdr_pack.nullclass()
    ext.v = v

    tx_result = xdr_type.TransactionResult(
        fee,
        result,
        ext
    )
    xdr_tx_result = xdr_pack.StellarXDRPacker()
    xdr_tx_result.pack_TransactionResult(tx_result)

    return xdr_tx_result.get_buffer()


def gen_create_op_result(result_code: int) -> xdr_type.OperationResult:
    """Generates a create account operation result.
    """
    tr = xdr_pack.nullclass()
    tr.type = xdr_const.CREATE_ACCOUNT
    tr.createAccountResult = xdr_type.CreateAccountResult(result_code)
    return xdr_type.OperationResult(xdr_const.opINNER, tr)


def gen_payment_op_result(result_code: int) -> xdr_type.OperationResult:
    """Generates a payment operation result.
    """
    tr = xdr_pack.nullclass()
    tr.type = xdr_const.PAYMENT
    tr.paymentResult = xdr_type.PaymentResult(result_code)
    return xdr_type.OperationResult(xdr_const.opINNER, tr)


def gen_merge_op_result(result_code: int) -> xdr_type.OperationResult:
    """Generates a merge operation result.
    """
    tr = xdr_pack.nullclass()
    tr.type = xdr_const.ACCOUNT_MERGE
    tr.accountMergeResult = xdr_type.AccountMergeResult(result_code)
    return xdr_type.OperationResult(xdr_const.opINNER, tr)
