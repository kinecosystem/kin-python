from agora.error import Error


class StellarTransactionError(Error):
    """Raised when a Stellar transaction fails.

    :param result_xdr: The decoded result_xdr, in bytes.
    """

    def __init__(self, result_xdr: bytes):
        self.result_xdr = result_xdr
