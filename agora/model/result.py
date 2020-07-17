from typing import List, Optional

from agora.error import Error
from agora.model.earn import Earn


class EarnResult(object):
    """The :class:`EarnResult <EarnResult>` object, which contains the result of a submitted earn.

    :param earn: The originally submitted earn.
    :param error: (optional) An :class:`Error <agora.error.Error>` indicating why an earn failed. The absence of an
        error does not indicate that the earn was submitted successfully, only that if the parent transaction failed, it
        may not have been due to this particular earn.
    """

    def __init__(self, earn: Earn, error: Optional[Error] = None):
        self.earn = earn
        self.error = error

    def __eq__(self, other):
        if not isinstance(other, EarnResult):
            return False

        return (self.earn == other.earn and
                self.error == other.error)


class EarnTransactionResult(object):
    """The :class:`TransactionResult <TransactionResult>` object, which contains the result of a submitted transaction
    for a batch of earns.

    :param tx_hash: The hash of the transaction that was submitted.
    :param earn_results: A list of :class:`EarnResult <EarnResult>` objects.
    """

    def __init__(self, tx_hash: bytes, earn_results: List[EarnResult]):
        self.tx_hash = tx_hash
        self.earn_results = earn_results

    def __eq__(self, other):
        if not isinstance(other, EarnTransactionResult):
            return False

        return (self.tx_hash == other.tx_hash and
                all(result == other.earn_results[idx] for idx, result in enumerate(self.earn_results)) and
                self.error == other.error)

    @property
    def has_failed(self) -> bool:
        """Indicates if the transaction failed.
        """
        return any(result.error is not None for result in self.earn_results)


class BatchEarnResult(object):
    """The :class:`BatchEarnResult <BatchEarnResult>` object, which contains the results of a submitted earn batch.

    :param transaction_results: A list of :class:`EarnTransactionResult <EarnTransactionResult>` objects.
    """

    def __init__(self, transaction_results: List[EarnTransactionResult]):
        self.tx_results = transaction_results

    def __eq__(self, other):
        if not isinstance(other, BatchEarnResult):
            return False

        return all(result == other.tx_results[idx] for idx, result in enumerate(self.tx_results))

    @property
    def any_failed(self) -> bool:
        """Indicates if any of the transactions in the batch failed.

        :return: A bool indicating whether any earns failed.
        """
        return any(result.has_failed for result in self.tx_results)
