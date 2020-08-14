from typing import List, Optional

from agora.model.earn import Earn


class EarnResult:
    """The :class:`EarnResult <EarnResult>` object, which contains the result of a submitted earn.

    :param earn: The originally submitted earn.
    :param tx_hash: (optional) The hash of the transaction that was submitted, if one was submitted for this earn. If
        omitted, it indicates that no transaction was submitted for this earn.
    :param error: (optional) An Exception indicating why the earn failed. The absence of an error does not indicate that
        the earn was submitted successfully, only that if it failed, either its transaction failed due to another earn,
        or it was not submitted at all.
    """

    def __init__(self, earn: Earn, tx_hash: bytes = None, error: Optional[Exception] = None):
        self.earn = earn
        self.tx_hash = tx_hash
        self.error = error

    def __eq__(self, other):
        if not isinstance(other, EarnResult):
            return False

        return (self.earn == other.earn and
                self.tx_hash == other.tx_hash and
                self.error == other.error)


class BatchEarnResult:
    """The :class:`BatchEarnResult <BatchEarnResult>` object, which contains the results of a submitted earn batch.

    :param succeeded: A list of :class:`EarnResult <EarnResult>` objects.
    :param failed: A list of :class:`EarnResult <EarnResult>` objects.
    """

    def __init__(self, succeeded: List[EarnResult], failed: List[EarnResult]):
        self.succeeded = succeeded
        self.failed = failed

    def __eq__(self, other):
        if not isinstance(other, BatchEarnResult):
            return False

        return (all(result == other.succeeded[idx] for idx, result in enumerate(self.succeeded)) and
                all(result == other.failed[idx] for idx, result in enumerate(self.failed)))
