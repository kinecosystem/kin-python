from typing import List, Optional

from agora.model.earn import Earn


class EarnResult:
    """The :class:`EarnResult <EarnResult>` object, which contains the result of a submitted earn.

    :param earn: The originally submitted earn.
    :param tx_id: (optional) The id of the transaction that was submitted, if one was submitted for this earn.
        If omitted, it indicates that no transaction was submitted for this earn.
    :param error: (optional) An Exception indicating why the earn failed. The absence of an error does not indicate that
        the earn was submitted successfully, only that if it failed, either its transaction failed due to another earn,
        or it was not submitted at all.
    """

    def __init__(self, earn: Earn, tx_id: bytes = None, error: Optional[Exception] = None):
        self.earn = earn
        self.tx_id = tx_id
        self.error = error

    def __eq__(self, other):
        if not isinstance(other, EarnResult):
            return False

        return (self.earn == other.earn and
                self.tx_id == other.tx_id and
                self.error == other.error)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'earn={self.earn!r}, tx_id={self.tx_id}, error={self.error!r})'


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

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'succeeded={[s for s in self.succeeded]!r}, failed={[f for f in self.failed]!r})'
