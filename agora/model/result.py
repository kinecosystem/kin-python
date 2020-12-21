from typing import List, Optional

from agora.error import Error


class EarnError:
    """The :class:`EarnError <EarnError>` object contains earn-specific details about why a submitted earn batch failed

    :param earn_index: The index of the earn the error pertains to
    :param error: The error
    """

    def __init__(self, earn_index: int, error: Error):
        self.earn_index = earn_index
        self.error = error

    def __eq__(self, other):
        if not isinstance(other, EarnError):
            return False

        return (self.earn_index == other.earn_index and
                self.error == other.error)

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'earn_index={self.earn_index}, error={self.error!r})'


class EarnBatchResult:
    """The :class:`BatchEarnResult <BatchEarnResult>` object, which contains the results of a submitted earn batch.

    :param tx_id: The id of the transaction that was submitted for the earn batch.
    :param tx_error: (optional) An Error indicating why an earn batch failed. If tx_error is defined, the transaction
        failed.
    :param earn_errors: (optional) A List of any available earn-specific error information. May or may not be set if
        tx_error is set.
    """

    def __init__(self, tx_id: bytes, tx_error: Optional[Error] = None, earn_errors: Optional[List[EarnError]] = None):
        self.tx_id = tx_id
        self.tx_error = tx_error
        self.earn_errors = earn_errors

    def __eq__(self, other):
        if not isinstance(other, EarnBatchResult):
            return False

        return (self.tx_id == other.tx_id and
                self.tx_error == other.tx_error and
                all(earn_error == other.earn_errors[idx] for idx, earn_error in enumerate(self.earn_errors)))

    def __repr__(self):
        return f'{self.__class__.__name__}(' \
               f'tx_id={self.tx_id}, tx_error={self.tx_error!r})' \
               f'earn_errors={[e for e in self.earn_errors]!r})'
