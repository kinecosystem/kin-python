import random
import time

from agora.retry.backoff import Backoff


class Strategy:
    """Determines whether or not an action should be retried. Strategies are allowed to delay or cause other side
    effects.

    """

    def should_retry(self, attempts: int, e: Exception) -> bool:
        """Returns whether or not to retry, based on this strategy.

        :param attempts: Tee number of attempts that have occurred. Starts at 1, since the action is evaluated first.
        :param e: The :class:`Exception <Exception>` that was raised.
        :return: A bool indicating whether the action should be retried, based on this strategy.
        """
        raise NotImplementedError('Strategy is an abstract class. Strategy must implement should_retry().')


class LimitStrategy(Strategy):
    """A strategy that limits the total umber of retries.

    :param max_attempts: The max number of attempts. Should be greater than 1, since the action is evaluated first.
    """

    def __init__(self, max_attempts):
        self.max_attempts = max_attempts

    def should_retry(self, attempts: int, e: Exception) -> bool:
        return attempts < self.max_attempts


class RetriableErrorsStrategy(Strategy):
    """A strategy that specifies which errors can be retried.

    :param: retriable_errors: A list of :class:`Exception <Exception>` classes that can be retried.
    """

    def __init__(self, retriable_errors):
        self.retriable_errors = retriable_errors

    def should_retry(self, attempts: int, e: Exception) -> bool:
        for error in self.retriable_errors:
            if isinstance(e, error):
                return True

        return False


class NonRetriableErrorsStrategy(Strategy):
    """A strategy that specifies which errors should not be retried.

    :param: non_retriable_errors: A list of :class:`Exception <Exception>` classes that shouldn't be retried.
    """

    def __init__(self, non_retriable_errors):
        self.non_retriable_errors = non_retriable_errors

    def should_retry(self, attempts: int, e: Exception) -> bool:
        for error in self.non_retriable_errors:
            if isinstance(e, error):
                return False

        return True


class BackoffStrategy(Strategy):
    """A strategy that will delay the next retry, provided the action raised an error.

    :param: backoff: The :class:`Backoff <agora.retry.backoff.Backoff> to use to determine the amount of time to delay.
    :param max_backoff: The maximum backoff, in seconds.
    """

    def __init__(self, backoff: Backoff, max_backoff: float):
        self.backoff = backoff
        self.max_backoff = max_backoff

    def should_retry(self, attempts: int, e: Exception) -> bool:
        delay = min(self.max_backoff, self.backoff.get_backoff(attempts))
        time.sleep(delay)
        return True


class BackoffWithJitterStrategy(Strategy):
    """A strategy that will delay the next retry, with jitter induced on the delay provided by `backoff`.

    The jitter parameter is a percentage of the total delay (after capping) that the timing can be off by. For example,
    a capped delay of 0.1s with a jitter of 0.1 will result in a delay of 0.1s +/- 0.01s.

    :param: backoff: The :class:`Backoff <agora.retry.backoff.Backoff> to use to determine the amount of time to delay.
    :param max_backoff: The maximum backoff, in seconds.
    :param jitter: A percentage of the total delay that timing can be off by.
    """

    def __init__(self, backoff: Backoff, max_backoff: float, jitter: float):
        self.backoff = backoff
        self.max_backoff = max_backoff
        self.jitter = jitter

    def should_retry(self, attempts: int, e: Exception) -> bool:
        delay = min(self.max_backoff, self.backoff.get_backoff(attempts))
        time.sleep(delay * (1 + random.random() * self.jitter * 2 - self.jitter))
        return True
