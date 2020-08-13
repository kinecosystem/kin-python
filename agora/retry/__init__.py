from typing import List, Callable

from agora.retry.backoff import Backoff, ConstantBackoff, LinearBackoff, ExponentialBackoff, BinaryExponentialBackoff
from agora.retry.strategy import Strategy, LimitStrategy, RetriableErrorsStrategy, NonRetriableErrorsStrategy, \
    BackoffStrategy, BackoffWithJitterStrategy


def retry(strategies: List[Strategy], f: Callable, *args, **kwargs):
    """Executes the provided function, potentially multiple times based off the provided strategies. Retry will block
    until the action is successful, or one of the provided strategies indicate no further retries should be performed.

    The strategies are executed in the provided order, so any strategies that induce delays should be specified last.

    :param strategies: The list of :class:`<agora.retry.strategy.Strategy>` objects to use
    :param f: A Callable to execute with the provided args and kwargs.
    :return: The return value of `f`.
    """
    i = 1
    while True:
        try:
            return f(*args, **kwargs)
        except Exception as e:
            if not strategies:
                raise e

            for s in strategies:
                if not s.should_retry(i, e):
                    raise e
        i += 1


__all__ = [
    'retry',
    'Backoff',
    'ConstantBackoff',
    'LinearBackoff',
    'ExponentialBackoff',
    'BinaryExponentialBackoff',
    'Strategy',
    'LimitStrategy',
    'RetriableErrorsStrategy',
    'NonRetriableErrorsStrategy',
    'BackoffStrategy',
    'BackoffWithJitterStrategy',
]
