import time

import pytest

from agora.retry import retry, LimitStrategy, ConstantBackoff
from agora.retry.strategy import BackoffStrategy


class TestRetry:
    def test_retry(self):
        strategies = [
            LimitStrategy(2),
            BackoffStrategy(ConstantBackoff(0.5), 0.5),
        ]

        assert not retry(strategies, self._return_none)

        start = time.time()
        with pytest.raises(ValueError):
            retry(strategies, self._raise_value_error)

        elapsed = time.time() - start
        assert 1 > elapsed > 0.5

    def test_retry_no_strategies(self):
        with pytest.raises(ValueError):
            retry([], self._raise_value_error)

    @staticmethod
    def _return_none():
        return

    @staticmethod
    def _raise_value_error():
        raise ValueError()
