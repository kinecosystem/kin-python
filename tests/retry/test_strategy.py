import pytest

from agora.retry import Strategy, LimitStrategy, RetriableErrorsStrategy, NonRetriableErrorsStrategy, ConstantBackoff
from agora.retry.strategy import BackoffStrategy, BackoffWithJitterStrategy


class TestStrategy:
    def test_should_retry(self):
        with pytest.raises(NotImplementedError):
            Strategy().should_retry(1, ValueError())


class TestLimitStrategy:
    def test_should_retry(self):
        s = LimitStrategy(2)
        assert s.should_retry(1, ValueError())
        assert not s.should_retry(2, ValueError())


class TestRetriableErrorsStrategy:
    def test_should_retry(self):
        s = RetriableErrorsStrategy([ConnectionError])
        assert s.should_retry(1, ConnectionError())
        assert not s.should_retry(1, ValueError())


class TestNonRetriableErrorsStrategy:
    def test_should_retry(self):
        s = NonRetriableErrorsStrategy([ValueError])
        assert s.should_retry(1, ConnectionError())
        assert not s.should_retry(1, ValueError())


class TestBackoffStrategy:
    def test_should_retry(self, mocker):
        mock_time = mocker.patch('time.time')

        s = BackoffStrategy(ConstantBackoff(0.1), 1)
        for i in range(10):
            assert s.should_retry(i, ValueError())

        for (args, kwargs) in mock_time.sleep.call_args_list:
            assert args[0] == 0.1


class TestBackoffWithJitterStrategy:
    def test_should_retry(self, mocker):
        mock_time = mocker.patch('time.time')

        s = BackoffWithJitterStrategy(ConstantBackoff(0.1), 1, 0.1)
        for i in range(10):
            assert s.should_retry(i, ValueError())

        for (args, kwargs) in mock_time.sleep.call_args_list:
            assert 0.09 < args[0] < 0.11
