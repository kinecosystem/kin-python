import pytest

from agora.retry import Backoff, ConstantBackoff, LinearBackoff, ExponentialBackoff, BinaryExponentialBackoff


class TestBackoff(object):
    def test_get_backoff(self):
        with pytest.raises(NotImplementedError):
            Backoff().get_backoff(1)


class TestConstantBackoff(object):
    def test_get_backoff(self):
        b = ConstantBackoff(0.1)

        for i in range(1, 10):
            assert b.get_backoff(i) == 0.1


class TestLinearBackoff(object):
    def test_get_backoff(self):
        b = LinearBackoff(1)

        assert b.get_backoff(1) == 1
        assert b.get_backoff(2) == 2
        assert b.get_backoff(3) == 3
        assert b.get_backoff(4) == 4


class TestExponentialBackoff(object):
    def test_get_backoff(self):
        b = ExponentialBackoff(2, 3.0)

        assert b.get_backoff(1) == 2  # 2*3^0
        assert b.get_backoff(2) == 6  # 2*3^1
        assert b.get_backoff(3) == 18  # 2*3^2
        assert b.get_backoff(4) == 54  # 2*3^3


class TestBinaryExponentialBackoff(object):
    def test_get_backoff(self):
        b = BinaryExponentialBackoff(2)

        assert b.get_backoff(1) == 2  # 2*2^0
        assert b.get_backoff(2) == 4  # 2*2^1
        assert b.get_backoff(3) == 8  # 2*2^2
        assert b.get_backoff(4) == 16  # 2*2^3
