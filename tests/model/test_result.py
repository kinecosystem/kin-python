from agora.error import Error
from agora.model.earn import Earn
from agora.model.result import EarnTransactionResult, EarnResult, BatchEarnResult


class TestEarnTransactionResult(object):
    def test_has_failed(self):
        assert not EarnTransactionResult(b'hash', [EarnResult(Earn(b'dest', 100))]).has_failed
        assert EarnTransactionResult(b'hash', [
            EarnResult(Earn(b'dest', 100), error=Error()),
            EarnResult(Earn(b'dest', 100)),
        ]).has_failed


class TestBatchEarnResult(object):
    def test_any_failed(self):
        assert not BatchEarnResult([
            EarnTransactionResult(b'hash', [EarnResult(Earn(b'dest', 100))]),
            EarnTransactionResult(b'hash', [EarnResult(Earn(b'dest', 100))]),
        ]).any_failed
        assert BatchEarnResult([
            EarnTransactionResult(b'hash', [EarnResult(Earn(b'dest', 100))]),
            EarnTransactionResult(b'hash', [EarnResult(Earn(b'dest', 100), error=Error())]),
        ]).any_failed
