import datetime

import pytest

from agora.cache.cache import LRUCache, BaseCache


class TestBaseCache:
    def test_not_implemented(self):
        cache = BaseCache()
        with pytest.raises(NotImplementedError):
            cache.get(b'key')

        with pytest.raises(NotImplementedError):
            cache.set(b'key', b'val')


class TestLRUCache:
    def test_round_trip(self):
        cache = LRUCache(10, 2)
        cache.set(b'key1', b'val1')
        assert cache.get(b'key1') == b'val1'
        cache.set(b'key2', b'val2')
        assert cache.get(b'key2') == b'val2'

        # move key1 to most recently used
        assert cache.get(b'key1') == b'val1'

        # add a third value, which causes key2 to get evicted
        cache.set(b'key3', b'val3')
        assert cache.get(b'key3') == b'val3'

        assert not cache.get(b'key2')

        cache.clear_all()
        assert not cache.get(b'key1')
        assert not cache.get(b'key2')

    def test_expiry(self, freezer):
        cache = LRUCache(30, 2)
        cache.set(b'key1', b'val1')
        assert cache.get(b'key1') == b'val1'

        # move time forward to ensure entry expires
        freezer.move_to(datetime.datetime.now() + datetime.timedelta(seconds=30))
        assert not cache.get(b'key1')

        # test custom TTL
        cache.set(b'key1', b'val1', 5)
        assert cache.get(b'key1') == b'val1'
        freezer.move_to(datetime.datetime.now() + datetime.timedelta(seconds=5))
        assert not cache.get(b'key1')
