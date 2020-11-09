import time
from collections import OrderedDict
from threading import Lock
from typing import Optional


class BaseCache:
    def set(self, key: bytes, value: bytes):
        raise NotImplementedError('BaseCache is an abstract class. Subclasses must implement `set`')

    def get(self, key: bytes) -> Optional[bytes]:
        raise NotImplementedError('BaseCache is an abstract class. Subclasses must implement `get`')


class LRUCache(BaseCache):
    """An in-memory LRU cache.

    :param default_ttl: the default amount of time, in seconds, that an entry will be cached if no other TTL is
        provided.
    :param max_entries: the maximum number of entries the cache will hold.
    """

    def __init__(self, default_ttl: int, max_entries: int):
        self._cache = OrderedDict()
        self._entry_expiry = {}
        self._lock = Lock()
        self._ttl = default_ttl
        self._max_entries = max_entries

    def set(self, key: bytes, value: bytes, ttl: Optional[int] = None):
        ttl = ttl if ttl else self._ttl
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key, last=False)
            self._entry_expiry[key] = time.time() + ttl

            if len(self._cache) > self._max_entries:
                self._evict()

    def get(self, key: bytes) -> Optional[bytes]:
        with self._lock:
            if not self._has_valid_entry(key):
                self._clear(key)
                return None
            value = self._cache.get(key, [])
            self._cache.move_to_end(key, last=False)

        return value

    def clear_all(self):
        with self._lock:
            self._cache.clear()
            self._entry_expiry.clear()

    def _has_valid_entry(self, key: bytes):
        exp = self._entry_expiry.get(key)
        return exp and exp > time.time()

    def _evict(self):
        key, _ = self._cache.popitem()
        del self._entry_expiry[key]

    def _clear(self, key):
        self._cache.pop(key, None)
        self._entry_expiry.pop(key, None)
