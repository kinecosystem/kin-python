class Backoff:
    """Provides the amount of time to wait before trying again.
    """

    def get_backoff(self, attempts: int) -> float:
        """Returns the amount of time to wait before trying again.

        :param attempts: The number of attempts that have occurred (starts at 1).
        :return: The float number of seconds to wait
        """
        raise NotImplementedError('Backoff is an abstract class. Subclasses must implement get_backoff().')


class ConstantBackoff(Backoff):
    """A backoff strategy that always returns the provided duration

    :param duration: The duration, in seconds.
    """

    def __init__(self, duration: float):
        self.interval = duration  # seconds

    def get_backoff(self, attempts: int) -> float:
        return self.interval


class LinearBackoff(Backoff):
    """A backoff strategy that linearly increases based off of the number of attempts.

    For example, with a `base_delay` of 2, this strategy will yield backoffs of 2, 4, 6, 8, etc.

    :param base_delay: The base delay, in seconds.
    """

    def __init__(self, base_delay: float):
        self.base_delay = base_delay

    def get_backoff(self, attempts: int) -> float:
        return self.base_delay * attempts


class ExponentialBackoff(Backoff):
    """A backoff strategy that exponentially increases based off of the number of attempts.

    For example, with a `base_delay` of 2 and a `base` of 3, this strategy will yield backoffs of 2, 6, 16, 54, etc.

    :param base_delay: The base delay, in seconds.
    :param base: The base by which to exponentially increase delay by.
    """

    def __init__(self, base_delay: float, base: float):
        self.base_delay = base_delay
        self.base = base

    def get_backoff(self, attempts: int) -> float:
        return self.base_delay * (self.base ** (attempts - 1))


class BinaryExponentialBackoff(ExponentialBackoff):
    """An ExponentialBackoffStrategy with a base of 2.

    For example, with a `base_delay` of 2, this strategy will yield backoffs of 2, 4, 6, 16, etc.

    :param: base_delay: The base delay, in seconds.
    """

    def __init__(self, base_delay: float):
        super(BinaryExponentialBackoff, self).__init__(base_delay, 2)
