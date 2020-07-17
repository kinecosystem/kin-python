from agora.utils import partition


class TestUtils(object):
    def test_partiion(self):
        numbers = list(range(250))
        expected_batches = [numbers[0:100], numbers[100:200], numbers[200:]]
        for idx, number_batch in enumerate(partition(numbers, 100)):
            assert number_batch == expected_batches[idx]
