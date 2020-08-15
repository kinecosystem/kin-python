from agora.utils import partition, kin_to_quarks, quarks_to_kin


class TestUtils:
    def test_partiion(self):
        numbers = list(range(250))
        expected_batches = [numbers[0:100], numbers[100:200], numbers[200:]]
        for idx, number_batch in enumerate(partition(numbers, 100)):
            assert number_batch == expected_batches[idx]

    def test_kin_to_quarks(self):
        assert kin_to_quarks("0.000009") == 0
        assert kin_to_quarks("0.00015") == 15
        assert kin_to_quarks("5") == 500000
        assert kin_to_quarks("5.1") == 510000
        assert kin_to_quarks("5.123459") == 512345

    def test_quarks_to_kin_str(self):
        assert quarks_to_kin(15) == "0.00015"
        assert quarks_to_kin(500000) == "5"
        assert quarks_to_kin(510000) == "5.1"
        assert quarks_to_kin(512345) == "5.12345"
