import kin_base

from agora.utils import kin_str_to_quarks, quarks_to_kin_str, public_key_to_address


class TestUtil(object):
    def test_kin_to_quarks(self):
        assert kin_str_to_quarks("0.000009") == 0
        assert kin_str_to_quarks("0.00015") == 15
        assert kin_str_to_quarks("5") == 500000
        assert kin_str_to_quarks("5.1") == 510000
        assert kin_str_to_quarks("5.123459") == 512345

    def test_quarks_to_kin_str(self):
        assert quarks_to_kin_str(15) == "0.00015"
        assert quarks_to_kin_str(500000) == "5"
        assert quarks_to_kin_str(510000) == "5.1"
        assert quarks_to_kin_str(512345) == "5.12345"

    def test_public_key_to_address(self):
        kp = kin_base.Keypair.random()

        data = b'data'
        sig = kp.sign(data)

        # ensure that verification still works after conversion
        addr = public_key_to_address(kp.raw_public_key())
        addr_kp = kin_base.Keypair.from_address(addr)
        addr_kp.verify(data, sig)
