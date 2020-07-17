import kin_base

from agora.client.utils import kin_to_quarks, quarks_to_kin, quarks_to_kin_str, public_key_to_address


class TestUtil(object):
    def test_kin_to_quarks(self):
        assert kin_to_quarks(5) == 500000
        assert kin_to_quarks(5.12345) == 512345

        assert kin_to_quarks(5.123452) == 512345
        assert kin_to_quarks(5.123455) == 512346

    def test_quarks_to_kin(self):
        assert quarks_to_kin(500000) == 5
        assert quarks_to_kin(512345) == 5.12345

    def test_quarks_to_kin_str(self):
        assert quarks_to_kin_str(500000) == "5.00000"
        assert quarks_to_kin_str(512345) == "5.12345"

    def test_public_key_to_address(self):
        kp = kin_base.Keypair.random()

        data = b'data'
        sig = kp.sign(data)

        # ensure that verification still works after conversion
        addr = public_key_to_address(kp.raw_public_key())
        addr_kp = kin_base.Keypair.from_address(addr)
        addr_kp.verify(data, sig)
