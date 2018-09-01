import os

from squeak.core.signing import CSigningKey
from squeak.core.signing import CVerifyingKey


class TestSignVerify(object):

    def test_sign_verify(self):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = os.urandom(32)
        signature = signing_key.sign(data)

        assert verifying_key.verify(data, signature)

    def test_serialize_deserialize(self):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        key_data = verifying_key.serialize()
        deserialized_verifying_key = CVerifyingKey.deserialize(key_data)

        data = os.urandom(32)
        signature = signing_key.sign(data)

        assert verifying_key.verify(data, signature)
        assert deserialized_verifying_key.verify(data, signature)
        assert len(key_data) == 33
        assert len(signature) == 64

    def test_sign_verify_other_data(self):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = os.urandom(32)
        data2 = os.urandom(32)
        signature = signing_key.sign(data)

        assert not verifying_key.verify(data2, signature)
