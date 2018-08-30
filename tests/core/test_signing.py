import os

from squeak.core.signing import deserialize_verifying_key
from squeak.core.signing import deserialize_signature
from squeak.core.signing import generate_signing_key
from squeak.core.signing import get_verifying_key
from squeak.core.signing import serialize_verifying_key
from squeak.core.signing import serialize_signature
from squeak.core.signing import sign
from squeak.core.signing import verify


class TestSignVerify(object):

    def test_sign_verify(self):
        signing_key = generate_signing_key()
        verifying_key = get_verifying_key(signing_key)

        data = os.urandom(32)
        signature = sign(data, signing_key)

        assert verify(data, signature, verifying_key)

    def test_serialize_deserialize(self):
        signing_key = generate_signing_key()
        verifying_key = get_verifying_key(signing_key)

        key_data = serialize_verifying_key(verifying_key)
        deserialized_verifying_key = deserialize_verifying_key(key_data)

        data = os.urandom(32)
        signature = sign(data, signing_key)

        sig_data = serialize_signature(signature)
        deserialized_sig = deserialize_signature(sig_data)

        assert verify(data, signature, verifying_key)
        assert verify(data, signature, deserialized_verifying_key)
        assert verify(data, deserialized_sig, deserialized_verifying_key)
        assert len(key_data) == 33
        assert len(sig_data) == 64

    def test_sign_verify_other_data(self):
        signing_key = generate_signing_key()
        verifying_key = get_verifying_key(signing_key)

        data = os.urandom(32)
        data2 = os.urandom(32)
        signature = sign(data, signing_key)

        assert not verify(data2, signature, verifying_key)
