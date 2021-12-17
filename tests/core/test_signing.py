import os

import pytest

from squeak.core import HASH_LENGTH
from squeak.core.signing import SqueakPrivateKey
from squeak.core.signing import SqueakPublicKey
from squeak.core.signing import PUB_KEY_LENGTH


def make_hash():
    return os.urandom(HASH_LENGTH)


class TestSignVerify(object):

    def test_sign_verify(self):
        priv_key = SqueakPrivateKey.generate()
        pub_key = priv_key.get_public_key()

        data = make_hash()
        signature = priv_key.sign(data)

        assert pub_key.verify(data, signature)

    def test_serialize_deserialize_public_key(self):
        priv_key = SqueakPrivateKey.generate()
        pub_key = priv_key.get_public_key()

        serialized = pub_key.to_bytes()
        deserialized = SqueakPublicKey.from_bytes(serialized)
        serialized2 = deserialized.to_bytes()
        deserialized2 = SqueakPublicKey.from_bytes(serialized2)

        data = make_hash()
        signature = priv_key.sign(data)

        assert pub_key.verify(data, signature)
        assert deserialized2.verify(data, signature)
        assert len(serialized2) == PUB_KEY_LENGTH

    def test_serialize_deserialize_private_key(self):
        priv_key = SqueakPrivateKey.generate()
        pub_key = priv_key.get_public_key()

        serialized = priv_key.to_bytes()
        deserialized_priv_key = SqueakPrivateKey.from_bytes(serialized)

        data = make_hash()
        signature = deserialized_priv_key.sign(data)

        assert pub_key.verify(data, signature)

    def test_serialize_deserialize_private_key_to_string(self):
        priv_key = SqueakPrivateKey.generate()
        pub_key = priv_key.get_public_key()

        priv_key_str = priv_key.to_str()
        print("priv_key_str:")
        print(priv_key_str)
        deserialized_priv_key = SqueakPrivateKey.from_str(priv_key_str)

        data = make_hash()
        signature = deserialized_priv_key.sign(data)

        assert pub_key.verify(data, signature)

    # def test_sign_verify_other_data(self):
    #     signing_key = CSigningKey.generate()
    #     verifying_key = signing_key.get_verifying_key()

    #     data = make_hash()
    #     data2 = make_hash()
    #     signature = signing_key.sign(data)

    #     assert not verifying_key.verify(data2, signature)

    # def test_address_to_pubkey(self):
    #     signing_key = CSigningKey.generate()
    #     verifying_key = signing_key.get_verifying_key()

    #     address = CSqueakAddress.from_verifying_key(verifying_key)
    #     pubkey_script = address.to_scriptPubKey()

    #     address_from_script = CSqueakAddress.from_scriptPubKey(pubkey_script)

    #     assert address_from_script == address

    # def test_address_to_string(self):
    #     signing_key = CSigningKey.generate()
    #     verifying_key = signing_key.get_verifying_key()

    #     address = CSqueakAddress.from_verifying_key(verifying_key)
    #     address_str = str(address)

    #     address_from_str = CSqueakAddress(address_str)

    #     assert address_from_str == address
    #     assert isinstance(address, CSqueakAddress)
    #     assert isinstance(address_from_str, CSqueakAddress)

    # def test_address_to_pubkey_invalid(self):
    #     with pytest.raises(CSqueakAddressError):
    #         CSqueakAddress.from_scriptPubKey(b'')
