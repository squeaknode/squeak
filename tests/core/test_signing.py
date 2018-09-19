import os

import pytest

from bitcoin.wallet import CBitcoinAddressError

from squeak.core import HASH_LENGTH
from squeak.core.signing import CSigningKey
from squeak.core.signing import CSqueakAddress
from squeak.core.signing import CVerifyingKey
from squeak.core.signing import PUB_KEY_LENGTH
from squeak.core.script import VerifyScript


@pytest.fixture
def make_hash():
    def _make_hash():
        return os.urandom(HASH_LENGTH)
    return _make_hash


class TestSignVerify(object):

    def test_sign_verify(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = make_hash()
        signature = signing_key.sign(data)

        assert verifying_key.verify(data, signature)

    def test_serialize_deserialize_verifying_key(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        serialized = verifying_key.serialize()
        deserialized = CVerifyingKey.deserialize(serialized)
        serialized2 = deserialized.serialize()
        deserialized2 = CVerifyingKey.deserialize(serialized2)

        data = make_hash()
        signature = signing_key.sign(data)

        assert verifying_key.verify(data, signature)
        assert deserialized2.verify(data, signature)
        assert len(serialized2) == PUB_KEY_LENGTH

    def test_serialize_deserialize_signing_key(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        key_data = str(signing_key)
        deserialized_signing_key = CSigningKey.from_string(key_data)

        data = make_hash()
        signature = deserialized_signing_key.sign(data)

        assert verifying_key.verify(data, signature)

    def test_sign_verify_other_data(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = make_hash()
        data2 = make_hash()
        signature = signing_key.sign(data)

        assert not verifying_key.verify(data2, signature)

    def test_sign_verify_script(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = make_hash()
        sig_script = signing_key.sign_to_scriptSig(data)
        address = CSqueakAddress.from_verifying_key(verifying_key)
        pubkey_script = address.to_scriptPubKey()

        VerifyScript(sig_script, pubkey_script, data)

    def test_address_to_pubkey(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        address = CSqueakAddress.from_verifying_key(verifying_key)
        pubkey_script = address.to_scriptPubKey()

        address_from_script = CSqueakAddress.from_scriptPubKey(pubkey_script)

        assert address_from_script == address

    def test_address_to_string(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        address = CSqueakAddress.from_verifying_key(verifying_key)
        address_str = str(address)

        address_from_str = CSqueakAddress(address_str)

        assert address_from_str == address
        assert isinstance(address, CSqueakAddress)
        assert isinstance(address_from_str, CSqueakAddress)

    def test_address_to_pubkey_invalid(self):
        with pytest.raises(CBitcoinAddressError):
            CSqueakAddress.from_scriptPubKey(b'')
