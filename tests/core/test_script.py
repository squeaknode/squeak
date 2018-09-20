import os

import pytest

from squeak.core import HASH_LENGTH
from squeak.core.signing import CSigningKey
from squeak.core.signing import CSqueakAddress
from squeak.core.script import MakeSigScript
from squeak.core.script import VerifyScript
from squeak.core.script import VerifyScriptError


@pytest.fixture
def make_hash():
    def _make_hash():
        return os.urandom(HASH_LENGTH)
    return _make_hash


class TestSignVerify(object):

    def test_sign_verify_script(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = make_hash()
        signature = signing_key.sign(data)
        address = CSqueakAddress.from_verifying_key(verifying_key)
        pubkey_script = address.to_scriptPubKey()
        sig_script = MakeSigScript(signature, verifying_key)

        VerifyScript(sig_script, pubkey_script, data)

    def test_sign_verify_script_invalid(self, make_hash):
        signing_key = CSigningKey.generate()
        verifying_key = signing_key.get_verifying_key()

        data = make_hash()
        signature = signing_key.sign(data)
        address = CSqueakAddress.from_verifying_key(verifying_key)
        pubkey_script = address.to_scriptPubKey()
        sig_script = MakeSigScript(signature, verifying_key)

        new_data = make_hash()

        with pytest.raises(VerifyScriptError):
            VerifyScript(sig_script, pubkey_script, new_data)
