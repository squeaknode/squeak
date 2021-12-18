# MIT License
#
# Copyright (c) 2020 Jonathan Zernik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os

import pytest

from squeak.core import HASH_LENGTH
from squeak.core.signing import PUB_KEY_LENGTH
from squeak.core.signing import SqueakPrivateKey
from squeak.core.signing import SqueakPublicKey


def make_hash():
    return os.urandom(HASH_LENGTH)


@pytest.fixture
def priv_key():
    yield SqueakPrivateKey.generate()


@pytest.fixture
def pub_key(priv_key):
    yield priv_key.get_public_key()


@pytest.fixture
def data():
    return make_hash()


class TestSignVerify(object):

    def test_sign_verify(self, priv_key, pub_key, data):
        signature = priv_key.sign(data)

        # TODO: fix
        # assert len(signature) == SIGNATURE_LENGTH
        assert pub_key.verify(data, signature)

    def test_serialize_deserialize_public_key(self, priv_key, pub_key, data):
        serialized = pub_key.to_bytes()
        deserialized = SqueakPublicKey.from_bytes(serialized)
        serialized2 = deserialized.to_bytes()
        deserialized2 = SqueakPublicKey.from_bytes(serialized2)

        assert deserialized.pub_key.W == pub_key.pub_key.W

        signature = priv_key.sign(data)

        assert pub_key.verify(data, signature)
        assert deserialized2.verify(data, signature)
        assert len(serialized2) == PUB_KEY_LENGTH

    def test_serialize_deserialize_private_key(self, priv_key, pub_key, data):
        serialized = priv_key.to_bytes()
        deserialized_priv_key = SqueakPrivateKey.from_bytes(serialized)

        signature = deserialized_priv_key.sign(data)

        assert pub_key.verify(data, signature)

    # def test_serialize_deserialize_private_key_to_string(self, priv_key, pub_key, data):
    #     priv_key_str = priv_key.to_str()
    #     deserialized_priv_key = SqueakPrivateKey.from_str(priv_key_str)

    #     signature = deserialized_priv_key.sign(data)

    #     assert pub_key.verify(data, signature)

    def test_sign_verify_other_data(self, priv_key, pub_key, data):
        data2 = make_hash()
        signature = priv_key.sign(data)

        assert not pub_key.verify(data2, signature)
