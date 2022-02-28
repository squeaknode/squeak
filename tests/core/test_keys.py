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
from squeak.core.keys import InvalidPrivateKeyError
from squeak.core.keys import InvalidPublicKeyError
from squeak.core.keys import PRIV_KEY_LENGTH
from squeak.core.keys import PUB_KEY_LENGTH
from squeak.core.keys import SIGNATURE_LENGTH
from squeak.core.keys import SqueakPrivateKey
from squeak.core.keys import SqueakPublicKey


def make_hash():
    return os.urandom(HASH_LENGTH)


@pytest.fixture
def seed_words():
    return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@pytest.fixture
def pubkey_from_seed_hex():
    return ""


@pytest.fixture
def priv_key():
    yield SqueakPrivateKey.generate()


@pytest.fixture
def pub_key(priv_key):
    yield priv_key.get_public_key()


@pytest.fixture
def other_priv_key():
    yield SqueakPrivateKey.generate()


@pytest.fixture
def other_pub_key(other_priv_key):
    yield other_priv_key.get_public_key()


@pytest.fixture
def data():
    return make_hash()


class TestSerialization(object):

    def test_serialize_deserialize_public_key(self, priv_key, pub_key, data):
        serialized = pub_key.to_bytes()
        deserialized = SqueakPublicKey.from_bytes(serialized)
        serialized2 = deserialized.to_bytes()
        deserialized2 = SqueakPublicKey.from_bytes(serialized2)

        assert deserialized == pub_key

        signature = priv_key.sign(data)

        assert pub_key.verify(data, signature)
        assert deserialized2.verify(data, signature)
        assert len(serialized2) == PUB_KEY_LENGTH

    def test_serialize_deserialize_private_key(self, priv_key, pub_key, data):
        serialized = priv_key.to_bytes()
        deserialized_priv_key = SqueakPrivateKey.from_bytes(serialized)

        assert deserialized_priv_key == priv_key

        signature = deserialized_priv_key.sign(data)

        assert len(serialized) == PRIV_KEY_LENGTH
        assert pub_key.verify(data, signature)

    def test_deserialize_invalid_private_key(self):
        invalid_private_key_bytes = b""

        with pytest.raises(InvalidPrivateKeyError):
            SqueakPrivateKey.from_bytes(invalid_private_key_bytes)

    def test_deserialize_invalid_public_key(self):
        invalid_public_key_bytes = b""

        with pytest.raises(InvalidPublicKeyError):
            SqueakPublicKey.from_bytes(invalid_public_key_bytes)

        invalid_bytes = bytes.fromhex("aa5f3b031505bb157c9ce26bf36bea93535921dfd124e9361aee84db1f9abde199")

        with pytest.raises(InvalidPublicKeyError):
            SqueakPublicKey.from_bytes(invalid_bytes)

    def test_hash_public_key(self, pub_key):

        assert hash(pub_key) == hash(pub_key.to_bytes())

    def test_hash_private_key(self, priv_key):

        assert hash(priv_key) == hash(priv_key.to_bytes())

    def test_compare_public_key(self, pub_key, other_pub_key):

        assert pub_key != other_pub_key

    def test_compare_private_key(self, priv_key, other_priv_key):

        assert priv_key != other_priv_key


class TestSignVerify(object):

    def test_sign_verify(self, priv_key, pub_key, data):
        signature = priv_key.sign(data)

        assert len(signature) == SIGNATURE_LENGTH
        assert pub_key.verify(data, signature)

    def test_sign_verify_other_data(self, priv_key, pub_key, data):
        data2 = make_hash()
        signature = priv_key.sign(data)

        assert not pub_key.verify(data2, signature)


class TestSeedWords(object):

    def test_public_key_from_seed(self, seed_words, pubkey_from_seed_hex):
        private_key = SqueakPrivateKey.from_seed_words(seed_words)
        public_key = private_key.get_public_key()

        # assert pubkey_from_seed_hex == public_key.to_bytes()
        assert len(public_key.to_bytes()) == 33


class TestSharedSecret(object):

    def test_get_shared_key(self, priv_key, pub_key, other_priv_key, other_pub_key):
        shared_secret_1 = priv_key.get_shared_key(other_pub_key)
        shared_secret_2 = other_priv_key.get_shared_key(pub_key)

        assert shared_secret_1 == shared_secret_2
        assert len(shared_secret_1) == 32
