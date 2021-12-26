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
import time

import pytest
from bitcoin.core import lx

from squeak.core import CheckSqueak
from squeak.core import CheckSqueakError
from squeak.core import CheckSqueakSecretKey
from squeak.core import CheckSqueakSecretKeyError
from squeak.core import CheckSqueakSignatureError
from squeak.core import CONTENT_LENGTH
from squeak.core import CSqueak
from squeak.core import CSqueakHeader
from squeak.core import EncryptContent
from squeak.core import InvalidContentLengthError
from squeak.core import MakeSqueak
from squeak.core import MakeSqueakFromStr
from squeak.core import SECRET_KEY_LENGTH
from squeak.core import SignSqueak
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.keys import SqueakPrivateKey


@pytest.fixture
def priv_key():
    return SqueakPrivateKey.generate()


@pytest.fixture
def pub_key(priv_key):
    return priv_key.get_public_key()


@pytest.fixture
def other_priv_key():
    yield SqueakPrivateKey.generate()


@pytest.fixture
def other_pub_key(other_priv_key):
    yield other_priv_key.get_public_key()


@pytest.fixture
def block_height():
    return 0


@pytest.fixture
def block_hash():
    return lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')


@pytest.fixture
def prev_squeak_hash():
    return lx('DEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAF')


@pytest.fixture
def fake_secret_key():
    return os.urandom(SECRET_KEY_LENGTH)


@pytest.fixture
def squeak_and_key(priv_key, prev_squeak_hash, block_height, block_hash):
    content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
    timestamp = int(time.time())

    squeak = MakeSqueak(
        priv_key,
        content,
        block_height,
        block_hash,
        timestamp,
        reply_to=prev_squeak_hash,
    )
    return squeak


@pytest.fixture
def squeak(squeak_and_key):
    squeak, _ = squeak_and_key
    return squeak


@pytest.fixture
def secret_key(squeak_and_key):
    _, secret_key = squeak_and_key
    return secret_key


class TestMakeSqueak(object):

    def test_make_squeak(self, priv_key, pub_key, prev_squeak_hash, block_height, block_hash):
        content = "Hello world!"
        timestamp = int(time.time())

        squeak, secret_key = MakeSqueakFromStr(
            priv_key,
            content,
            block_height,
            block_hash,
            timestamp,
            reply_to=prev_squeak_hash,
        )

        CheckSqueak(squeak)

        # pub_key = priv_key.get_public_key()
        decrypted_content = squeak.GetDecryptedContentStr(secret_key)

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert squeak.is_reply
        assert squeak.GetPubKey().to_bytes() == pub_key.to_bytes()
        assert decrypted_content == "Hello world!"

    def test_make_squeak_is_not_reply(self, priv_key, pub_key, block_height, block_hash):
        content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, secret_key = MakeSqueak(
            priv_key,
            content,
            block_height,
            block_hash,
            timestamp,
        )

        CheckSqueak(squeak)

        decrypted_content = squeak.GetDecryptedContent(secret_key)

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert not squeak.is_reply
        assert squeak.GetPubKey().to_bytes() == pub_key.to_bytes()
        assert decrypted_content.rstrip(b"\00") == b"Hello world!"

    def test_make_squeak_is_private_message(self, priv_key, pub_key, other_priv_key, other_pub_key, block_height, block_hash):
        content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, secret_key = MakeSqueak(
            priv_key,
            content,
            block_height,
            block_hash,
            timestamp,
            recipient=other_pub_key,
        )

        CheckSqueak(squeak)

        with pytest.raises(Exception):
            squeak.GetDecryptedContent(secret_key)

        decrypted_content = squeak.GetDecryptedContent(secret_key, recipientPrivKey=other_priv_key)

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert not squeak.is_reply
        assert squeak.is_private_message
        assert squeak.GetPubKey().to_bytes() == pub_key.to_bytes()
        assert decrypted_content.rstrip(b"\00") == b"Hello world!"

    def test_make_squeak_content_too_short(self, priv_key, prev_squeak_hash, block_height, block_hash):
        content = b"Hello world!"
        timestamp = int(time.time())

        with pytest.raises(InvalidContentLengthError):
            MakeSqueak(
                priv_key,
                content,
                block_height,
                block_hash,
                timestamp,
                reply_to=prev_squeak_hash,
            )


class TestCheckSqueak(object):

    def test_check_squeak_fake_content(self, squeak):
        fake_enc_content = EncryptContent(
            generate_data_key(),
            generate_initialization_vector(),
            b"This is fake!".ljust(CONTENT_LENGTH, b"\x00"),
        )
        fake_squeak = CSqueak(
            hashEncContent=squeak.hashEncContent,
            hashReplySqk=squeak.hashReplySqk,
            hashBlock=squeak.hashBlock,
            nBlockHeight=squeak.nBlockHeight,
            pubKey=squeak.pubKey,
            paymentPoint=squeak.paymentPoint,
            iv=squeak.iv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=fake_enc_content,
        )

        with pytest.raises(CheckSqueakError):
            CheckSqueak(fake_squeak)

    # def test_check_squeak_pubkey_script_invalid(self, squeak):
    #     fake_squeak = CSqueak(
    #         hashEncContent=squeak.hashEncContent,
    #         hashReplySqk=squeak.hashReplySqk,
    #         hashBlock=squeak.hashBlock,
    #         nBlockHeight=squeak.nBlockHeight,
    #         paymentPoint=squeak.paymentPoint,
    #         iv=squeak.iv,
    #         nTime=squeak.nTime,
    #         nNonce=squeak.nNonce,
    #         encContent=squeak.encContent,
    #     )

    #     with pytest.raises(CheckSqueakHeaderError):
    #         CheckSqueak(fake_squeak)


class TestCheckSqueakSignature(object):

    def test_verify_squeak_pubkey_sig_fails_verify(self, squeak):
        squeak_header = squeak.get_header()
        fake_priv_key = SqueakPrivateKey.generate()
        fake_sig = SignSqueak(fake_priv_key, squeak_header)

        fake_squeak = CSqueak(
            hashEncContent=squeak.hashEncContent,
            hashReplySqk=squeak.hashReplySqk,
            hashBlock=squeak.hashBlock,
            nBlockHeight=squeak.nBlockHeight,
            pubKey=squeak.pubKey,
            paymentPoint=squeak.paymentPoint,
            iv=squeak.iv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=squeak.encContent,
            sig=fake_sig,
        )

        with pytest.raises(CheckSqueakSignatureError):
            CheckSqueak(fake_squeak)


class TestCheckSqueakSecreKey(object):

    def test_verify_squeak_secret_key_check(self, squeak, secret_key):
        CheckSqueak(squeak)
        CheckSqueakSecretKey(squeak, secret_key)

    def test_verify_squeak_secret_key_check_fails(self, squeak, fake_secret_key):
        CheckSqueak(squeak)
        with pytest.raises(CheckSqueakSecretKeyError):
            CheckSqueakSecretKey(squeak, fake_secret_key)


class TestSerializeSqueak(object):

    def test_serialize_squeak(self, squeak, secret_key):
        serialized_squeak = squeak.serialize()
        deserialized_squeak = CSqueak.deserialize(serialized_squeak)

        assert len(serialized_squeak) == 1427
        assert deserialized_squeak == squeak
        assert isinstance(squeak, CSqueak)
        assert squeak.GetDecryptedContent(secret_key) == \
            deserialized_squeak.GetDecryptedContent(secret_key)

    def test_serialize_squeak_null(self):
        squeak = CSqueak()
        serialized_squeak = squeak.serialize()
        deserialized_squeak = CSqueak.deserialize(serialized_squeak)

        assert deserialized_squeak == squeak
        assert isinstance(squeak, CSqueak)

    def test_serialize_squeak_header(self, squeak):
        squeak_header = squeak.get_header()
        serialized_squeak_header = squeak_header.serialize()
        deserialized_squeak_header = CSqueakHeader.deserialize(serialized_squeak_header)

        assert len(serialized_squeak_header) == 227
        assert deserialized_squeak_header == squeak_header
        assert isinstance(squeak_header, CSqueakHeader)
