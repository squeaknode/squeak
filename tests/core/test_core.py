import os
import time

import pytest

from bitcoin.core import lx

from squeak.core import CSqueakHeader
from squeak.core import CSqueak
from squeak.core import CSqueakEncContent
from squeak.core import SignSqueak
from squeak.core import CheckSqueak
from squeak.core import VerifySqueak
from squeak.core import DecryptContent
from squeak.core import MakeSqueak
from squeak.core import InvalidContentLengthError
from squeak.core import CONTENT_LENGTH
from squeak.core import ENC_CONTENT_LENGTH
from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import INITIALIZATION_VECTOR_LENGTH
from squeak.core.encryption import DATA_KEY_LENGTH
from squeak.core.signing import CSigningKey


@pytest.fixture
def signing_key():
    return CSigningKey.generate()


@pytest.fixture
def verifying_key(signing_key):
    return signing_key.get_verifying_key()


@pytest.fixture
def rsa_private_key():
    return CDecryptionKey.generate()


@pytest.fixture
def rsa_public_key(rsa_private_key):
    return rsa_private_key.get_encryption_key()


@pytest.fixture
def data_key():
    return os.urandom(DATA_KEY_LENGTH)


@pytest.fixture
def iv():
    return os.urandom(INITIALIZATION_VECTOR_LENGTH)


@pytest.fixture
def genesis_block_height():
    return 0


@pytest.fixture
def genesis_block_hash():
    return lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')


@pytest.fixture
def fake_squeak_hash():
    return lx('DEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAF')


@pytest.fixture
def enc_content():
    encrypted_content = CSqueakEncContent(b'\00'*ENC_CONTENT_LENGTH)
    return encrypted_content


@pytest.fixture
def squeak_header_params(verifying_key, rsa_public_key, iv, genesis_block_height, genesis_block_hash, fake_squeak_hash):
    return dict(
        nVersion=1,
        hashReplySqk=fake_squeak_hash,
        hashBlock=genesis_block_hash,
        nBlockHeight=genesis_block_height,
        vchPubkey=verifying_key.serialize(),
        vchEncPubkey=rsa_public_key.serialize(),
        vchIv=iv,
        nTime=1231920354,
        nNonce=2083236893,
    )


@pytest.mark.usefixtures("squeak_header_params")
class TestCSqueakHeader(object):

    @pytest.fixture(autouse=True)
    def _params(self, squeak_header_params):
        self._params = squeak_header_params

    def _build_with_params(self, **extra_params):
        params = {
            **self._params,
            **extra_params,
        }
        return CSqueakHeader(**params)

    def test_serialization(self):
        hello = self._build_with_params()
        serialized = hello.serialize()
        hello2 = CSqueakHeader.deserialize(serialized)

        assert hello == hello2

    def test_serialization_no_params(self):
        hello = CSqueakHeader()
        serialized = hello.serialize()
        hello2 = CSqueakHeader.deserialize(serialized)

        assert hello == hello2

    def test_GetHash(self):
        hello = self._build_with_params()

        assert isinstance(repr(hello), str)

    def test_is_reply_true(self):
        hello = self._build_with_params()

        assert hello.is_reply

    def test_is_reply_false(self):
        hello = self._build_with_params(
            hashReplySqk=lx('00'*32),
        )

        assert not hello.is_reply

    def test_sign_verify(self, signing_key):
        hello = self._build_with_params()
        signature = SignSqueak(signing_key, hello)

        VerifySqueak(hello, signature)


@pytest.mark.usefixtures("squeak_header_params")
class TestCSqueak(object):

    @pytest.fixture(autouse=True)
    def _params(self, squeak_header_params, enc_content):
        self._params = squeak_header_params
        self._enc_content = enc_content

    def _build_with_params(self, **extra_params):
        cipher_content = {
            'encContent': self._enc_content,
        }
        params = {
            **self._params,
            **cipher_content,
            **extra_params,
        }
        return CSqueak(**params)

    def test_serialization(self):
        hello = self._build_with_params()
        serialized = hello.serialize()
        hello2 = CSqueak.deserialize(serialized)

        assert hello == hello2

    def test_serialization_no_params(self):
        hello = CSqueak()
        serialized = hello.serialize()
        hello2 = CSqueak.deserialize(serialized)

        assert hello == hello2

    def test_GetHash(self):
        hello = self._build_with_params()

        assert hello.GetHash() == hello.get_header().GetHash()

    def test_sign_verify(self, signing_key):
        hello = self._build_with_params()
        signature = SignSqueak(signing_key, hello)

        assert signature is not None
        VerifySqueak(hello, signature)


@pytest.mark.usefixtures("squeak_header_params")
class TestMakeSqueak(object):

    def test_make_squeak(self, signing_key, fake_squeak_hash, genesis_block_height, genesis_block_hash):
        content = b"Hello world!"
        padded_content = content.ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, _, signature = MakeSqueak(
            signing_key,
            padded_content,
            genesis_block_height,
            genesis_block_hash,
            timestamp,
            fake_squeak_hash,
        )

        CheckSqueak(squeak)
        VerifySqueak(squeak, signature)

    def test_decrypt_squeak(self, signing_key, fake_squeak_hash, genesis_block_height, genesis_block_hash):
        content = b"Hello world!"
        padded_content = content.ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, decryption_key, signature = MakeSqueak(
            signing_key,
            padded_content,
            genesis_block_height,
            genesis_block_hash,
            timestamp,
            fake_squeak_hash,
        )

        CheckSqueak(squeak)
        VerifySqueak(squeak, signature)
        decrypted_content = DecryptContent(squeak, decryption_key)

        assert decrypted_content.rstrip(b"\00") == content

    def test_make_squeak_content_too_short(self, signing_key, fake_squeak_hash, genesis_block_height, genesis_block_hash):
        with pytest.raises(InvalidContentLengthError):
            content = b"X"*140*4
            timestamp = int(time.time())

            MakeSqueak(
                signing_key,
                content,
                genesis_block_height,
                genesis_block_hash,
                timestamp,
                fake_squeak_hash,
            )
