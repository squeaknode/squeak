import os

import pytest

from bitcoin.core import lx

from squeak.core import CSqueakHeader
from squeak.core import CSqueak
from squeak.core import SignSqueak
from squeak.core import VerifySqueak
from squeak.core import EncryptContent
from squeak.core import DecryptContent
from squeak.core import EncryptDataKey
from squeak.core.encryption import generate_assymetric_keys
from squeak.core.encryption import serialize_public_key
from squeak.core.signing import generate_signing_key
from squeak.core.signing import get_verifying_key


@pytest.fixture
def signing_key():
    return generate_signing_key()


@pytest.fixture
def verifying_key(signing_key):
    return get_verifying_key(signing_key)


@pytest.fixture
def rsa_private_key():
    return generate_assymetric_keys()


@pytest.fixture
def rsa_public_key(rsa_private_key):
    return rsa_private_key.public_key()


@pytest.fixture
def data_key():
    return os.urandom(32)


@pytest.fixture
def iv():
    return os.urandom(16)


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
def squeak_header_params(verifying_key, rsa_public_key, iv, genesis_block_height, genesis_block_hash, fake_squeak_hash):
    return dict(
        nVersion=1,
        vchPubkey=verifying_key,
        vchEncPubkey=serialize_public_key(rsa_public_key),
        vchIv=iv,
        nBlockHeight=genesis_block_height,
        hashBlock=genesis_block_hash,
        hashReplySqk=fake_squeak_hash,
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

        assert VerifySqueak(hello, signature)


@pytest.mark.usefixtures("squeak_header_params")
class TestCSqueak(object):

    @pytest.fixture(autouse=True)
    def _params(self, squeak_header_params):
        self._params = squeak_header_params

    def _build_with_params(self, **extra_params):
        random_cipher_content = {
            'strEncContent': os.urandom(128),
        }
        params = {
            **self._params,
            **random_cipher_content,
            **extra_params,
        }
        return CSqueak(**params)

    def test_serialization(self):
        hello = self._build_with_params()
        serialized = hello.serialize()
        hello2 = CSqueak.deserialize(serialized)

        assert hello == hello2

    def test_GetHash(self):
        hello = self._build_with_params()

        assert hello.GetHash() == hello.get_header().GetHash()

    def test_encrypted_content_too_long(self):
        with pytest.raises(AssertionError):
            self._build_with_params(
                strEncContent=b'X'*1137,
            )

    def test_sign_verify(self, signing_key):
        hello = self._build_with_params()
        signature = SignSqueak(signing_key, hello)

        assert signature is not None
        assert VerifySqueak(hello, signature)

    def test_encrypt_decrypt(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b"hello world!"
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        hello = self._build_with_params(
            vchEncDatakey=data_key_cipher,
            strEncContent=encrypted_content,
        )
        decrypted_content = DecryptContent(hello, rsa_private_key)

        assert decrypted_content == content

    def test_content_length(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b"X" * 280 * 4
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        self._build_with_params(
            vchEncDatakey=data_key_cipher,
            strEncContent=encrypted_content,
        )

        assert True

    def test_content_length_too_long(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b"X" * 284 * 4
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        with pytest.raises(AssertionError):
            self._build_with_params(
                vchEncDatakey=data_key_cipher,
                strEncContent=encrypted_content,
            )

    def test_content_length_zero(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b""
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        empty_squeak = self._build_with_params(
            vchEncDatakey=data_key_cipher,
            strEncContent=encrypted_content,
        )
        decrypted_content = DecryptContent(empty_squeak, rsa_private_key)

        assert decrypted_content == content
