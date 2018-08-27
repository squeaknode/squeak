import os

import pytest

from bitcoin.core import lx
from bitcoin.wallet import CKey

from squeak.core import CSqueakHeader
from squeak.core import CSqueak
from squeak.core import SignSqueak
from squeak.core import VerifySqueak
from squeak.core import EncryptContent
from squeak.core import DecryptContent
from squeak.core import EncryptDataKey
from squeak.core.encryption import generate_assymetric_keys
from squeak.core.encryption import serialize_public_key


@pytest.fixture
def private_key():
    return CKey(b'deadbeef')


@pytest.fixture
def public_key(private_key):
    return private_key.pub


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
def squeak_header_params(public_key, rsa_public_key, iv, genesis_block_height, genesis_block_hash, fake_squeak_hash):
    return dict(
        nVersion=1,
        vchPubkey=public_key._cec_key.get_pubkey(),
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

    def test_serialization(self):
        hello = CSqueakHeader(
            **self._params,
        )
        serialized = hello.serialize()
        hello2 = CSqueakHeader.deserialize(serialized)

        assert hello == hello2

    def test_GetHash(self):
        hello = CSqueakHeader(
            **self._params,
        )

        assert isinstance(repr(hello), str)

    def test_is_reply_true(self):
        hello = CSqueakHeader(
            **self._params,
        )

        assert hello.is_reply

    def test_is_reply_false(self):
        params = {
            **self._params,
            'hashReplySqk': lx('00'*32),
        }
        hello = CSqueakHeader(
            **params,
        )

        assert not hello.is_reply

    def test_sign_verify(self, private_key):
        hello = CSqueakHeader(
            **self._params,
        )
        signature = SignSqueak(private_key, hello)

        # assert len(private_key._cec_key.get_privkey()) == 33
        assert len(private_key.pub._cec_key.get_pubkey()) == 33
        # assert len(signature) == 70 # TODO: use fixed length, compressed signature.
        assert VerifySqueak(hello, signature)


@pytest.mark.usefixtures("squeak_header_params")
class TestCSqueak(object):

    @pytest.fixture(autouse=True)
    def _params(self, squeak_header_params):
        self._params = squeak_header_params

    def test_serialization(self):
        hello = CSqueak(
            **self._params,
            strEncContent=b'hello world!',
        )
        serialized = hello.serialize()
        hello2 = CSqueak.deserialize(serialized)

        assert hello == hello2

    def test_GetHash(self):
        hello = CSqueak(
            **self._params,
            strEncContent=b'hello world!',
        )

        assert hello.GetHash() == hello.get_header().GetHash()

    def test_content_too_long(self):
        with pytest.raises(AssertionError):
            CSqueak(
                **self._params,
                strEncContent=b'hello'*100,
            )

    def test_sign_verify(self, private_key):
        hello = CSqueak(
            **self._params,
        )
        signature = SignSqueak(private_key, hello)

        assert signature is not None
        assert VerifySqueak(hello, signature)

    def test_encrypt_decrypt(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b"hello world!"
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        hello = CSqueak(
            **self._params,
            vchEncDatakey=data_key_cipher,
            strEncContent=encrypted_content,
        )
        decrypted_content = DecryptContent(hello, rsa_private_key)

        assert decrypted_content == content

    def test_content_length(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b"X"*280
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        CSqueak(
            **self._params,
            vchEncDatakey=data_key_cipher,
            strEncContent=encrypted_content,
        )

        assert True

    def test_content_length_too_long(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b"X"*290
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        with pytest.raises(AssertionError):
            CSqueak(
                **self._params,
                vchEncDatakey=data_key_cipher,
                strEncContent=encrypted_content,
            )

    def test_content_length_zero(self, rsa_private_key, rsa_public_key, data_key, iv):
        content = b""
        encrypted_content = EncryptContent(data_key, iv, content)
        data_key_cipher = EncryptDataKey(rsa_public_key, data_key)
        empty_squeak = CSqueak(
            **self._params,
            vchEncDatakey=data_key_cipher,
            strEncContent=encrypted_content,
        )
        decrypted_content = DecryptContent(empty_squeak, rsa_private_key)

        assert decrypted_content == content
