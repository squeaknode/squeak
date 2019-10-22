import time

import pytest

from bitcoin.core import lx

from squeak.core import CSqueak
from squeak.core import CSqueakHeader
from squeak.core import CheckSqueak
from squeak.core import EncryptContent
from squeak.core import MakeSqueak
from squeak.core import MakeSqueakFromStr
from squeak.core import SignSqueak
from squeak.core import InvalidContentLengthError
from squeak.core import CheckSqueakError
from squeak.core import CheckSqueakHeaderError
from squeak.core import CheckSqueakDataKeyError
from squeak.core import CONTENT_LENGTH
from squeak.core import CheckSqueakSignatureError
from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.signing import CSigningKey
from squeak.core.signing import CSqueakAddress


@pytest.fixture
def signing_key():
    return CSigningKey.generate()


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
def squeak(signing_key, prev_squeak_hash, block_height, block_hash):
    content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
    timestamp = int(time.time())

    squeak = MakeSqueak(
        signing_key,
        content,
        block_height,
        block_hash,
        timestamp,
        prev_squeak_hash,
    )
    return squeak


class TestMakeSqueak(object):

    def test_make_squeak(self, signing_key, prev_squeak_hash, block_height, block_hash):
        content = "Hello world!"
        timestamp = int(time.time())

        squeak = MakeSqueakFromStr(
            signing_key,
            content,
            block_height,
            block_hash,
            timestamp,
            prev_squeak_hash,
        )

        CheckSqueak(squeak)

        address = CSqueakAddress.from_verifying_key(signing_key.get_verifying_key())
        decrypted_content = squeak.GetDecryptedContentStr()

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert squeak.is_reply
        assert squeak.GetAddress() == address
        assert decrypted_content == "Hello world!"

    def test_make_squeak_is_not_reply(self, signing_key, block_height, block_hash):
        content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak = MakeSqueak(
            signing_key,
            content,
            block_height,
            block_hash,
            timestamp,
        )

        CheckSqueak(squeak)

        address = CSqueakAddress.from_verifying_key(signing_key.get_verifying_key())
        decrypted_content = squeak.GetDecryptedContent()

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert not squeak.is_reply
        assert squeak.GetAddress() == address
        assert decrypted_content.rstrip(b"\00") == b"Hello world!"

    def test_make_squeak_content_too_short(self, signing_key, prev_squeak_hash, block_height, block_hash):
        content = b"Hello world!"
        timestamp = int(time.time())

        with pytest.raises(InvalidContentLengthError):
            MakeSqueak(
                signing_key,
                content,
                block_height,
                block_hash,
                timestamp,
                prev_squeak_hash,
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
            scriptPubKey=squeak.scriptPubKey,
            hashDataKey=squeak.hashDataKey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=fake_enc_content,
            vchDataKey=squeak.vchDataKey,
        )

        with pytest.raises(CheckSqueakError):
            CheckSqueak(fake_squeak)

    def test_check_squeak_pubkey_script_invalid(self, squeak):
        fake_squeak = CSqueak(
            hashEncContent=squeak.hashEncContent,
            hashReplySqk=squeak.hashReplySqk,
            hashBlock=squeak.hashBlock,
            nBlockHeight=squeak.nBlockHeight,
            scriptPubKey=b'',
            hashDataKey=squeak.hashDataKey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=squeak.encContent,
            vchDataKey=squeak.vchDataKey,
        )

        with pytest.raises(CheckSqueakHeaderError):
            CheckSqueak(fake_squeak)


class TestCheckSqueakSignature(object):

    def test_verify_squeak_pubkey_sigscript_fails_verify(self, squeak):
        squeak_header = squeak.get_header()
        fake_signing_key = CSigningKey.generate()
        fake_sig_script = SignSqueak(fake_signing_key, squeak_header)

        fake_squeak = CSqueak(
            hashEncContent=squeak.hashEncContent,
            hashReplySqk=squeak.hashReplySqk,
            hashBlock=squeak.hashBlock,
            nBlockHeight=squeak.nBlockHeight,
            scriptPubKey=squeak.scriptPubKey,
            hashDataKey=squeak.hashDataKey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=squeak.encContent,
            scriptSig=fake_sig_script,
            vchDataKey=squeak.vchDataKey,
        )

        with pytest.raises(CheckSqueakSignatureError):
            CheckSqueak(fake_squeak)


class TestCheckSqueakDataKey(object):

    def test_verify_squeak_data_key_check_fails(self, squeak):
        fake_data_key = generate_data_key()

        fake_squeak = CSqueak(
            hashEncContent=squeak.hashEncContent,
            hashReplySqk=squeak.hashReplySqk,
            hashBlock=squeak.hashBlock,
            nBlockHeight=squeak.nBlockHeight,
            scriptPubKey=squeak.scriptPubKey,
            hashDataKey=squeak.hashDataKey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=squeak.encContent,
            scriptSig=squeak.scriptSig,
            vchDataKey=fake_data_key,
        )

        with pytest.raises(CheckSqueakDataKeyError):
            CheckSqueak(fake_squeak)

        CheckSqueak(fake_squeak, skipDecryptionCheck=True)


class TestSerializeSqueak(object):

    def test_serialize_squeak(self, squeak):
        serialized_squeak = squeak.serialize()
        deserialized_squeak = CSqueak.deserialize(serialized_squeak)

        assert deserialized_squeak == squeak
        assert isinstance(squeak, CSqueak)

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

        assert deserialized_squeak_header == squeak_header
        assert isinstance(squeak_header, CSqueakHeader)
