import time

import pytest

from bitcoin.core import lx

from squeak.core import CSqueak
from squeak.core import CheckSqueak
from squeak.core import VerifySqueakSignature
from squeak.core import EncryptContent
from squeak.core import DecryptContent
from squeak.core import MakeSqueak
from squeak.core import InvalidContentLengthError
from squeak.core import CheckSqueakError
from squeak.core import CheckSqueakHeaderError
from squeak.core import CONTENT_LENGTH
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


class TestMakeSqueak(object):

    def test_make_squeak(self, signing_key, prev_squeak_hash, block_height, block_hash):
        content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, decryption_key, signature = MakeSqueak(
            signing_key,
            content,
            block_height,
            block_hash,
            timestamp,
            prev_squeak_hash,
        )

        CheckSqueak(squeak)
        VerifySqueakSignature(squeak, signature)

        address = CSqueakAddress.from_verifying_key(signing_key.get_verifying_key())
        decrypted_content = DecryptContent(squeak, decryption_key)

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert squeak.is_reply
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

    def test_make_squeak_fake_content(self, signing_key, prev_squeak_hash, block_height, block_hash):
        content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, _, _ = MakeSqueak(
            signing_key,
            content,
            block_height,
            block_hash,
            timestamp,
            prev_squeak_hash,
        )

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
            vchEncryptionKey=squeak.vchEncryptionKey,
            vchEncDatakey=squeak.vchEncDatakey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=fake_enc_content,
        )

        with pytest.raises(CheckSqueakError):
            CheckSqueak(fake_squeak)

    def test_make_squeak_pubkey_script_invalid(self, signing_key, prev_squeak_hash, block_height, block_hash):
        content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, _, _ = MakeSqueak(
            signing_key,
            content,
            block_height,
            block_hash,
            timestamp,
            prev_squeak_hash,
        )

        fake_squeak = CSqueak(
            hashEncContent=squeak.hashEncContent,
            hashReplySqk=squeak.hashReplySqk,
            hashBlock=squeak.hashBlock,
            nBlockHeight=squeak.nBlockHeight,
            scriptPubKey=b'',
            vchEncryptionKey=squeak.vchEncryptionKey,
            vchEncDatakey=squeak.vchEncDatakey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=squeak.encContent,
        )

        with pytest.raises(CheckSqueakHeaderError):
            CheckSqueak(fake_squeak)
