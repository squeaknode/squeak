import os
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
from squeak.core import CONTENT_LENGTH
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
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
    return os.urandom(CIPHER_BLOCK_LENGTH)


@pytest.fixture
def genesis_block_height():
    return 0


@pytest.fixture
def genesis_block_hash():
    return lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')


@pytest.fixture
def fake_squeak_hash():
    return lx('DEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAF')


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
        VerifySqueakSignature(squeak, signature)

        assert squeak.GetHash() == squeak.get_header().GetHash()
        assert squeak.is_reply

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
        VerifySqueakSignature(squeak, signature)
        decrypted_content = DecryptContent(squeak, decryption_key)

        assert decrypted_content.rstrip(b"\00") == content

    def test_make_squeak_content_too_short(self, signing_key, fake_squeak_hash, genesis_block_height, genesis_block_hash):
        content = b"X"*140*4
        timestamp = int(time.time())

        with pytest.raises(InvalidContentLengthError):
            MakeSqueak(
                signing_key,
                content,
                genesis_block_height,
                genesis_block_hash,
                timestamp,
                fake_squeak_hash,
            )

    def test_make_squeak_fake_content(self, signing_key, fake_squeak_hash, genesis_block_height, genesis_block_hash):
        content = b"Hello world!"
        padded_content = content.ljust(CONTENT_LENGTH, b"\x00")
        timestamp = int(time.time())

        squeak, _, _ = MakeSqueak(
            signing_key,
            padded_content,
            genesis_block_height,
            genesis_block_hash,
            timestamp,
            fake_squeak_hash,
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
            vchPubkey=squeak.vchPubkey,
            vchEncPubkey=squeak.vchEncPubkey,
            vchEncDatakey=squeak.vchEncDatakey,
            vchIv=squeak.vchIv,
            nTime=squeak.nTime,
            nNonce=squeak.nNonce,
            encContent=fake_enc_content,
        )

        with pytest.raises(CheckSqueakError):
            CheckSqueak(fake_squeak)
