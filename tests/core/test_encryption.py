import os

import pytest

from squeak.core.encryption import _create_data_cipher
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import CEncryptionKey
from squeak.core.encryption import CEncryptedDecryptionKey
from squeak.core.encryption import KEY_SIZE


PREIMAGE_LENGTH = 32


@pytest.fixture
def fake_preimage():
    return os.urandom(PREIMAGE_LENGTH)


class TestEncryptionCipher(object):

    def test_cipher_block_size(self):
        data_key = generate_data_key()
        initialization_vector = generate_initialization_vector()
        cipher = _create_data_cipher(data_key, initialization_vector)

        assert cipher.algorithm.block_size == CIPHER_BLOCK_LENGTH * 8


class TestEncryptContent(object):

    def test_encrypt_decrypt(self):
        data_key = generate_data_key()
        initialization_vector = generate_initialization_vector()
        message = b"encrypted data"

        encrypted_msg = encrypt_content(data_key, initialization_vector, message)
        decrypted_msg = decrypt_content(data_key, initialization_vector, encrypted_msg)

        assert decrypted_msg == message

    def test_encrypt_decrypt_assymetric(self):
        private_key = CDecryptionKey.generate()
        public_key = private_key.get_encryption_key()

        message = b"encrypted data"

        encrypted_msg = public_key.encrypt(message)
        decrypted_msg = private_key.decrypt(encrypted_msg)

        assert decrypted_msg == message
        assert public_key.public_key.key_size == KEY_SIZE

    def test_serialize_deserialize_assymetric_key(self):
        private_key = CDecryptionKey.generate()
        public_key = private_key.get_encryption_key()

        public_key_data = public_key.get_bytes()
        private_key_data = private_key.get_bytes()

        assert public_key.public_key.key_size == KEY_SIZE
        assert isinstance(public_key_data, bytes)
        assert len(public_key_data) > 0
        assert isinstance(private_key_data, bytes)

        deserialized_public_key = CEncryptionKey.from_bytes(public_key_data)
        deserialized_private_key = CDecryptionKey.from_bytes(private_key_data)

        assert isinstance(deserialized_public_key, CEncryptionKey)
        assert isinstance(deserialized_private_key, CDecryptionKey)

        public_key_data_again = deserialized_public_key.get_bytes()
        private_key_data_again = deserialized_private_key.get_bytes()

        assert public_key_data_again == public_key_data
        assert private_key_data_again == private_key_data


class TestEncryptedDecryptionKey(object):

    def test_encrypt_decrypt(self, fake_preimage):
        # Create the encryption/decryption key pair.
        iv = generate_initialization_vector()
        private_key = CDecryptionKey.generate()
        public_key = private_key.get_encryption_key()

        message = b"encrypted data"
        encrypted_msg = public_key.encrypt(message)

        # Encrypt the decryption key
        encrypted_decryption_key = CEncryptedDecryptionKey.from_decryption_key(private_key, fake_preimage, iv)

        assert encrypted_decryption_key is not None

        # Decrypt the decryption key
        new_decryption_key = encrypted_decryption_key.get_decryption_key(fake_preimage, iv)

        assert new_decryption_key is not None

        # Decrypt the original message with the decrypted decryption key.
        decrypted_msg = new_decryption_key.decrypt(encrypted_msg)

        assert decrypted_msg == message
        assert public_key.public_key.key_size == KEY_SIZE
