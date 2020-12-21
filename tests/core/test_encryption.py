from squeak.core.encryption import _create_data_cipher
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector


PREIMAGE_LENGTH = 32


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
