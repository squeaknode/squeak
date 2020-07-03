from squeak.core.encryption import _create_data_cipher
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import CEncryptionKey
from squeak.core.encryption import KEY_SIZE
from squeak.core.encryption import ENCRYPTION_PUB_KEY_LENGTH


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

        public_key_data = public_key.serialize()
        private_key_data = private_key.serialize()

        assert public_key.public_key.key_size == KEY_SIZE
        assert isinstance(public_key_data, bytes)
        assert len(public_key_data) == ENCRYPTION_PUB_KEY_LENGTH
        assert isinstance(private_key_data, bytes)

        deserialized_public_key = CEncryptionKey.deserialize(public_key_data)
        deserialized_private_key = CDecryptionKey.deserialize(private_key_data)

        assert isinstance(deserialized_public_key, CEncryptionKey)
        assert isinstance(deserialized_private_key, CDecryptionKey)

        public_key_data_again = deserialized_public_key.serialize()
        private_key_data_again = deserialized_private_key.serialize()

        assert public_key_data_again == public_key_data
        assert private_key_data_again == private_key_data
