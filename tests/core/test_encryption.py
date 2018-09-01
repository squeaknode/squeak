from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import CEncryptionKey
from squeak.core.encryption import KEY_SIZE
from squeak.core.encryption import ENCRYPTION_PUB_KEY_LENGTH


class TestEncryptContent(object):

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
