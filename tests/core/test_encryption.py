from cryptography.hazmat.primitives.asymmetric import rsa

from squeak.core.encryption import generate_assymetric_keys
from squeak.core.encryption import encrypt_assymetric
from squeak.core.encryption import decrypt_assymetric
from squeak.core.encryption import serialize_public_key
from squeak.core.encryption import serialize_private_key
from squeak.core.encryption import deserialize_public_key
from squeak.core.encryption import deserialize_private_key
from squeak.core.encryption import KEY_SIZE


class TestEncryptContent(object):

    def test_encrypt_decrypt_assymetric(self):
        private_key = generate_assymetric_keys()
        public_key = private_key.public_key()

        message = b"encrypted data"

        encrypted_msg = encrypt_assymetric(message, public_key)
        decrypted_msg = decrypt_assymetric(encrypted_msg, private_key)

        assert decrypted_msg == message
        assert public_key.key_size == KEY_SIZE

    def test_serialize_deserialize_assymetric_key(self):
        private_key = generate_assymetric_keys()
        public_key = private_key.public_key()

        public_key_data = serialize_public_key(public_key)
        private_key_data = serialize_private_key(private_key)

        assert public_key.key_size == KEY_SIZE
        assert isinstance(public_key_data, bytes)
        assert len(public_key_data) == 162
        assert isinstance(private_key_data, bytes)

        deserialized_public_key = deserialize_public_key(public_key_data)
        deserialized_private_key = deserialize_private_key(private_key_data)

        assert isinstance(deserialized_public_key, rsa.RSAPublicKey)
        assert isinstance(deserialized_private_key, rsa.RSAPrivateKey)

        public_key_data_again = serialize_public_key(deserialized_public_key)
        private_key_data_again = serialize_private_key(deserialized_private_key)

        assert public_key_data_again == public_key_data
        assert private_key_data_again == private_key_data
