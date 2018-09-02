import os
import struct

from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import VarStringSerializer
from bitcoin.core.serialize import ser_read
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as data_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_der_private_key


KEY_SIZE = 1024
ENCRYPTION_PUB_KEY_LENGTH = 162
DATA_KEY_LENGTH = 32
ENCRYPTED_DATA_KEY_LENGTH = 128
INITIALIZATION_VECTOR_LENGTH = 16
CIPHER_BLOCK_SIZE = 128


class CDecryptionKey(Serializable):

    def __init__(self, private_key):
        self.private_key = private_key

    @classmethod
    def stream_deserialize(cls, f):
        data = VarStringSerializer.stream_deserialize(f)
        return cls(_deserialize_private_key(data))

    @classmethod
    def generate(cls):
        return cls(_generate_assymetric_decryption_key())

    def stream_serialize(self, f):
        data = _serialize_private_key(self.private_key)
        VarStringSerializer.stream_serialize(data, f)

    def get_encryption_key(self):
        return CEncryptionKey(self.private_key.public_key())

    def decrypt(self, ciphertext):
        return _decrypt_assymetric(ciphertext, self.private_key)

    def __repr__(self):
        return "CDecryptionKey(private_key=%s)" % \
            (repr(self.private_key))


class CEncryptionKey(Serializable):

    def __init__(self, public_key):
        self.public_key = public_key

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f, ENCRYPTION_PUB_KEY_LENGTH)
        return cls(_deserialize_public_key(data))

    def stream_serialize(self, f):
        data = _serialize_public_key(self.public_key)
        f.write(data)

    def encrypt(self, message):
        return _encrypt_assymetric(message, self.public_key)

    def __repr__(self):
        return "CEncryptionKey(public_key=%s)" % \
            (repr(self.public_key))


def _generate_assymetric_decryption_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend(),
    )


def _get_assymetric_encryption_key(private_key):
    return private_key.public_key()


def _encrypt_assymetric(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _decrypt_assymetric(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _deserialize_public_key(public_der_data):
    return load_der_public_key(
        public_der_data,
        backend=default_backend(),
    )


def _serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _deserialize_private_key(private_der_data):
    return load_der_private_key(
        private_der_data,
        backend=default_backend(),
        password=None,
    )


def _create_data_cipher(key, iv):
    return Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )


def _pad(data):
    padder = data_padding.PKCS7(CIPHER_BLOCK_SIZE).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def _unpad(padded_data):
    unpadder = data_padding.PKCS7(CIPHER_BLOCK_SIZE).unpadder()
    data = unpadder.update(padded_data)
    return data + unpadder.finalize()


def encrypt_content(key, iv, content):
    encryptor = _create_data_cipher(key, iv).encryptor()
    padded_content = _pad(content)
    return encryptor.update(padded_content) + encryptor.finalize()


def decrypt_content(key, iv, cipher):
    decryptor = _create_data_cipher(key, iv).decryptor()
    padded_content = decryptor.update(cipher) + decryptor.finalize()
    return _unpad(padded_content)


def generate_data_key():
    return os.urandom(DATA_KEY_LENGTH)


def generate_initialization_vector():
    return os.urandom(INITIALIZATION_VECTOR_LENGTH)


def generate_nonce():
    data = os.urandom(4)
    return struct.unpack(b"<I", data)[0]
