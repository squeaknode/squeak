import os
import struct

from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import BytesSerializer
from bitcoin.core.serialize import ser_read
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as data_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_SIZE = 1024
ENCRYPTION_PUB_KEY_LENGTH = 162
DATA_KEY_LENGTH = 32
ENCRYPTED_DATA_KEY_LENGTH = 128
CIPHER_BLOCK_LENGTH = 16


def _create_data_cipher(key, iv):
    return Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )


def _pad(data):
    block_size = _block_size_bits()
    padder = data_padding.PKCS7(block_size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def _unpad(padded_data):
    block_size = _block_size_bits()
    unpadder = data_padding.PKCS7(block_size).unpadder()
    data = unpadder.update(padded_data)
    return data + unpadder.finalize()


def _block_size_bits():
    return CIPHER_BLOCK_LENGTH * 8


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
    return os.urandom(CIPHER_BLOCK_LENGTH)


def generate_nonce():
    data = os.urandom(4)
    return struct.unpack(b"<I", data)[0]
