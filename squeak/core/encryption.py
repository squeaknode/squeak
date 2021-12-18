# MIT License
#
# Copyright (c) 2020 Jonathan Zernik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as data_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key


KEY_SIZE = 1024
DATA_KEY_LENGTH = 32
ENCRYPTED_DATA_KEY_LENGTH = 128
CIPHER_BLOCK_LENGTH = 16


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
