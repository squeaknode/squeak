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


def generate_assymetric_keys():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend(),
    )


def encrypt_assymetric(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_assymetric(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(public_der_data):
    return load_der_public_key(
        public_der_data,
        backend=default_backend(),
    )


def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(private_der_data):
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
    padder = data_padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def _unpad(padded_data):
    unpadder = data_padding.PKCS7(128).unpadder()
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
