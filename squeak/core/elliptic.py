import os
import struct

from ecpy.ecschnorr import ECSchnorr

from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.formatters import decode_sig, encode_sig, list_formats
from ecpy            import ecrand
from ecpy.curves     import ECPyException

import hashlib


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as data_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_der_private_key


KEY_SIZE = 1024
DATA_KEY_LENGTH = 32
ENCRYPTED_DATA_KEY_LENGTH = 128
CIPHER_BLOCK_LENGTH = 16


CURVE = Curve.get_curve('secp256k1')


def generate_secret_key():
    ## Step 2: Generate random message
    #msg = os.urandom(KEY_LENGTH)
    msg = int(0x0101010101010101010101010101010101010101010101010101010101010101)
    msg = msg.to_bytes(32,'big')

    ## Step 3: Generate key pair
    #x = os.urandom(KEY_LENGTH)
    cv = Curve.get_curve('secp256k1')
    pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                               0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                               cv))
    pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                          cv)

    ## Step 4: Generate random nonce
    #k = int.from_bytes(os.urandom(KEY_LENGTH), 'big')
    k = int(0x4242424242424242424242424242424242424242424242424242424242424242)

    ## Step 5: Calculate signature
    signer = ECSchnorr(hashlib.sha256,"LIBSECP","ITUPLE")
    sig = signer.sign_k(msg,pv_key,k)

    ## Step 6: Verify the signature
    expect_r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
    expect_s = 0xacd417b277ab7e7d993cc4a601dd01a71696fd0dd2e93561d9de9b69dd4dc75c
    r, s = sig
    r_hex = "{:64x}".format(r)
    s_hex = "{:64x}".format(s)
    assert(expect_r == r)
    assert(expect_s == s)
    assert(signer.verify(msg,sig,pu_key))
    return bytes.fromhex(s_hex)


def payment_point_from_secret_key(secret_key):
    G = CURVE.generator
    s_hex = secret_key.hex()
    s = int(s_hex, 16)
    payment_point = s*G
    return bytes(CURVE.encode_point(payment_point, compressed=True))


class CDecryptionKey():

    def __init__(self, private_key=None):
        self.private_key = private_key

    @classmethod
    def generate(cls):
        return cls(_generate_assymetric_decryption_key())

    @classmethod
    def from_bytes(cls, key_bytes):
        return cls(_deserialize_private_key(key_bytes))

    def get_bytes(self):
        return _serialize_private_key(self.private_key)

    def get_encryption_key(self):
        return CEncryptionKey(self.private_key.public_key())

    def decrypt(self, ciphertext):
        return _decrypt_assymetric(ciphertext, self.private_key)

    def __repr__(self):
        return "CDecryptionKey(private_key=%s)" % \
            (repr(self.private_key))


class CEncryptionKey():

    def __init__(self, public_key=None):
        self.public_key = public_key

    @classmethod
    def from_bytes(cls, data):
        public_key = _deserialize_public_key(data)
        return cls(public_key)

    def get_bytes(self):
        return _serialize_public_key(self.public_key)

    def encrypt(self, message):
        return _encrypt_assymetric(message, self.public_key)

    def __repr__(self):
        return "CEncryptionKey(public_key=%s)" % \
            (repr(self.public_key))


class CEncryptedDecryptionKey():

    def __init__(self, cipher_bytes):
        self.cipher_bytes = cipher_bytes

    @classmethod
    def from_decryption_key(cls, decryption_key, preimage, iv):
        decryption_key_bytes = _serialize_private_key(decryption_key.private_key)
        cipher_bytes = encrypt_content(preimage, iv, decryption_key_bytes)
        return cls(cipher_bytes)

    @classmethod
    def from_bytes(cls, cipher_bytes):
        return cls(cipher_bytes)

    def get_decryption_key(self, preimage, iv):
        new_decryption_key_bytes = decrypt_content(preimage, iv, self.cipher_bytes)
        new_decryption_key = CDecryptionKey.from_bytes(new_decryption_key_bytes)
        return new_decryption_key

    def __repr__(self):
        return "CEncryptedDecryptionKey(cipher_bytes=%s)" % \
            (repr(self.cipher_bytes))


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
