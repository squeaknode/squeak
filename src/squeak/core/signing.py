import os

from bitcoin.core.key import CPubKey
from bitcoin.wallet import CKey


def generate_signing_key():
    secret = os.urandom(32)
    return CKey(secret)


def get_verifying_key(signing_key):
    return signing_key.pub


def serialize_verifying_key(verifying_key):
    return bytes(verifying_key)


def deserialize_verifying_key(key_data):
    return CPubKey(key_data)


def sign(data, signing_key):
    return signing_key.sign(data)


def verify(data, signature, verifying_key):
    return verifying_key.verify(data, signature)
