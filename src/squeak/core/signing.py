from secp256k1 import PrivateKey
from secp256k1 import PublicKey


def generate_signing_key():
    return PrivateKey()


def get_verifying_key(signing_key):
    return signing_key.pubkey


def serialize_verifying_key(verifying_key):
    return verifying_key.serialize()


def deserialize_verifying_key(key_data):
    return PublicKey(key_data, raw=True)


def sign(data, signing_key):
    return signing_key.ecdsa_sign(data)


def verify(data, signature, verifying_key):
    return verifying_key.ecdsa_verify(data, signature)


def serialize_signature(signature):
    return PrivateKey().ecdsa_serialize_compact(signature)


def deserialize_signature(signature_data):
    return PrivateKey().ecdsa_deserialize_compact(signature_data)
