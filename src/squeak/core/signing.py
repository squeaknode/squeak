import os

import hashlib

from bitcoin.core.key import CECKey
from bitcoin.core.key import CPubKey
from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import ser_read
from bitcoin.wallet import CBitcoinSecret
from bitcoin.wallet import P2PKHBitcoinAddress

from squeak.core.script import CScript


PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64  # Only if the signature is compacted
SIGHASH_ALL = b'\01'


class CSigningKey(object):
    """Represents a DSA signing key.

    Args:
        private_key (CECKey): An elliptic curve private key.

    """

    def __init__(self, private_key):
        self.private_key = private_key

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        # TODO
        # c.key =
        return c

    @classmethod
    def generate(cls):
        secret = CSqueakSecret.generate()
        return cls.from_secret(secret)

    @classmethod
    def from_secret(cls, secret):
        private_key = CECKey()
        private_key.set_secretbytes(secret)
        private_key.set_compressed(True)
        return cls(private_key)

    def get_verifying_key(self):
        public_key = CPubKey(self.private_key.get_pubkey(), self.private_key)
        return CVerifyingKey(public_key)

    def sign(self, data):
        signature = self.private_key.sign(data)
        return signature

    def sign_to_scriptSig(self, data):
        signature = self.sign(data)
        verifying_key = self.get_verifying_key()
        pubkey_bytes = verifying_key.serialize()
        script = CScript()
        script += (signature + SIGHASH_ALL)
        script += pubkey_bytes
        return script

    def __repr__(self):
        return "CSigningKey(private_key=%s)" % \
            (repr(self.private_key))


class CVerifyingKey(Serializable):
    """Represents a DSA verifying key.

    Args:
        public_key (CPubKey): An elliptic curve public key.

    """

    def __init__(self, public_key):
        self.public_key = public_key

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f, PUB_KEY_LENGTH)
        return CPubKey(data)

    def stream_serialize(self, f):
        data = bytes(self.public_key)
        f.write(data)

    def verify(self, data, signature):
        return self.public_key.verify(data, signature)

    def __repr__(self):
        return "CVerifyingKey(public_key=%s)" % \
            (repr(self.public_key))


class CSqueakAddress(P2PKHBitcoinAddress):

    @classmethod
    def from_verifying_key(cls, verifying_key):
        return cls.from_pubkey(verifying_key.public_key)


class CSqueakSecret(CBitcoinSecret):
    # TODO: Override BASE58_PREFIXES

    @classmethod
    def generate(cls):
        return cls.from_secret_bytes(_generate_secret_bytes())


def _generate_secret_bytes():
    ## https://en.bitcoin.it/wiki/Private_key#Range_of_valid_ECDSA_private_keys
    min_key = b'\00' * 31 + b'\01'
    max_key = bytes.fromhex('FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140')

    h = b'\00' * 32
    while h < min_key or h > max_key:
        h = hashlib.sha256(os.urandom(128)).digest()
    return h
