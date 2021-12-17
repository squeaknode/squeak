import hashlib
import os
import secrets

from ecpy.keys import ECPrivateKey
from ecpy.keys import ECPublicKey
from ecpy.ecschnorr import ECSchnorr
from ecpy.ecdsa      import ECDSA

from bitcoin.core.key import CPubKey
from bitcoin.wallet import CBitcoinAddressError
from bitcoin.wallet import CBitcoinSecret
from bitcoin.wallet import P2PKHBitcoinAddress

from ecpy.curves import Curve

from secp256k1 import PrivateKey, PublicKey


PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64  # Only if the signature is compacted


class SqueakPrivateKey:
    """Represents a squeak private key.

    """

    def __init__(self, priv_key):
        self.priv_key = priv_key

    @classmethod
    def generate(cls):
        priv_key = PrivateKey()
        return cls(priv_key=priv_key)

    def sign(self, msg):
        return self.priv_key.schnorr_sign(msg, '', raw=True)

    def get_public_key(self):
        pub_key = self.priv_key.pubkey
        return SqueakPublicKey(pub_key=pub_key)

    def to_bytes(self):
        return self.priv_key.private_key

    def to_str(self):
        return self.priv_key.serialize()

    @classmethod
    def from_bytes(cls, priv_key_bytes):
        priv_key = PrivateKey(privkey=priv_key_bytes, raw=True)
        return cls(priv_key)

    @classmethod
    def from_str(cls, priv_key_str):
        priv_key = PrivateKey(privkey=priv_key_str, raw=False)
        return cls(priv_key)


class SqueakPublicKey:
    """Represents a squeak public key.

    """

    def __init__(self, pub_key):
        self.pub_key = pub_key

    def verify(self, msg, sig):
        return self.pub_key.schnorr_verify(msg, sig, '', raw=True)

    def to_bytes(self):
        return self.pub_key.serialize(compressed=True)

    @classmethod
    def from_bytes(cls, pub_key_bytes):
        pub_key = PublicKey(pubkey=pub_key_bytes, raw=True)
        return cls(pub_key)
