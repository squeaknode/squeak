import hashlib
import os

from bitcoin.core.key import CPubKey
from bitcoin.wallet import CBitcoinAddressError
from bitcoin.wallet import CBitcoinSecret
from bitcoin.wallet import P2PKHBitcoinAddress


PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64  # Only if the signature is compacted


class CSigningKey(CBitcoinSecret):
    """Represents a DSA signing key.

    """

    @classmethod
    def generate(cls):
        return cls.from_secret_bytes(_generate_secret_bytes())

    def get_verifying_key(self):
        public_key = self.pub
        return CVerifyingKey.from_pubkey(public_key)


class CVerifyingKey(CPubKey):

    """Represents a DSA verifying key.

    """

    @classmethod
    def from_pubkey(cls, pubkey):
        data = bytes(pubkey)
        return cls(data)


class CSqueakAddressError(Exception):
    pass


class CSqueakAddress(P2PKHBitcoinAddress):

    @classmethod
    def from_verifying_key(cls, verifying_key):
        self = cls.from_pubkey(verifying_key)
        self.__class__ = CSqueakAddress
        return self

    @classmethod
    def from_bytes(cls, data, nVersion=None):
        try:
            self = super(CSqueakAddress, cls).from_bytes(data, nVersion)
        except CBitcoinAddressError:
            raise CSqueakAddressError("CSqueakAddress() : bytes do not convert to a valid squeak address")

        if not self.__class__ == P2PKHBitcoinAddress:
            raise CSqueakAddressError("CSqueakAddress() : bytes do not convert to a valid squeak address")

        self.__class__ = CSqueakAddress
        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        try:
            self = super(CSqueakAddress, cls).from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            raise CSqueakAddressError("CSqueakAddress() : pubkey_script does not convert to a valid squeak address")

        self.__class__ = CSqueakAddress
        return self


def _generate_secret_bytes():
    # https://en.bitcoin.it/wiki/Private_key#Range_of_valid_ECDSA_private_keys
    min_key = b'\00' * 31 + b'\01'
    max_key = bytes.fromhex('FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140')

    h = b'\00' * 32
    while h < min_key or h > max_key:
        h = hashlib.sha256(os.urandom(128)).digest()
    return h
