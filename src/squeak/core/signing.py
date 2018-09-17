import bitcoin.core.script

def _new_RawSignatureHash(script, hash, _, hashtype):
    return (hash, None)

bitcoin.core.script.RawSignatureHash = _new_RawSignatureHash


from bitcoin.core.key import CECKey
from bitcoin.core.key import CPubKey
from bitcoin.core.script import CScript
from bitcoin.core.scripteval import VerifyScript as BitcoinVerifyScript
from bitcoin.core.scripteval import VerifyScriptError
from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import ser_read
from bitcoin.wallet import CBitcoinAddress
from bitcoin.wallet import P2PKHBitcoinAddress

from secp256k1 import PrivateKey


PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64  # Only if the signature is compacted
SIGHASH_ALL = b'\01'


class CSigningKey(Serializable):
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
        secret = _generate_secret()
        private_key = CECKey()
        private_key.set_secretbytes(secret)
        private_key.set_compressed(True)
        return cls(private_key)

    def stream_serialize(self, f):
        # TODO
        # f.write(struct.pack(data)
        pass

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


def _generate_secret():
    return PrivateKey().private_key


def VerifyScript(scriptSig, scriptPubKey, hash):
    try:
        BitcoinVerifyScript(scriptSig, scriptPubKey, hash, 0)
        return True
    except VerifyScriptError:
        return False
