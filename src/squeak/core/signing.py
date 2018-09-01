from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import ser_read
from secp256k1 import PrivateKey
from secp256k1 import PublicKey

PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64


class CSigningKey(Serializable):

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
        return cls(PrivateKey())

    def stream_serialize(self, f):
        # TODO
        # f.write(struct.pack(data)
        pass

    def get_verifying_key(self):
        return CVerifyingKey(self.private_key.pubkey)

    def sign(self, data):
        internal_signature = self.private_key.ecdsa_sign(data)
        return self.private_key.ecdsa_serialize_compact(internal_signature)

    def __repr__(self):
        return "CSigningKey(private_key=%s)" % \
            (repr(self.private_key))


class CVerifyingKey(Serializable):

    def __init__(self, public_key):
        self.public_key = public_key

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f, PUB_KEY_LENGTH)
        return cls(PublicKey(data, raw=True))

    def stream_serialize(self, f):
        data = self.public_key.serialize()
        f.write(data)

    def verify(self, data, signature):
        internal_signature = self.public_key.ecdsa_deserialize_compact(signature)
        return self.public_key.ecdsa_verify(data, internal_signature)

    def __repr__(self):
        return "CVerifyingKey(public_key=%s)" % \
            (repr(self.public_key))
