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
from secp256k1 import PrivateKey
from secp256k1 import PublicKey


PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64


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

    def __eq__(self, other):
        return other.to_bytes() == self.to_bytes()

    def __ne__(self, other):
        return other.to_bytes() != self.to_bytes()


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

    def __eq__(self, other):
        return other.to_bytes() == self.to_bytes()

    def __ne__(self, other):
        return other.to_bytes() != self.to_bytes()
