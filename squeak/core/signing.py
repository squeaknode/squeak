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
import hashlib

import ecpy
from ecpy.curves import Curve
from ecpy.curves import Point
from ecpy.ecdsa import ECDSA
from ecpy.keys import ECPrivateKey
from ecpy.keys import ECPublicKey

CURVE_SECP256K1 = Curve.get_curve('secp256k1')
SIGNER = ECDSA()


PUB_KEY_LENGTH = 33
SIGNATURE_LENGTH = 64


class SqueakPrivateKey:
    """Represents a squeak private key.

    """

    def __init__(self, priv_key):
        self.priv_key = priv_key

    @classmethod
    def generate(cls):
        priv_key_bytes = ecpy.ecrand.rnd(CURVE_SECP256K1.order)
        priv_key = ECPrivateKey(priv_key_bytes, CURVE_SECP256K1)
        return cls(priv_key=priv_key)

    def sign(self, msg):
        hashlib.sha256
        return SIGNER.sign(msg, self.priv_key, True)

    def get_public_key(self):
        # pubkey = self.priv_key.get_public_key().W
        # out = b"\x04"
        # out += pubkey.x.to_bytes(32, 'big')
        # out += pubkey.y.to_bytes(32, 'big')
        # return SqueakPublicKey.from_bytes(out)

        pubkey = self.priv_key.get_public_key()
        return SqueakPublicKey(pub_key=pubkey)

    def to_bytes(self):
        return self.priv_key.d

    # def to_str(self):
    #     return self.priv_key.serialize()

    @classmethod
    def from_bytes(cls, priv_key_bytes):
        priv_key = ECPrivateKey(priv_key_bytes, CURVE_SECP256K1)
        return cls(priv_key)

    # @classmethod
    # def from_str(cls, priv_key_str):
    #     priv_key = PrivateKey(privkey=priv_key_str, raw=False)
    #     return cls(priv_key)

    def __eq__(self, other):
        return other.to_bytes() == self.to_bytes()

    def __ne__(self, other):
        return other.to_bytes() != self.to_bytes()

    def __repr__(self):
        return 'SqueakPublicKey(%r)' % (
            self.to_bytes().hex(),
        )


class SqueakPublicKey:
    """Represents a squeak public key.

    """

    def __init__(self, pub_key):
        self.pub_key = pub_key

    def verify(self, msg, sig):
        raw_sig = bytearray(sig)
        # return self.pub_key.ecdsa_verify(msg, sig, '', raw=True)
        return SIGNER.verify(msg, raw_sig, self.pub_key)

    def to_bytes(self):
        # out = b"\x03" if ((self.pub_key.W.y & 1) != 0) else b"\x02"
        # out += self.pub_key.W.x.to_bytes(32, 'big')
        # return out

        # print("self.pub_key.W:")
        # print(self.pub_key.W)

        # print("self.pub_key:")
        # print(self.pub_key)

        # return payment_point_to_bytes(self.pub_key.W)
        # # return self.pub_key.W

        pubkey = self.pub_key.W
        out = b"\x04"
        out += pubkey.x.to_bytes(32, 'big')
        out += pubkey.y.to_bytes(32, 'big')
        return out

    @classmethod
    def from_bytes(cls, pub_key_bytes):
        pubkey = pub_key_bytes[1:]
        x = int.from_bytes(pubkey[0:32], 'big')
        y = int.from_bytes(pubkey[32:], 'big')
        pub_key = ECPublicKey(Point(x, y, CURVE_SECP256K1))

        # s = scalar_from_bytes(pub_key_bytes)
        # point = payment_point_from_scalar(s)
        # pub_key = ECPublicKey(point)

        # s = scalar_from_bytes(pub_key_bytes)
        # point = payment_point_from_scalar(s)
        # pub_key = ECPublicKey(point)

        return cls(pub_key)

    def __eq__(self, other):
        return other.to_bytes() == self.to_bytes()

    def __ne__(self, other):
        return other.to_bytes() != self.to_bytes()

    def __repr__(self):
        return 'SqueakPublicKey(%r)' % (
            self.to_bytes().hex(),
        )
