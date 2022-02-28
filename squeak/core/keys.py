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
from ecpy.curves import ECPyException
from ecpy.ecschnorr import ECSchnorr
from ecpy.keys import ECPrivateKey
from ecpy.keys import ECPublicKey

from squeak.core.elliptic import bytes_to_payment_point
from squeak.core.elliptic import CURVE
from squeak.core.elliptic import payment_point_to_bytes
from squeak.core.hashing import sha256


SIGNER = ECSchnorr(hashlib.sha256,"LIBSECP","ITUPLE")

PRIV_KEY_LENGTH = 32
PUB_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64


class SqueakPublicKey:
    """Represents a squeak public key.

    """

    def __init__(self, pub_key):
        self.pub_key = pub_key

    def verify(self, msg, sig):
        return self.verify_with_zeroth(msg, sig, b'\x02') or \
            self.verify_with_zeroth(msg, sig, b'\x03')

    def verify_with_zeroth(self, msg, sig, zeroth):
        point_bytes = self.to_bytes()
        pub_key_with_zeroth = self.pub_key_from_bytes_with_zeroth(point_bytes, zeroth)

        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        sig_tuple = r, s
        return SIGNER.verify(msg, sig_tuple, pub_key_with_zeroth)

    def to_bytes(self):
        point_bytes = payment_point_to_bytes(self.pub_key.W)
        return point_bytes[1:]

    @classmethod
    def from_bytes(cls, pub_key_bytes):
        if len(pub_key_bytes) != PUB_KEY_LENGTH:
            raise InvalidPublicKeyError()
        try:
            point_bytes = b'\x02' + pub_key_bytes
            point = bytes_to_payment_point(point_bytes)
            pub_key = ECPublicKey(point)
            return cls(pub_key)
        except ECPyException:
            raise InvalidPublicKeyError()

    def pub_key_from_bytes_with_zeroth(self, pub_key_bytes, zeroth):
        try:
            point_bytes = zeroth + pub_key_bytes
            point = bytes_to_payment_point(point_bytes)
            return ECPublicKey(point)
        except ECPyException:
            raise InvalidPublicKeyError()

    def __eq__(self, other):
        return other.to_bytes() == self.to_bytes()

    def __ne__(self, other):
        return other.to_bytes() != self.to_bytes()

    def __hash__(self):
        return hash(self.to_bytes())

    def __repr__(self):
        return 'SqueakPublicKey(%r)' % (
            self.to_bytes().hex(),
        )


class SqueakPrivateKey:
    """Represents a squeak private key.

    """

    def __init__(self, priv_key):
        self.priv_key = priv_key

    @classmethod
    def generate(cls):
        priv_key_bytes = ecpy.ecrand.rnd(CURVE.order)
        priv_key = ECPrivateKey(priv_key_bytes, CURVE)
        return cls(priv_key=priv_key)

    def sign(self, msg):
        r, s = SIGNER.sign(msg, self.priv_key)
        r = r.to_bytes(32, 'big')
        s = s.to_bytes(32, 'big')
        return r+s

    def get_public_key(self):
        pubkey = self.priv_key.get_public_key()
        return SqueakPublicKey(pub_key=pubkey)

    def get_shared_key(self, public_key: SqueakPublicKey) -> bytes:
        point = self.priv_key.d * public_key.pub_key.W
        x_bytes = point.x.to_bytes(32, 'big')
        return sha256(x_bytes)

    def to_bytes(self):
        return self.priv_key.d.to_bytes(32, 'big')

    @classmethod
    def from_bytes(cls, priv_key_bytes):
        if len(priv_key_bytes) != PRIV_KEY_LENGTH:
            raise InvalidPrivateKeyError()
        priv_key_int = int.from_bytes(priv_key_bytes, "big")
        priv_key = ECPrivateKey(priv_key_int, CURVE)
        return cls(priv_key)

    def __eq__(self, other):
        return other.to_bytes() == self.to_bytes()

    def __ne__(self, other):
        return other.to_bytes() != self.to_bytes()

    def __hash__(self):
        return hash(self.to_bytes())

    def __repr__(self):
        return 'SqueakPrivateKey(%r)' % (
            self.to_bytes().hex(),
        )


class InvalidPrivateKeyError(Exception):
    """ Invalid private key error.
    """


class InvalidPublicKeyError(Exception):
    """ Invalid public key error.
    """
