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
import struct

from bitcoin.core import b2lx
from bitcoin.core.serialize import ser_read
from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import VarIntSerializer
from bitcoin.core.serialize import VarStringSerializer
from bitcoin.core.serialize import VectorSerializer
from bitcoin.net import CInv as BitcoinCInv

from squeak.core import HASH_LENGTH
from squeak.core.keys import PUB_KEY_LENGTH
from squeak.core.keys import SqueakPublicKey


PROTO_VERSION = 60003


class CSqueakLocator(Serializable):
    """Used for locating desired squeaks.

    Contains a list of public keys, each with a block height range and reply_to hash.
    """

    def __init__(
            self,
            vInterested=None,
            protover=PROTO_VERSION,
    ):
        self.nVersion = protover
        self.vInterested = vInterested or []

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
        vInterested = VectorSerializer.stream_deserialize(CInterested, f)
        return cls(vInterested=vInterested, protover=nVersion)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        VectorSerializer.stream_serialize(CInterested, self.vInterested, f)

    def __repr__(self):
        return "CSqueakLocator(nVersion=%i vInterested=%s)" % \
            (self.nVersion, repr(self.vInterested))


class CInterested(Serializable):
    """Contains a public key together with a block range and reply_to hash.

    """

    def __init__(
            self,
            pubkeys=(),
            nMinBlockHeight=-1,
            nMaxBlockHeight=-1,
            hashReplySqk=b'\x00'*HASH_LENGTH,
            protover=PROTO_VERSION,
    ):
        self.pubkeys = pubkeys
        self.nMinBlockHeight = nMinBlockHeight
        self.nMaxBlockHeight = nMaxBlockHeight
        self.hashReplySqk = hashReplySqk

    @classmethod
    def stream_deserialize(cls, f):
        n = VarIntSerializer.stream_deserialize(f)
        pubkeys = tuple(SqueakPublicKey.from_bytes(ser_read(f, PUB_KEY_LENGTH)) for i in range(n))
        nMinBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        nMaxBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        hashReplySqk = ser_read(f, HASH_LENGTH)
        return cls(pubkeys, nMinBlockHeight, nMaxBlockHeight, hashReplySqk)

    def stream_serialize(self, f):
        VarIntSerializer.stream_serialize(len(self.pubkeys), f)
        for pubkey in self.pubkeys:
            pubkey_bytes = pubkey.to_bytes()
            assert len(pubkey_bytes) == PUB_KEY_LENGTH
            f.write(pubkey_bytes)
            # BytesSerializer.stream_serialize(pubkey, f)
        f.write(struct.pack(b"<i", self.nMinBlockHeight))
        f.write(struct.pack(b"<i", self.nMaxBlockHeight))
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)

    def __repr__(self):
        return "CInterested(pubkeys=%r nMinBlockHeight=%s nMaxBlockHeight=%s hashReplySqk=%s)" % \
            (self.pubkeys, repr(self.nMinBlockHeight), repr(self.nMaxBlockHeight), b2lx(self.hashReplySqk))


class CInv(BitcoinCInv):
    typemap = {
        0: "Error",
        1: "Squeak",
        2: "SecretKey",
    }

    def __init__(self, type=0, hash=b'\x00'*HASH_LENGTH,):
        super(CInv, self).__init__()
        self.type = type
        self.hash = hash


class COffer(Serializable):
    """An offer that can be used to buy a secret key.

    """

    def __init__(
            self,
            nonce=b'\x00'*HASH_LENGTH,
            strPaymentInfo=b'',
            host=b'',
            port=0,
            protover=PROTO_VERSION,
    ):
        self.nonce = nonce
        self.strPaymentInfo = strPaymentInfo
        self.host = host
        self.port = port

    @classmethod
    def stream_deserialize(cls, f):
        nonce = ser_read(f, HASH_LENGTH)
        strPaymentInfo = VarStringSerializer.stream_deserialize(f)
        host = VarStringSerializer.stream_deserialize(f)
        port = struct.unpack(b">H", ser_read(f, 2))[0]
        return cls(nonce, strPaymentInfo, host, port)

    def stream_serialize(self, f):
        assert len(self.nonce) == HASH_LENGTH
        f.write(self.nonce)
        VarStringSerializer.stream_serialize(self.strPaymentInfo, f)
        VarStringSerializer.stream_serialize(self.host, f)
        f.write(struct.pack(b">H", self.port))

    def __repr__(self):
        return "COffer(nonce=lx(%s) strPaymentInfo=%s host=%s port=%i)" % \
            (b2lx(self.nonce), self.strPaymentInfo, self.host, self.port)
