import struct

from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import VectorSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2lx
from bitcoin.net import CInv as BitcoinCInv

from squeak.core import PUB_KEY_LENGTH

PROTO_VERSION = 60002


class CSqueakLocator(Serializable):
    """Used for locating desired squeaks.

    Contains a list of public keys, each with a block height range.
    """
    def __init__(self, protover=PROTO_VERSION):
        self.nVersion = protover
        self.vInterested = []

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
        c.vInterested = VectorSerializer.stream_deserialize(CInterested, f)
        return c

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        VectorSerializer.stream_serialize(CInterested, self.vInterested, f)

    def __repr__(self):
        return "CSqueakLocator(nVersion=%i vInterested=%s)" % \
            (self.nVersion, repr(self.vInterested))


class CInterested(Serializable):
    """Contains a public key together with a block range.

    """
    def __init__(self, protover=PROTO_VERSION):
        self.vchPubkey = b'\x00' * PUB_KEY_LENGTH
        self.nMinBlockHeight = 0
        self.nMaxBlockHeight = 0

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.vchPubkey = ser_read(f,PUB_KEY_LENGTH)
        c.nMinBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        c.nMaxBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        return c

    def stream_serialize(self, f):
        assert len(self.vchPubkey) == PUB_KEY_LENGTH
        f.write(self.vchPubkey)
        f.write(struct.pack(b"<I", self.nMinBlockHeight))
        f.write(struct.pack(b"<I", self.nMaxBlockHeight))

    def __repr__(self):
        return "CInterested(vchPubkey=lx(%s) nMinBlockHeight=%s nMaxBlockHeight=%s)" % \
            (b2lx(self.vchPubkey), repr(self.nMinBlockHeight), repr(self.nMaxBlockHeight))


class CInv(BitcoinCInv):
    typemap = {
        0: "Error",
        1: "Squeak",
        3: "FilteredSqueak",
    }
