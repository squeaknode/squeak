import struct

from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import VectorSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2lx
from bitcoin.net import CInv as BitcoinCInv

from squeak.core import PUB_KEY_LENGTH
from squeak.core import HASH_LENGTH

PROTO_VERSION = 60002


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
    """Contains a public key together with a block range and reply_to hash.

    """
    def __init__(
            self,
            vchPubkey=b'\x00' * PUB_KEY_LENGTH,
            nMinBlockHeight=-1,
            nMaxBlockHeight=-1,
            hashReplySqk=b'\x00'*HASH_LENGTH,
            protover=PROTO_VERSION,
    ):
        self.vchPubkey = vchPubkey
        self.nMinBlockHeight = nMinBlockHeight
        self.nMaxBlockHeight = nMaxBlockHeight
        self.hashReplySqk = hashReplySqk

    @classmethod
    def stream_deserialize(cls, f):
        c = cls()
        c.vchPubkey = ser_read(f,PUB_KEY_LENGTH)
        c.nMinBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        c.nMaxBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        c.hashReplySqk = ser_read(f, HASH_LENGTH)
        return c

    def stream_serialize(self, f):
        assert len(self.vchPubkey) == PUB_KEY_LENGTH
        f.write(self.vchPubkey)
        f.write(struct.pack(b"<i", self.nMinBlockHeight))
        f.write(struct.pack(b"<i", self.nMaxBlockHeight))
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)

    def __repr__(self):
        return "CInterested(vchPubkey=lx(%s) nMinBlockHeight=%s nMaxBlockHeight=%s hashReplySqk=%s)" % \
            (b2lx(self.vchPubkey), repr(self.nMinBlockHeight), repr(self.nMaxBlockHeight), b2lx(self.hashReplySqk))


class CInv(BitcoinCInv):
    typemap = {
        0: "Error",
        1: "Squeak",
        3: "FilteredSqueak",
    }

    def __init__(self, type=0, hash=b'\x00'*HASH_LENGTH,):
        super(CInv, self).__init__()
        self.type = type
        self.hash = hash
