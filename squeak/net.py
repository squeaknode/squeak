import struct

from bitcoin.core import b2lx
from bitcoin.core.serialize import BytesSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core.serialize import Serializable
from bitcoin.core.serialize import VectorSerializer
from bitcoin.core.serialize import VarIntSerializer
from bitcoin.net import CInv as BitcoinCInv

from squeak.core import HASH_LENGTH
from squeak.core.signing import CSqueakAddress


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
            addresses=(),
            nMinBlockHeight=-1,
            nMaxBlockHeight=-1,
            hashReplySqk=b'\x00'*HASH_LENGTH,
            protover=PROTO_VERSION,
    ):
        self.addresses = addresses
        self.nMinBlockHeight = nMinBlockHeight
        self.nMaxBlockHeight = nMaxBlockHeight
        self.hashReplySqk = hashReplySqk

    @classmethod
    def stream_deserialize(cls, f):
        n = VarIntSerializer.stream_deserialize(f)
        addresses = tuple(CSqueakAddress.from_bytes(BytesSerializer.stream_deserialize(f)) for i in range(n))
        nMinBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        nMaxBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        hashReplySqk = ser_read(f, HASH_LENGTH)
        return cls(addresses, nMinBlockHeight, nMaxBlockHeight, hashReplySqk)

    def stream_serialize(self, f):
        VarIntSerializer.stream_serialize(len(self.addresses), f)
        for address in self.addresses:
            BytesSerializer.stream_serialize(address, f)
        f.write(struct.pack(b"<i", self.nMinBlockHeight))
        f.write(struct.pack(b"<i", self.nMaxBlockHeight))
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)

    def __repr__(self):
        return "CInterested(addresses=%r nMinBlockHeight=%s nMaxBlockHeight=%s hashReplySqk=%s)" % \
            (self.addresses, repr(self.nMinBlockHeight), repr(self.nMaxBlockHeight), b2lx(self.hashReplySqk))


class CInv(BitcoinCInv):
    typemap = {
        0: "Error",
        1: "Squeak",
        2: "Offer",
    }

    def __init__(self, type=0, hash=b'\x00'*HASH_LENGTH,):
        super(CInv, self).__init__()
        self.type = type
        self.hash = hash
