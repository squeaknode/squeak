from io import BytesIO as _BytesIO

import pytest
from bitcoin.core import lx

from squeak.core import HASH_LENGTH
from squeak.core.signing import CSigningKey
from squeak.core.signing import CSqueakAddress
from squeak.net import CInterested
from squeak.net import CInv
from squeak.net import CSqueakLocator


@pytest.fixture
def signing_key():
    return CSigningKey.generate()


@pytest.fixture
def verifying_key(signing_key):
    return signing_key.get_verifying_key()


@pytest.fixture
def fake_squeak_hash():
    return lx('DEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAFDEADBEAF')


class TestCInv(object):
    def test_serialization(self):
        inv = CInv(type=1)
        stream = _BytesIO()

        inv.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())

        deserialized = CInv.stream_deserialize(serialized)

        assert deserialized.typemap[deserialized.type] == "Squeak"
        assert deserialized == inv


class TestCSqueakLocator(object):
    def test_serialization(self, verifying_key, fake_squeak_hash):
        address = CSqueakAddress.from_verifying_key(verifying_key)
        interested = [
            CInterested([address, address, address], -1, 10, fake_squeak_hash),
            CInterested([address], 30, 2000),
            CInterested(
                nMinBlockHeight=0,
                nMaxBlockHeight=100,
                hashReplySqk=fake_squeak_hash,
            ),
        ]
        locator = CSqueakLocator(interested)
        stream = _BytesIO()
        locator.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())
        deserialized = CSqueakLocator.stream_deserialize(serialized)

        assert deserialized == locator
        assert len(deserialized.vInterested) == 3
        assert deserialized.vInterested[0].addresses == (address, address, address)
        assert deserialized.vInterested[1].addresses == (address,)
        assert deserialized.vInterested[2].addresses == ()
        assert deserialized.vInterested[1].hashReplySqk == b'\x00'*HASH_LENGTH
        assert deserialized.vInterested[2].hashReplySqk == fake_squeak_hash
