import pytest

from io import BytesIO as _BytesIO

from squeak.core.signing import generate_signing_key
from squeak.core.signing import get_verifying_key
from squeak.core.signing import serialize_verifying_key
from squeak.net import CInv
from squeak.net import CSqueakLocator
from squeak.net import CInterested


@pytest.fixture
def signing_key():
    return generate_signing_key()


@pytest.fixture
def verifying_key(signing_key):
    return get_verifying_key(signing_key)


class TestCInv(object):
    def test_serialization(self):
        inv = CInv()
        inv.type = 1
        inv.hash = b"0" * 32
        stream = _BytesIO()

        inv.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())

        deserialized = CInv.stream_deserialize(serialized)

        assert deserialized.typemap[deserialized.type] == "Squeak"
        assert deserialized == inv


class TestCSqueakLocator(object):
    def test_serialization(self, verifying_key):
        locator = CSqueakLocator()
        interested1 = self._make_interested(verifying_key, 5, 10)
        interested2 = self._make_interested(verifying_key, 30, 2000)
        locator.nVersion = 1
        locator.vInterested = [interested1, interested2]
        stream = _BytesIO()

        locator.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())

        deserialized = CSqueakLocator.stream_deserialize(serialized)
        assert deserialized == locator

    def _make_interested(self, public_key, start, end):
        vk = serialize_verifying_key(public_key)
        interested = CInterested()
        interested.vchPubkey = vk
        interested.nMinBlockHeight = start
        interested.nMaxBlockHeight = end
        return interested
