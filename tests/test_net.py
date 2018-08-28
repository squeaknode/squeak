from io import BytesIO as _BytesIO

from squeak.core.signing import generate_signing_key
from squeak.core.signing import get_verifying_key
from squeak.net import CInv
from squeak.net import CSqueakLocator
from squeak.net import CInterested


class TestCInv(object):
    def test_serialization(self):
        inv = CInv()
        inv.type = 123
        inv.hash = b"0" * 32
        stream = _BytesIO()

        inv.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())

        deserialized = CInv.stream_deserialize(serialized)
        assert deserialized == inv


class TestCSqueakLocator(object):
    def test_serialization(self):
        locator = CSqueakLocator()
        interested1 = self._make_interested(5, 10)
        interested2 = self._make_interested(30, 2000)
        locator.nVersion = 1
        locator.vInterested = [interested1, interested2]

        print(interested1)
        print(interested2)

        stream = _BytesIO()

        locator.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())

        deserialized = CInterested.stream_deserialize(serialized)
        assert deserialized == locator


    def _make_interested(self, start, end):
        vk = get_verifying_key(generate_signing_key())
        interested = CInterested()
        interested.vchPubkey = vk
        interested.nMinBlockHeight = start
        interested.nMaxBlockHeight = end
        return interested
