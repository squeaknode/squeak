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
from io import BytesIO as _BytesIO

import pytest
from bitcoin.core import lx

from squeak.core import HASH_LENGTH
from squeak.core.keys import SqueakPrivateKey
from squeak.net import CInterested
from squeak.net import CInv
from squeak.net import COffer
from squeak.net import CSqueakLocator


@pytest.fixture
def signing_key():
    return SqueakPrivateKey.generate()


@pytest.fixture
def verifying_key(signing_key):
    return signing_key.get_public_key()


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
        # pubkey_bytes = verifying_key.to_bytes()
        interested = [
            CInterested([verifying_key, verifying_key, verifying_key], -1, 10, fake_squeak_hash),
            CInterested([verifying_key], 30, 2000),
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
        assert deserialized.vInterested[0].pubkeys == (verifying_key, verifying_key, verifying_key)
        assert deserialized.vInterested[1].pubkeys == (verifying_key,)
        assert deserialized.vInterested[2].pubkeys == ()
        assert deserialized.vInterested[1].hashReplySqk == b'\x00'*HASH_LENGTH
        assert deserialized.vInterested[2].hashReplySqk == fake_squeak_hash


class TestCOffer(object):
    def test_serialization(self):
        fake_payment_str = "fakepaymentstr".encode('utf-8')
        fake_host = "foo.com".encode('utf-8')
        port = 5678

        offer = COffer(
            strPaymentInfo=fake_payment_str,
            host=fake_host,
            port=port,
        )
        stream = _BytesIO()

        offer.stream_serialize(stream)
        serialized = _BytesIO(stream.getvalue())

        deserialized = COffer.stream_deserialize(serialized)

        # assert deserialized.typemap[deserialized.type] == "Squeak"
        assert deserialized.strPaymentInfo == fake_payment_str
        assert deserialized == offer
