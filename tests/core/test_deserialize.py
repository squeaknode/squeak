import os

import pytest

from bitcoin.core import lx, x
from bitcoin.core.script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG

from squeak.core import CSqueak
from squeak.core.script import CScript


TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'squeak-example.dat')


@pytest.yield_fixture
def test_data():
    with open(TESTDATA_FILENAME, 'rb') as f:
        yield f.read()


class TestDeserializeSqueak(object):

    def test_deserialize_squeak(self, test_data):
        print('test_data: ')
        print(test_data)

        assert len(test_data) > 0

        deserialized_squeak = CSqueak.deserialize(test_data)
        print(deserialized_squeak)

        assert(deserialized_squeak.nVersion == 1)
        assert(deserialized_squeak.hashEncContent == lx('a6ed7e0b2314d9b1616e9ccdff18df970b2b697b80a98739e50deab98f64afb9'))
        assert(deserialized_squeak.hashReplySqk == lx('0000000000000000000000000000000000000000000000000000000000000000'))
        assert(deserialized_squeak.hashBlock == lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'))
        assert(deserialized_squeak.nBlockHeight == 0)
        assert(deserialized_squeak.scriptPubKey == CScript([OP_DUP, OP_HASH160, x('d90be698f3b2dd28eb8f32933186fda15e9cc5f3'), OP_EQUALVERIFY, OP_CHECKSIG]))
        assert(deserialized_squeak.hashDataKey == lx('a892b040034ca5e70da84d7e5997653004df21de39e9db946692ebe7819a8f60'))
        assert(deserialized_squeak.vchIv == lx('036516e4f1c0c55e1201e0a28f016ff3'))
        assert(deserialized_squeak.nTime == 1588050767)
        assert(deserialized_squeak.nNonce == 0x2885819d)
