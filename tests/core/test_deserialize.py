import os

import pytest

from bitcoin.core import lx

from squeak.core import CSqueak


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
