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
import os

import pytest
from bitcoin.core import lx

from squeak.core import CheckSqueak
from squeak.core import CSqueak
# from squeak.core import CSqueakEncContent


TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'squeak-example.dat')


@pytest.yield_fixture
def test_data():
    with open(TESTDATA_FILENAME, 'rb') as f:
        yield f.read()


class TestDeserializeSqueak(object):

    @pytest.mark.skip(reason="The test resource is using an old squeak version.")
    def test_deserialize_squeak(self, test_data):
        deserialized_squeak = CSqueak.deserialize(test_data)

        # Header fields
        assert(deserialized_squeak.nVersion == 1)
        assert(deserialized_squeak.hashEncContent == lx('a6ed7e0b2314d9b1616e9ccdff18df970b2b697b80a98739e50deab98f64afb9'))
        assert(deserialized_squeak.hashReplySqk == lx('0000000000000000000000000000000000000000000000000000000000000000'))
        assert(deserialized_squeak.hashBlock == lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'))
        assert(deserialized_squeak.nBlockHeight == 0)
        assert(deserialized_squeak.pubkey == b"")  # TODO
        assert(deserialized_squeak.hashDataKey == lx('a892b040034ca5e70da84d7e5997653004df21de39e9db946692ebe7819a8f60'))
        assert(deserialized_squeak.vchIv == lx('036516e4f1c0c55e1201e0a28f016ff3'))
        assert(deserialized_squeak.nTime == 1588050767)
        assert(deserialized_squeak.nNonce == 0x2885819d)

        # # Non-header fields
        # assert(deserialized_squeak.encContent == CSqueakEncContent(lx('e6d55179ea34d521dbc445163b8cfa8dec6b5445c7c7ab7ee523663dfd0ffe2a1feb1dce7001eee23c10e516529874ab6686a56989c686947290f1392ce12204b56c1a0b9c8c5a34ecd265154b2b1acd4dafe353396433abc5683efb4e0d9b5bc4ba1a232b806d46be48e946e0c1358d17ae552d821723fe50fa3e31c57fcfb2cfa3b0cbcf22860319f5d910e6726c72a71f74614e9d4914c36f2517ce8e252914cc02ff687e4cf9dc39d31c95a8cf8b40d1397dc6dafd32017970044e825ac6975628e26ed4a75b02169b8d151828dea4080e12c82c3f753eda48ed7220f53c8e7189feae92a6a427040089e9886fc3968db5842a00394cac00ba407cf8866812c88d436d14fbd607652c7d94e846c61c8f1c186687a50c3d3ffde73b0b563313e257b1b98607c29d764bbbb8613e50ac421467ad23a75095f0d5223d178af1ebc5bad28980473f6cad6427dac24778a58ecf7a8b0b84c366c514a3507372eb9d36dac4e43225efdb40c3091b7eb45f605d4325f88a4112014b2e3dce752a166c9eca5a8e7fa207f248623ce43141f91cd038a3662ca5c53d6b378be6b039b96b1e4595bc7cf1028ddf61c6babe84a9d109370c1eb03e17d9725e1da445a1fcde98fc6ccc2f75739eaa4d0f5ba95a27e9a0d35b30ba051e2a8dd86507074635755b08069c77af2a731a5f1dc5d5ac9a279bdf8d3ea445332f798da03ee2abcbc2853b3fa0934822b3e4eb85e1900aed1186273aa5bba1e8f93dd71df849c61f42d29cd886af4caf2a88bfc00e9b1ca5c8743870b6e10cb7194a3e61eccbf312c16a1a4b903ca9eb7ccd0a002e76b260a28870e6dd17061cb7fa2cc3901152b7da2035c326f3d71c645bff7853b1ab912333855d8c9c7cf487a33354675148a9f881f6993dd8cd9e2728d9d6112442a23b1a05dd693cc78ed2eadff39d218a64f41d302aabb5f5831f23af030dab65ba1eb8a77f2391704e604c22c6e63be930a8df822640d9d3c039542a6c6459e6d5cae76abf75ffc696bae156be1e61a777722c9cdae64a9ebe9c28dff140dc85c956224a1922ea3f04ce8d936a2c9d756ef493efd5631b466616ffe2b4bfc61227e0f3e1ba1b455cc7880361508167ac18140017d0db6dbffdabd566fe71d699fcb30abc4a747aa22bc48dc4e469ae124a1bcc52ff565c5d16c0a3fe6f69d320c9fc67b0ba155a87f74bfc74c7e0a7a11bc53ab73bd0e97ff42be66a0f79818e067d69d8d7e6e655f1f5a9e2882519085184b22ed4ae9cfe6fbe55d51479ae96fa41bd6941b54c12eec1b0da2601caae1d350dbb4f160c448b9f8782908bb38a43f479091943313ebc0d8b18011dcc9f477d4ef2eb51afdcfada3fc35327c3589147ae39bbb8be366e95c26aa46d4f7eda43fe4c1e9514016644f69399c32dd705b7bcc914cbb06a52681ae142c99cb72d93858f5588e73bf14f70320dde4eb90dcdfba6cfa5e9ec7cb11a444a909991350461876b8390db421f8000eef1eaf1505a7e1d07851e8e2f04ce36e6341acbac823a54e56a33387637307fd09b26d36c1773b42f9d98be05a9d8a4181248c56acb60f137b5630a29310b790ca974a3c0')))

        assert(deserialized_squeak.pubkey == b"")  # TODO
        assert(deserialized_squeak.vchDataKey == lx('eb8b021786ae01835cc914d043a498cba2fcb4df6687667b2566c34a9de8173d'))

        # Check the hash
        assert(deserialized_squeak.GetHash() == lx('4d320a62da0b85fa749e6910ae0b4f33e384b9a1af78055d25f0e7d040bd76ef'))

        # Check the address
        assert(str(deserialized_squeak.GetAddress()) == '1LndtWRXeZKUBjRu4K28d26PVWHopFJ9Z6')

        # Check the decrypted content
        assert(len(deserialized_squeak.GetDecryptedContent()) == 1120)
        assert(deserialized_squeak.GetDecryptedContentStr() == 'Hello world!')

        # Check the validity of the squeak
        CheckSqueak(deserialized_squeak)
