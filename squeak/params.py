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
import bitcoin


class MainParams(bitcoin.MainParams):
    MESSAGE_START = b'\xb4n\x83\xfe'
    DEFAULT_PORT = 8555
    RPC_PORT = 8554
    DNS_SEEDS = ()


class TestNetParams(bitcoin.TestNetParams):
    MESSAGE_START = b'\x9b\xe50\x89'
    DEFAULT_PORT = 18555
    RPC_PORT = 18554
    DNS_SEEDS = ()


class RegTestParams(bitcoin.RegTestParams):
    MESSAGE_START = b'X\x85\xf4\xcb'
    DEFAULT_PORT = 18666
    RPC_PORT = 18665
    DNS_SEEDS = ()


class SimNetParams(bitcoin.RegTestParams):
    MESSAGE_START = b'X\x85\xf4\xcb'
    DEFAULT_PORT = 18777
    RPC_PORT = 18776
    DNS_SEEDS = ()


"""Master global setting for what chain params we're using.
However, don't set this directly, use SelectParams() instead so as to set the
bitcoin.params correctly too.
"""
params = MainParams()


def SelectParams(name):
    """Select the chain parameters to use
    name is one of 'mainnet', 'testnet', or 'regtest'
    Default chain is 'mainnet'
    """
    global params
    if name == 'mainnet':
        bitcoin.SelectParams(name)
        params = bitcoin.params = MainParams()
    elif name == 'testnet':
        bitcoin.SelectParams(name)
        params = bitcoin.params = TestNetParams()
    elif name == 'regtest':
        bitcoin.SelectParams(name)
        params = bitcoin.params = RegTestParams()
    elif name == 'simnet':
        # Should be ok because 'regtest' and 'simnet' use the same magic.
        bitcoin.SelectParams('regtest')
        params = bitcoin.params = SimNetParams()
    else:
        raise ValueError('Unknown chain %r' % name)
