__version__ = '0.1.2'


class MainParams():
    MESSAGE_START = b'\xb4n\x83\xfe'
    DEFAULT_PORT = 8555
    RPC_PORT = 8554
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':0,
                       'SCRIPT_ADDR':5,
                       'SECRET_KEY':128}


class TestNetParams():
    MESSAGE_START = b'\x9b\xe50\x89'
    DEFAULT_PORT = 18555
    RPC_PORT = 18554
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY':239}


class RegTestParams():
    MESSAGE_START = b'X\x85\xf4\xcb'
    DEFAULT_PORT = 18666
    RPC_PORT = 18665
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY':239}


"""Master global setting for what chain params we're using."""
params = MainParams()


def SelectParams(name):
    """Select the chain parameters to use
    name is one of 'mainnet', 'testnet', or 'regtest'
    Default chain is 'mainnet'
    """
    global params
    if name == 'mainnet':
        params = MainParams()
    elif name == 'testnet':
        params = TestNetParams()
    elif name == 'regtest':
        params = RegTestParams()
    else:
        raise ValueError('Unknown chain %r' % name)
