import bitcoin.core


__version__ = '0.1.0'


# TODO: Replace with new network params
class MainParams(bitcoin.core.CoreMainParams):
    MESSAGE_START = b'\xf9\xbe\xb4\xd9'
    DEFAULT_PORT = 8333
    RPC_PORT = 8332
    DNS_SEEDS = (('bitcoin.sipa.be', 'seed.bitcoin.sipa.be'),
                 ('bluematt.me', 'dnsseed.bluematt.me'),
                 ('dashjr.org', 'dnsseed.bitcoin.dashjr.org'),
                 ('bitcoinstats.com', 'seed.bitcoinstats.com'),
                 ('xf2.org', 'bitseed.xf2.org'),
                 ('bitcoin.jonasschnelli.ch', 'seed.bitcoin.jonasschnelli.ch'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':0,
                       'SCRIPT_ADDR':5,
                       'SECRET_KEY':128}


class TestNetParams(bitcoin.core.CoreTestNetParams):
    MESSAGE_START = b'\x0b\x11\x09\x07'
    DEFAULT_PORT = 18333
    RPC_PORT = 18332
    DNS_SEEDS = (('testnetbitcoin.jonasschnelli.ch', 'testnet-seed.bitcoin.jonasschnelli.ch'),
                 ('petertodd.org', 'seed.tbtc.petertodd.org'),
                 ('bluematt.me', 'testnet-seed.bluematt.me'),
                 ('bitcoin.schildbach.de', 'testnet-seed.bitcoin.schildbach.de'))
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY':239}


class RegTestParams(bitcoin.core.CoreRegTestParams):
    MESSAGE_START = b'\xfa\xbf\xb5\xda'
    DEFAULT_PORT = 18444
    RPC_PORT = 18443
    DNS_SEEDS = ()
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY':239}
