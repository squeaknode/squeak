from bitcoin.core.script import CScript as BitcoinCScript

from squeak.core._script import _VerifyScript


class CScript(BitcoinCScript):
    pass


def VerifyScript(scriptSig, scriptPubKey, hash):
    return _VerifyScript(scriptSig, scriptPubKey, hash)
