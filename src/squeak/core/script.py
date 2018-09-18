from bitcoin.core.script import CScript as BitcoinCScript

from squeak.core._script import _VerifyScript


SIGHASH_ALL = b'\01'


class CScript(BitcoinCScript):
    pass


def VerifyScript(scriptSig, scriptPubKey, hash):
    return _VerifyScript(scriptSig, scriptPubKey, hash)


def MakeSigScript(signature, verifying_key):
    pubkey_bytes = verifying_key.serialize()
    script = CScript()
    script += (signature + SIGHASH_ALL)
    script += pubkey_bytes
    return script
