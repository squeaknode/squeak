# Import internal module first
from squeak.core._script import _VerifyScript

from bitcoin.core.script import CScript as BitcoinCScript
from bitcoin.core.scripteval import VerifyScriptError as BitcoinVerifyScriptError


SIGHASH_ALL = b'\01'


class CScript(BitcoinCScript):
    pass


class VerifyScriptError(Exception):
    """An error that occurs when the squeak script does
    not evaluate successfully.
    """


def VerifyScript(scriptSig, scriptPubKey, hash):
    try:
        _VerifyScript(scriptSig, scriptPubKey, hash)
    except BitcoinVerifyScriptError:
        raise VerifyScriptError("VerifyScript() : script does not evaluate successfully")


def MakeSigScript(signature, verifying_key):
    script = CScript()
    script += (signature + SIGHASH_ALL)
    script += verifying_key
    return script
