# Import internal module first
from squeak.core._script import _VerifyScript

from bitcoin.core.script import CScript as BitcoinCScript
from bitcoin.core.scripteval import VerifyScriptError as BitcoinVerifyScriptError
from bitcoin.core.scripteval import EvalScriptError as BitcoinEvalScriptError


SIGHASH_ALL = b'\01'


class CScript(BitcoinCScript):
    pass


class EvalScriptError(Exception):
    pass


class VerifyScriptError(Exception):
    pass


def VerifyScript(scriptSig, scriptPubKey, hash):
    try:
        _VerifyScript(scriptSig, scriptPubKey, hash)
    except BitcoinEvalScriptError:
        raise EvalScriptError("VerifyScript() : script does not evaluate")
    except BitcoinVerifyScriptError:
        raise VerifyScriptError("VerifyScript() : script does not verify")


def MakeSigScript(signature, verifying_key):
    script = CScript()
    script += (signature + SIGHASH_ALL)
    script += verifying_key
    return script
