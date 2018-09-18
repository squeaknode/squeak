import bitcoin.core.script


def _new_RawSignatureHash(script, hash, _, hashtype):
    return (hash, None)


bitcoin.core.script.RawSignatureHash = _new_RawSignatureHash

from bitcoin.core.scripteval import VerifyScript as BitcoinVerifyScript  # noqa: E402
from bitcoin.core.scripteval import VerifyScriptError  # noqa: E402


def _VerifyScript(scriptSig, scriptPubKey, hash):
    try:
        BitcoinVerifyScript(scriptSig, scriptPubKey, hash, 0)
        return True
    except VerifyScriptError:
        return False
