import bitcoin.core.script


def _new_RawSignatureHash(script, hash, _, hashtype):
    return (hash, None)


bitcoin.core.script.RawSignatureHash = _new_RawSignatureHash

from bitcoin.core.scripteval import VerifyScript as BitcoinVerifyScript  # noqa: E402


def _VerifyScript(scriptSig, scriptPubKey, hash):
    BitcoinVerifyScript(scriptSig, scriptPubKey, hash, 0)
