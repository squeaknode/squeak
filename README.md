# squeak

### Requirements

* python3

### Test

```
make test
```

### Install

```
pip install squeaklib
```

### Examples

Create a squeak, verify the signature, and decrypt the content:

```
>>> import time
>>>
>>> from bitcoin.core import lx
>>>
>>> from squeak.core import MakeSqueak
>>> from squeak.core import VerifySqueak
>>> from squeak.core import DecryptContent
>>> from squeak.core import CONTENT_LENGTH
>>> from squeak.core.signing import CSigningKey
>>>
>>> signing_key = CSigningKey.generate()
>>>
>>> genesis_block_height = 0
>>> genesis_block_hash = lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')
>>>
>>> content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
>>> timestamp = int(time.time())
>>>
>>> squeak, decryption_key, signature = MakeSqueak(
...     signing_key,
...     content,
...     genesis_block_height,
...     genesis_block_hash,
...     timestamp,
... )
>>>
>>> print(squeak)
CSqueak(1, lx(daa5bb1b660640624c4f358133631b532dc96813e6a046d19809de819b3f046a), lx(0000000000000000000000000000000000000000000000000000000000000000), lx(4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b), 0, lx(157529c839e9d8d3a8bc520de79cadc1c5bfbdd363328e6c96ef84fe5c43343f02), lx(0100010302b7e644b5e6ff01f82819d40ff6b0d5b9c74c8a4851ce25fe3b9a6075dfc3d990807a7ec12f975e0ae0b74e3964b51da83688381ce0f3000f573f9597b39c0e75c0044b6e541acda88244bb90de30e688581262b443a45100b3769188f61498c49d66ada75d20332f785899b040bb714cadf8e0fe4831045da440b9fc36b275ba00818102898130008d810300050101010df78648862a09060d309f8130), lx(39d8e43764d4b04bb97490bd881b6af3d8ecdb63d41aa0bbdaf0a25dd1d968eec039db362bea5db9e4af9ccc1a870330d4eb0ecf9b23a0aa0816df5dfb32a7c91137a8def07f73b1f3c33eaabcb02ef2777bd42a0ff2c18fbd016efd026caaf6c4c0a2aafad5325272741940e7915118a581f3b19124d62d2068c06826a0da95), lx(ee1bdbb3ea21af285605c06284fce781), 1535874553, 0xd9c63909)
>>> print(squeak.GetHash())
b'\xb7\x84Z\xf0\xa1z\xe4|\x15\x05\xe6\xbdC\xe2\xb3"\xbd\xce\xbc\xa0\xa9\xaa6\xa2\xa2\xcfl\xf9L\xc6\xfd\xd1'
>>>
>>> VerifySqueak(squeak, signature)
>>> decrypted_content = DecryptContent(squeak, decryption_key)
>>>
>>> print(decrypted_content.rstrip(b"\00"))
b'Hello world!'
```
