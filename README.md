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
>>> print(squeak.GetHash())
b"\xa7*\x1e\x08\xddg\x8cO\xc5\x8b@\xa0\xc5\x12\xa2'\xac-V\xcb\x1c\xb0_\xf1\x7f\xc1\x04\xb28s(\xbf"
>>>
>>> VerifySqueak(squeak, signature)
>>> decrypted_content = DecryptContent(squeak, decryption_key)
>>>
>>> print(decrypted_content.rstrip(b"\00"))
b'Hello world!'
```
