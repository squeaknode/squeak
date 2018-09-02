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
CSqueak(1, lx(7b9cf5637706c7de6293adebf49954b4df66a648490f38b144baaaccaf49f068), lx(430328e2406d9be0250f21cc53910e115c9dd1012ccb267fbbf1a09c41ade7c103), lx(01000103024f0351abd835c3c4e0ff9d0fdb2feb2a6353613139df7edb5d03880b28969de8f225cf48b3db10590a4284101bebb010f063a480ca761bba2cbae1c8fb45c8a9e5764e248fa602d44119baadb26a2cc498f1f0a6d94d7610b6cdc11e9a7705ab9e4c341627eec1c2e460f9c6790a3c7216075e1b18fa34afb68a69846ae626df00818102898130008d810300050101010df78648862a09060d309f8130), lx(182f630b46742287403ea731df9edba454e6a5ba9514d3ef5217c1389ef9fb25486e26edfed4727252b93915fa5fa6f294ba728fe2e8e4d821e5608fad00077c40e75af8d6a92fd9222b558844e836104a7f442601421b3d0956bb48e5c74397f4bf4bc5d4f43b175b70560e0de71d0e3881fc2fe7dd804a94a8ab566a7a2e43), lx(1d2cb2efdc63ff6aa7b4342c647147b8), 0, lx(4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b), lx(0000000000000000000000000000000000000000000000000000000000000000), 1535857025, 0xad728bf7)
>>> print(squeak.GetHash())
b'A\n\xd7\xafb)L:!q\x0cD=\x83\xf2\x8f\x17\xd0\xb7Q\xd3C\x81J\xf63\x0b\xbe\x88\xd4\x10\x83'
>>>
>>> VerifySqueak(squeak, signature)
>>> decrypted_content = DecryptContent(squeak, decryption_key)
>>>
>>> print(decrypted_content.rstrip(b"\00"))
b'Hello world!'
```
