Requirements
============

* python3

Test
====

```
make test
```


Examples
========

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
CSqueak(1, lx(d87139fbf24262968813f309e21f634a742dbc0eec7ad2b1ad86fd5b23a35c91), lx(b216d4bb8e90c16eca8c66640ec9311c4e9c5ce640dc3c1235211a244199c20f03), lx(0100010302fb2de517d92df419b49e5feca3cac3ea0257daca8c94fc19d9663f7aaea547fe673c1fc87cd0370bbeb2fe05c73e5e9d71dd1bfb58dd672a6eb587bdd5d72324d3fa47a62fd04e2c5698be94fc31d5e56ad699604c9506d0ce131b93ef3e9e8c37e6d8a20ab9877a600a9bf49b5977b0c0f1260a485e4b423344d171429854dd00818102898130008d810300050101010df78648862a09060d309f8130), lx(e7161563039a84c63d6c77941fd55c946c0d540e6611231acde21b3ce0940183b45f955e23b73cbb8be9481eafca0418f46202db31367090df331c7a52b29f64c141b584ccbc680d05c8db58e9534fd3462b7931396c04160fa0393041dcf89394e731d0f277eed6386b28e906fd939c9fe58d13bcb459102d836d59ccb0a49e), lx(f6269c47c60b895d03335b0c9081b9ad), 0, lx(4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b), lx(0000000000000000000000000000000000000000000000000000000000000000), 1535849555, 0x5e2f6823)
>>>
>>> VerifySqueak(squeak, signature)
>>> decrypted_content = DecryptContent(squeak, decryption_key)
>>>
>>> print(decrypted_content.rstrip(b"\00"))
b'Hello world!'
```
