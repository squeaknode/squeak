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

Create a squeak, verify it with the signature script, and decrypt the content:

```
>>> import time
>>>
>>> from bitcoin.core import lx
>>>
>>> from squeak.core import MakeSqueak
>>> from squeak.core import VerifySqueakSignature
>>> from squeak.core import DecryptContent
>>> from squeak.core import CONTENT_LENGTH
>>> from squeak.core.signing import CSigningKey
>>>
>>> signing_key = CSigningKey.generate()
>>>
>>> block_height = 0
>>> block_hash = lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')
>>>
>>> content = b"Hello world!".ljust(CONTENT_LENGTH, b"\x00")
>>> timestamp = int(time.time())
>>>
>>> squeak, decryption_key, sig_script = MakeSqueak(
...     signing_key,
...     content,
...     block_height,
...     block_hash,
...     timestamp,
... )
>>>
>>> print(squeak.GetHash())
b'\x8b\xe6\x04\x87\xc0B\xb4\xf4of\x91p-\xc8Nw\xd2Z]_\x8b\x005\x0b\xb8\x19\x9b\xb0p\x98\xf6\x18'
>>> print(squeak.GetAddress())
1LU2c2iUorm1DJHrdmoU2wwJSPUrJythGq
>>>
>>> VerifySqueakSignature(squeak, sig_script)
>>> decrypted_content = DecryptContent(squeak, decryption_key)
>>>
>>> print(decrypted_content.rstrip(b"\00"))
b'Hello world!'
```

Create a getheaders messages with a given squeak address and block height range, serialize it, and deserialize it:

```
>>> from io import BytesIO
>>>
>>> from squeak.messages import MsgSerializable
>>> from squeak.messages import msg_getheaders
>>> from squeak.net import CInterested
>>> from squeak.net import CSqueakLocator
>>> from squeak.core.signing import CSqueakAddress
>>>
>>>
>>> address = CSqueakAddress('1LU2c2iUorm1DJHrdmoU2wwJSPUrJythGq')
>>>
>>> locator = CSqueakLocator([
...     CInterested(address, 10, 15),
... ])
>>> getheaders = msg_getheaders(locator)
>>>
>>> getheaders_bytes = getheaders.serialize()
>>> getheaders_deserialized = MsgSerializable.stream_deserialize(BytesIO(getheaders_bytes))
>>>
>>> print(getheaders_deserialized)
msg_getheaders(locator=CSqueakLocator(nVersion=60002 vInterested=[CInterested(address=P2PKHBitcoinAddress('1LU2c2iUorm1DJHrdmoU2wwJSPUrJythGq') nMinBlockHeight=10 nMaxBlockHeight=15 hashReplySqk=0000000000000000000000000000000000000000000000000000000000000000)]))
```
