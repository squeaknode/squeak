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

Create a getheaders messages with a given public key and block height range, serialize it, and deserialize it:

```
>>> from io import BytesIO
>>>
>>> from squeak.messages import MsgSerializable
>>> from squeak.messages import msg_getheaders
>>> from squeak.net import CInterested
>>> from squeak.net import CSqueakLocator
>>>
>>> public_key = b'\x03U\xfc\xd2\xfe\x14:y\xe7\xd0n\x9asZK\xe9b\x05${\x18Z\xc7\xd4\x89vf\x1a\xdb\xf2\xc4\xd2$'
>>>
>>> locator = CSqueakLocator([
...     CInterested(public_key, 10, 15)
... ])
>>> getheaders = msg_getheaders(locator)
>>>
>>> getheaders_bytes = getheaders.serialize()
>>> getheaders_deserialized = MsgSerializable.stream_deserialize(BytesIO(getheaders_bytes))
>>>
>>> print(getheaders_deserialized)
msg_getheaders(locator=CSqueakLocator(nVersion=60002 vInterested=[CInterested(vchPubkey=lx(24d2c4f2db1a667689d4c75a187b240562e94b5a739a6ed0e7793a14fed2fc5503) nMinBlockHeight=10 nMaxBlockHeight=15 hashReplySqk=0000000000000000000000000000000000000000000000000000000000000000)]))
```
