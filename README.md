# squeak

### Requirements

* python3

### Test

```
make test
```

### Install

```
pip install squeakpy
```

### Examples

Create a squeak, verify it with the signature script, and decrypt the content:

```python
import time

from bitcoin.core import lx

from squeak.core import CheckSqueak
from squeak.core import MakeSqueakFromStr
from squeak.core.signing import SqueakPrivateKey

private_key = SqueakPrivateKey.generate()

block_height = 0
block_hash = lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')

content = "Hello world!"
timestamp = int(time.time())

squeak, secret_key = MakeSqueakFromStr(
    private_key,
    content,
    block_height,
    block_hash,
    timestamp,
)

CheckSqueak(squeak)  # No exception raised

print(squeak.GetHash())  # prints b"\x9e\xeb\xbc)N\x94\xe2\x85\x9b(d\x7f\x1e7\xb5{\xcbY\xef\xd4;\xf7P\xfe\x19'Q\xb7\x7f\xbda\xaf"
b'\x1d\x05\xf1\x98\x00p\x9a(d\x0b\xbde#\x96\x1b\x13i\x92\xbbk\xa7\n\x02;\xab\r\x15\xe6\x83\\\x1d\xcc'
print(squeak.GetPubKey())
<squeak.core.signing.SqueakPublicKey object at 0x7f3a2224f130>
print(squeak.GetDecryptedContentStr(secret_key))  # Hello world!
```
