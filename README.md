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

from squeak.core import MakeSqueakFromStr
from squeak.core import CONTENT_LENGTH
from squeak.core.signing import CSigningKey


signing_key = CSigningKey.generate()

block_height = 0
block_hash = lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b')

content = "Hello world!"
timestamp = int(time.time())

squeak = MakeSqueakFromStr(
    signing_key,
    content,
    block_height,
    block_hash,
    timestamp,
)

print(squeak.GetHash())  # prints b"\x9e\xeb\xbc)N\x94\xe2\x85\x9b(d\x7f\x1e7\xb5{\xcbY\xef\xd4;\xf7P\xfe\x19'Q\xb7\x7f\xbda\xaf"
print(squeak.GetAddress())  # prints 16sFQMmfiU9g3B2ZW55YppjMa3icEuncxj
print(squeak.GetDecryptedContentStr())  # Hello world!
```
