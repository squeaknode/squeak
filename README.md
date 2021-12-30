# squeak

[![GitHub release](https://img.shields.io/github/release/squeaknode/squeak.svg)](https://github.com/squeaknode/squeak/releases)
[![codecov](https://codecov.io/gh/squeaknode/squeak/branch/master/graph/badge.svg?token=R4MAF14FYN)](https://codecov.io/gh/squeaknode/squeak)

Python library for Squeak protocol.

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

Create a squeak, verify its signature with the public key, and decrypt the content:

```python
import time

from bitcoin.core import lx

from squeak.core import CheckSqueak
from squeak.core import MakeSqueakFromStr
from squeak.core.keys import SqueakPrivateKey

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
print(squeak.GetPubKey())  # prints SqueakPublicKey('02d2fe30552bb5ec3b6822cec25b7dd7d4163974e28f2f4ef40d1f9d09086704c6')
print(squeak.GetDecryptedContentStr(secret_key))  # Hello world!
```
