# Protocol

### Structures

#### Squeak header

[Source](https://github.com/squeaknode/squeak/blob/c079ae321a455a6858018ebd77ef10f68dfdc4b5/squeak/core/__init__.py#L159)

Field Size | Description | Data type | Comments
--- | --- | --- | ---
4 | nVersion | int32_t | Squeak version information
32 | hashReplySqk | char[32] | The hash value of the previous squeak in the conversation thread or null bytes if squeak is not a reply
32 | hashBlock | char[32] | The hash value of the latest block in the blockchain
4 | nBlockHeight | int32_t | The height of the latest block in the blockchain
32 | pubKey | char[32] | Contains the public key of the author
4 | nTime | uint32_t | A timestamp recording when this squeak was created
4 | nNonce | uint32_t | The nonce used to generate this squeak
1136 | encContent | char[1136] | The encrypted ciphertext of the content of the squeak
32 | recipientPubKey | char[32] | Contains the public key of the recipient if squeak is a private message
33 | paymentPoint | char[33] | The payment point of the squeak derived from the decryption key on the secp256k1 curve.
16 | iv | char[16] | Random bytes used for the initialization vector

Therefore, the total size of a `squeak header` is 1329 bytes.

#### Squeak

[Source](https://github.com/squeaknode/squeak/blob/c079ae321a455a6858018ebd77ef10f68dfdc4b5/squeak/core/__init__.py#L283)

A `squeak` has all of the fields of a `squeak header` plus the following:

Field Size | Description | Data type | Comments
--- | --- | --- | ---
64 | sig | char[64] | Signature over the squeak header by the author

Therefore, the total size of a `squeak` is 1393 bytes.

The hash of a `squeak` is calculated by taking the double SHA256 of the header bytes.

#### Resqueak header

[Source](https://github.com/squeaknode/squeak/blob/c079ae321a455a6858018ebd77ef10f68dfdc4b5/squeak/core/__init__.py#L343)

Field Size | Description | Data type | Comments
--- | --- | --- | ---
4 | nVersion | int32_t | Squeak version information
32 | hashReplySqk | char[32] | The hash value of the previous squeak in the conversation thread or null bytes if squeak is not a reply
32 | hashBlock | char[32] | The hash value of the latest block in the blockchain
4 | nBlockHeight | int32_t | The height of the latest block in the blockchain
32 | pubKey | char[32] | Contains the public key of the author
4 | nTime | uint32_t | A timestamp recording when this squeak was created
4 | nNonce | uint32_t | The nonce used to generate this squeak
32 | hashResqueak | char[32] | The hash of the resqueaked squeak

Therefore, the total size of a `resqueak header` is 144 bytes.

#### Resqueak

[Source](https://github.com/squeaknode/squeak/blob/c079ae321a455a6858018ebd77ef10f68dfdc4b5/squeak/core/__init__.py#L403)

A `resqueak` has all of the fields of a `resqueak header` plus the following:

Field Size | Description | Data type | Comments
--- | --- | --- | ---
64 | sig | char[64] | Signature over the resqueak header by the author

Therefore, the total size of a `resqueak` is 208 bytes.

The hash of a `resqueak` is calculated by taking the double SHA256 of the header bytes.
