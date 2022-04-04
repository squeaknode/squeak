# Protocol

### Structures

#### squeak header

Field Size | Description | Data type | Comments
--- | --- | --- | ---
4 | nVersion | int32_t | Squeak version information
32 | hashEncContent | char[32] | The hash value of the encrypted content of the squeak
32 | hashReplySqk | char[32] | The hash value of the previous squeak in the conversation thread or null bytes if squeak is not a reply
32 | hashBlock | char[32] | The hash value of the latest block in the blockchain
4 | nBlockHeight | int32_t | The height of the latest block in the blockchain
32 | pubKey | char[32] | Contains the public key of the author
32 | recipientPubKey | char[32] | Contains the public key of the recipient if squeak is a private message
33 | paymentPoint | char[33] | The payment point of the squeak derived from the decryption key on the secp256k1 curve.
16 | iv | char[16] | Random bytes used for the initialization vector
4 | nTime | uint32_t | A timestamp recording when this squeak was created
4 | nNonce | uint32_t | The nonce used to generate this squeak

Therefore, the total size of a squeak header is 192 bytes.

#### squeak

A squeak has all of the fields of a squeak header plus the following:

Field Size | Description | Data type | Comments
--- | --- | --- | ---
1136 | encContent | char[1136] | Encrypted content
64 | sig | char[64] | Signature over the squeak header by the author

Add these two fields to the squeak header, and the total size of a squeak is 1425 bytes.
