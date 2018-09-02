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
33 | vchPubkey | char[32] | The DSA public key of the author of the squeak, as a compacted SECP256k1 key
162 | vchEncPubkey | char[32] | The RSA public key of the squeak, as an RSA-1024 key
128 | vchEncDatakey | char[32] | The RSA-encrypted AES data key used to encrypt and decrypt the squeak content
16 | vchIv | char[32] | Random bytes used for the initialization vector
4 | nTime | uint32_t | A timestamp recording when this squeak was created
4 | nNonce | uint32_t | The nonce used to generate this squeak

#### squeak

#### squeak locator


### Messages
