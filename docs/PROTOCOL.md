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
32 | pubKey | char[33] | Contains the public key of the author
32 | recipientPubKey | char[33] | Contains the public key of the recipient if squeak is a private message
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

#### squeak locator

Field Size | Description | Data type | Comments
--- | --- | --- | ---
4 | nVersion | uint32_t | The protocol version
? | count | var_int | Number of interested structs
? | interesteds | interested[] | Interested structs

#### interested

Field Size | Description | Data type | Comments
--- | --- | --- | ---
? | count | var_int | Number of addresses
1+ | address length | var_int | Length of the address
33 | pubkey | char[33] | The bytes of the public key identifying the squeak author
4 | nMinBlockHeight | int32_t | The minimum block height or -1 to use no minimum
4 | nMaxBlockHeight | int32_t | The maximum block height or -1 to use no maximum
32 | hashReplySqk | char[32] | The hash value of the previous squeak in the conversation thread or null bytes

#### inv_vect

Field Size | Description | Data type | Comments
--- | --- | --- | ---
4 | type | uint32_t | Identifies the object type linked to this inventory
32 | hash | char[32] | Hash of the object

The object type is currently defined as one of the following possibilities:

Value | Name | Description
--- | --- | ---
0 | ERROR | Any data of with this number may be ignored
1 | MSG_SQUEAK | Hash is related to a squeak
2 | MSG_SECRET_KEY | Hash is related to a squeak secret key

### Messages

#### msg_version
#### msg_verack
#### msg_addr
#### msg_inv

Field Size | Description | Data type | Comments
--- | --- | --- | ---
? | count | var_int | Number of inventory entries
36x? | inventory | inv_vect[] | Inventory vectors

#### msg_getdata

Field Size | Description | Data type | Comments
--- | --- | --- | ---
? | count | var_int | Number of inventory entries
36x? | inventory | inv_vect[] | Inventory vectors

#### msg_notfound

Field Size | Description | Data type | Comments
--- | --- | --- | ---
? | count | var_int | Number of inventory entries
36x? | inventory | inv_vect[] | Inventory vectors

#### msg_getsqueaks

Field Size | Description | Data type | Comments
--- | --- | --- | ---
? | locator | squeak_locator | A single squeak locator struct

#### msg_subscribe

Field Size | Description | Data type | Comments
--- | --- | --- | ---
? | locator | squeak_locator | A single squeak locator struct

#### msg_squeak

Field Size | Description | Data type | Comments
--- | --- | --- | ---
1427 | squeak | char[1427] | The full squeak struct

#### msg_getaddr
#### msg_ping
#### msg_pong
#### msg_offer

Field Size | Description | Data type | Comments
--- | --- | --- | ---
32 | hashSqk | char[32] | The hash value of the squeak
32 | nonce | char[32] | The nonce of the offer
? | strPaymentInfo | var_str | The lightning payment info string for the invoice
? | host | var_str | The host of the seller lightning node
4 | port | uint32_t | The port of the seller lightning node

#### msg_secretkey

Field Size | Description | Data type | Comments
--- | --- | --- | ---
32 | hashSqk | char[32] | The hash value of the squeak
32 | secretKey | char[32] | The secret key of the squeak
