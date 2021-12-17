# How the Squeak Protocol Works

The Squeak protocol attempts to solve the problem of decentralized social media by allowing users to share content in exchange for Bitcoin payments.

This document describes the challenges and how the Squeak protocol solves them with cryptography.

## The problem of incentives in a decentralized social network
There have been many attempts at creating a decentralized protocol for social media. Almost all of them rely on some kind of relay in the network, that accepts posts from users and makes them available to other users.

### Existing protocols

* [Mastodon](https://github.com/mastodon/mastodon) uses a federation model, where the owner of the instance has complete control of everything that happens on their instance.
* [Nostr](https://github.com/fiatjaf/nostr) uses interchangeable relay servers, so no single relay server has the power to ban or censor someone.

### Reliance on relays

These protocols have one major problem, which is that they rely on hubs or relays for the network to work. There is no incentive for someone to host a Mastodon instance or Nostr relay, aside from altruism. A Nostr relay could charge some amount of money in exchange for relaying content, but there is no guarantee that the relay will actually honor their commitment and share the content with other clients. They could just take the money and throw away the content.

In both cases, users have to rely on the honesty or generosity of the instance/relay owner to provide a service to the network.

### Pull is better than push

Rather than requiring payment for a client to push content to a relay, a better approach is to require payment when a client pulls content. If a relay receives a payment every time a post is downloaded, then the relay owner has an incentive to host as much content as possible to maximize profit.

## Trustless payments for content in an adversarial environment
The Squeak protocol attempts to solve this problem by creating a "flat" network, where every node can connect to every other node, and there is no distinction between clients and relays. Every node can pull content from every other node, and every node follows the same protocol rules.

Every node can act as a relay, and earn a profit by hosting content that is sold to other nodes in the network.

### Payments must be trustless

In order for this type of flat network to work, it must be possible for payments between nodes to work trustlessly. When a user makes a payment to another node to get a specific piece of content, they must have a guarantee they will get what they pay for.

Without the ability to buy content trustlessly, users would be less willing to make payments to other nodes. A reputation system would be necessary, which would make everything inefficient.

## How trustless payments work
The Squeak protocol uses primitives from elliptic curve cryptography to do trustless Bitcoin payments over Lightning in exchange for content.

### Elliptic curve distributive property

We can take advantage of the distributive property of points on elliptic curves:

```
(s1 + s2)*G = s1*G + s2*G
```

where `s1` and `s2` are scalars, and `G` is an elliptic curve.

### Selling decryption keys over Lightning

The basic idea for selling content is as follows:

* Alice has a piece of content she wants to sell.
* Alice generates a scalar value `s1` to use as a symmetric encryption/decryption key, and encrypts the content.
* Alice calculates the point `p1` on an elliptic curve `G` by calculating `p1 = s1*G`.
* Alice publishes `p1` for anyone interested in buying the content.
* Bob downloads the encrypted content, and requests an invoice to unlock the content.
* Alice generates a new scalar value `s2`, and creates a *PTLC* Lightning invoice with `s1 + s2` as the preimage.
* Alice sends Bob `s2` and the Lightning invoice as a payment request string.
* Bob decodes the payment request string to get the payment point of the invoice, call it `p3`.
* Bob calculates `s2*G`. If it is equeal to `p3 - p1`, then Bob knows that the invoice is valid.
* Bob pays the Lightning invoice, and gets the value of `s1 + s2` as the preimage.
* Bob calculates `s1 = (s1 + s2) - s2` to get the decryption key, and decrypts the content.

If Alice tries to give Bob an invalid invoice, Bob will know. And then he will not pay the invoice.


## How squeaks work
The basic unit of content in the Squeak protocol is a squeak.

It is an immutable structure that contains all of the fields necessary to share and validate "locked" posts between nodes.

### Squeak structure

There are two components in a squeak:

* The squeak header
* The external fields outside the header.

A squeak header has the following fields:

Field Size | Description | Data type | Comments
--- | --- | --- | ---
4 | nVersion | int32_t | Squeak version information
32 | hashEncContent | char[32] | The hash value of the encrypted content of the squeak
32 | hashReplySqk | char[32] | The hash value of the previous squeak in the conversation thread or null bytes if squeak is not a reply
32 | hashBlock | char[32] | The hash value of the latest block in the blockchain
4 | nBlockHeight | int32_t | The height of the latest block in the blockchain
1+ | script length | var_int | Length of the scriptPubKey
? | scriptPubKey | char[] | Contains the public key as a script setting up conditions to claim authorship.
33 | paymentPoint | char[33] | The payment point of the squeak derived from the decryption key on the secp256k1 curve.
16 | vchIv | char[16] | Random bytes used for the initialization vector
4 | nTime | uint32_t | A timestamp recording when this squeak was created
4 | nNonce | uint32_t | The nonce used to generate this squeak

There are also external fields outside the header:

Field Size | Description | Data type | Comments
--- | --- | --- | ---
1136 | vchEncContent | char[1136] | Encrypted content
1+ | script length | var_int | Length of the scriptSig
? | scriptSig | char[] | Computational Script for confirming authorship

There is also a squeak hash, which is derived from the bytes of the squeak header using SHA256.

### How a squeak is created

When a user creates a squeak, the following happens:

* An encryption/decryption key is generated as a random scalar value.
* A random initialization vector is generated.
* The post content is encrypted with a symmetric-key algorithm using the encryption key and the initialization vector.
* A hash is calculated over the encrypted ciphertext.
* The payment point is calculated from the encryption key scalar value on an elliptic curve.
* A new nonce is generated.
* The private key of the author is used to create a P2PKH pubkey script.

Also,

* The latest block height and block hash are fetched from the Bitcoin blockchain.
* The hash of another squeak (to make a reply) can also be provided by the author.

All of these values are used to populate the squeak header. After the header is created:

* The squeak hash is calculated from the header.
* The private key of the author is used to sign the squeak hash.
* The signature is then turned into a degenerate (SIGHASH_ALL) sig script, and attached to the squeak.

The `MakeSqueak` function looks like this:

```
def MakeSqueak(signing_key, content, block_height, block_hash, timestamp, reply_to=None):
    """Create a new squeak.
    Returns a tuple of (squeak, decryption_key)
    signing_key (CSigningkey)
    content (bytes)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    reply_to (bytes)
    """
    reply_to = reply_to or b'\x00'*HASH_LENGTH
    secret_key = generate_secret_key()
    data_key = sha256(secret_key)
    initialization_vector = generate_initialization_vector()
    enc_content = EncryptContent(data_key, initialization_vector, content)
    hash_enc_content = HashEncryptedContent(enc_content)
    payment_point_encoded = payment_point_bytes_from_scalar_bytes(secret_key)
    nonce = generate_nonce()
    verifying_key = signing_key.get_verifying_key()
    squeak_address = CSqueakAddress.from_verifying_key(verifying_key)
    pubkey_script = squeak_address.to_scriptPubKey()
    squeak = CSqueak(
        hashEncContent=hash_enc_content,
        hashReplySqk=reply_to,
        hashBlock=block_hash,
        nBlockHeight=block_height,
        vchScriptPubKey=bytes(pubkey_script),
        paymentPoint=payment_point_encoded,
        iv=initialization_vector,
        nTime=timestamp,
        nNonce=nonce,
        encContent=enc_content,
    )
    sig_script = SignSqueak(signing_key, squeak)
    squeak.SetScriptSigBytes(bytes(sig_script))
    return squeak, secret_key
```

### Properties of a squeak

After a squeak is created, it can be shared and validated on any node.

A validated squeak has the following properies:

* The pubkey embedded in the squeak belongs to the author of the squeak (proved by the signature).
* None of the fields in the header were modified after being signed by the author (that would change the hash, and the signature would become invalid if that happened).
* The encrypted content field was not modified after being signed by the author (that would also result in the signature becoming invalid).
* The Bitcoin block hash and block height (if valid) prove that the squeak was created after that block was mined.

### How a user interacts with a squeak

For example, if Alice authored a squeak, and Bob obtained a copy of the squeak:

* Bob will know that the squeak was authored by Alice.
* Bob will know that the squeak was created after a certain time (given by the block hash).
* Bob will know if the squeak is a reply to another squeak.

However, because Bob does not have the decryption key:

* Bob will not be able to see the content of the squeak.

### How a user unlocks the content of a squeak

Now Bob has a choice to make. Is he interested in reading the squeak that Alice authored, given everything he knows about the squeak?

If Bob wants to unlock the content, he can send a message to all of his peers in the network expressing interest in buying the decryption key for the squeak.

Bob's peers in the network (only those who already have a copy of the decryption key) will respond to Bob by sending him invoices as described in the earlier section.

Bob can now browse through the offers, and make a payment to any peer that offered him a valid invoice. Bob knows which invoices are valid because he can validate against `paymentPoint` field of the squeak header, using the elliptic curve math described earlier.

When Bob makes a Lightning payment to one of the sellers, he will obtain the preimage of the invoice. This preimage can be used to get the decryption key:

* The preimage is `s1 + s2`, as described earlier.
* Bob already knows `s2`, because the seller sent it to him.
* Bob calculates `s1 = (s1 + s2) - s2` to obtain the decryption key.
* Bob can then decrypt the content of the squeak.

Now Bob can read the content of the squeak!
