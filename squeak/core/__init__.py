# MIT License
#
# Copyright (c) 2020 Jonathan Zernik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import struct
from typing import Optional

from bitcoin.core import b2lx
from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.core.serialize import ser_read

from squeak.core.elliptic import generate_secret_key
from squeak.core.elliptic import payment_point_bytes_from_scalar_bytes
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import generate_nonce
from squeak.core.encryption import xor_bytes
from squeak.core.hashing import sha256
from squeak.core.keys import PUB_KEY_LENGTH
from squeak.core.keys import SIGNATURE_LENGTH
from squeak.core.keys import SqueakPrivateKey
from squeak.core.keys import SqueakPublicKey


# Core definitions
CONTENT_LENGTH = 1120  # 280*4
ENC_CONTENT_LENGTH = 1136  # This is the length of cipher text when content length is 280*4.
HASH_LENGTH = 32
SQUEAK_VERSION = 1
PAYMENT_POINT_LENGTH = 33
SECRET_KEY_LENGTH = 32


class ValidationError(Exception):
    """Base class for all squeak validation errors
    Everything that is related to validating the squeak,
    content, signature, etc. is derived from this class.
    """


class CSqueakHeader(ImmutableSerializable):
    """A squeak header"""
    __slots__ = ['nVersion', 'hashEncContent', 'hashReplySqk', 'hashBlock', 'nBlockHeight', 'pubKey', 'recipientPubKey', 'paymentPoint', 'iv', 'nTime', 'nNonce']

    def __init__(self, nVersion=SQUEAK_VERSION, hashEncContent=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, recipientPubKey=b'\x00'*PUB_KEY_LENGTH, paymentPoint=b'\x00'*PAYMENT_POINT_LENGTH, iv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashEncContent) == HASH_LENGTH
        object.__setattr__(self, 'hashEncContent', hashEncContent)
        assert len(hashReplySqk) == HASH_LENGTH
        object.__setattr__(self, 'hashReplySqk', hashReplySqk)
        assert len(hashBlock) == HASH_LENGTH
        object.__setattr__(self, 'hashBlock', hashBlock)
        object.__setattr__(self, 'nBlockHeight', nBlockHeight)
        assert len(pubKey) == PUB_KEY_LENGTH
        object.__setattr__(self, 'pubKey', pubKey)
        assert len(recipientPubKey) == PUB_KEY_LENGTH
        object.__setattr__(self, 'recipientPubKey', recipientPubKey)
        assert len(paymentPoint) == PAYMENT_POINT_LENGTH
        object.__setattr__(self, 'paymentPoint', paymentPoint)
        assert len(iv) == CIPHER_BLOCK_LENGTH
        object.__setattr__(self, 'iv', iv)
        object.__setattr__(self, 'nTime', nTime)
        object.__setattr__(self, 'nNonce', nNonce)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashEncContent = ser_read(f,HASH_LENGTH)
        hashReplySqk = ser_read(f,HASH_LENGTH)
        hashBlock = ser_read(f,HASH_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        pubKey = ser_read(f, PUB_KEY_LENGTH)
        recipientPubKey = ser_read(f, PUB_KEY_LENGTH)
        paymentPoint = ser_read(f,PAYMENT_POINT_LENGTH)
        iv = ser_read(f,CIPHER_BLOCK_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(
            nVersion=nVersion,
            hashEncContent=hashEncContent,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            recipientPubKey=recipientPubKey,
            paymentPoint=paymentPoint,
            iv=iv,
            nTime=nTime,
            nNonce=nNonce,
        )

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashEncContent) == HASH_LENGTH
        f.write(self.hashEncContent)
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)
        assert len(self.hashBlock) == HASH_LENGTH
        f.write(self.hashBlock)
        f.write(struct.pack(b"<i", self.nBlockHeight))
        assert len(self.pubKey) == PUB_KEY_LENGTH
        f.write(self.pubKey)
        assert len(self.recipientPubKey) == PUB_KEY_LENGTH
        f.write(self.recipientPubKey)
        assert len(self.paymentPoint) == PAYMENT_POINT_LENGTH
        f.write(self.paymentPoint)
        assert len(self.iv) == CIPHER_BLOCK_LENGTH
        f.write(self.iv)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nNonce))

    @property
    def is_reply(self):
        """Return True if the squeak is a reply to another squeak."""
        return not self.hashReplySqk == b'\x00'*HASH_LENGTH

    @property
    def is_private_message(self):
        """Return True if the squeak is a reply to another squeak."""
        return self.recipientPubKey != b'\x00'*PUB_KEY_LENGTH

    def is_secret_key_valid(self, secret_key: bytes):
        """Return True if the secret key is valid."""
        payment_point_encoded = payment_point_bytes_from_scalar_bytes(secret_key)
        return payment_point_encoded == self.paymentPoint

    def GetPubKey(self):
        """Return the squeak author pub key."""
        return SqueakPublicKey.from_bytes(self.pubKey)

    def GetRecipientPubKey(self):
        """Return the recipient pub key."""
        if not self.is_private_message:
            return None
        return SqueakPublicKey.from_bytes(self.recipientPubKey)

    def __repr__(self):
        return "%s(nVersion: %i, hashEncContent: lx(%s), hashReplySqk: lx(%s), hashBlock: lx(%s), nBlockHeight: %s, pubKey: %r, recipientPubKey: %r, paymentPoint: b2lx(%s), iv: lx(%s), nTime: %s, nNonce: 0x%08x)" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.hashEncContent), b2lx(self.hashReplySqk),
             b2lx(self.hashBlock), self.nBlockHeight, b2lx(self.pubKey), b2lx(self.pubKey), b2lx(self.paymentPoint), b2lx(self.iv), self.nTime, self.nNonce)


class CSqueak(CSqueakHeader):
    """A squeak including the encrypted content in it"""
    __slots__ = ['encContent', 'sig']

    def __init__(self, nVersion=1, hashEncContent=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, recipientPubKey=b'\x00'*PUB_KEY_LENGTH, paymentPoint=b'\x00'*PAYMENT_POINT_LENGTH, iv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0, encContent=b'\x00'*ENC_CONTENT_LENGTH, sig=b'\x00'*SIGNATURE_LENGTH):
        """Create a new squeak"""
        super(CSqueak, self).__init__(
            nVersion=nVersion,
            hashEncContent=hashEncContent,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            recipientPubKey=recipientPubKey,
            paymentPoint=paymentPoint,
            iv=iv,
            nTime=nTime,
            nNonce=nNonce,
        )
        object.__setattr__(self, 'encContent', encContent)
        object.__setattr__(self, 'sig', sig)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CSqueak, cls).stream_deserialize(f)
        encContent = ser_read(f, ENC_CONTENT_LENGTH)
        object.__setattr__(self, 'encContent', encContent)
        sig = ser_read(f, SIGNATURE_LENGTH)
        object.__setattr__(self, 'sig', sig)
        return self

    def stream_serialize(self, f):
        super(CSqueak, self).stream_serialize(f)
        assert len(self.encContent) == ENC_CONTENT_LENGTH
        f.write(self.encContent)
        assert len(self.sig) == SIGNATURE_LENGTH
        f.write(self.sig)

    def get_header(self):
        """Return the squeak header
        Returned header is a new object.
        """
        return CSqueakHeader(
            nVersion=self.nVersion,
            hashEncContent=self.hashEncContent,
            hashReplySqk=self.hashReplySqk,
            hashBlock=self.hashBlock,
            nBlockHeight=self.nBlockHeight,
            pubKey=self.pubKey,
            recipientPubKey=self.recipientPubKey,
            paymentPoint=self.paymentPoint,
            iv=self.iv,
            nTime=self.nTime,
            nNonce=self.nNonce,
        )

    def GetHash(self):
        """Return the squeak hash
        Note that this is the hash of the header, not the entire serialized
        squeak.
        """
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = self.get_header().GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

    def GetEncContentHash(self):
        """Return the hash of the encContent."""
        return HashEncryptedContent(self.encContent)

    def GetSignature(self):
        """Return the signature."""
        return self.sig

    def SetSignature(self, sig):
        """Set the signature."""
        object.__setattr__(self, 'sig', sig)

    def GetDecryptedContent(
            self,
            secret_key: bytes,
            authorPrivKey: Optional[SqueakPrivateKey] = None,
            recipientPrivKey: Optional[SqueakPrivateKey] = None,
    ):
        """Return the decrypted content."""
        CheckSqueakSecretKey(self, secret_key)
        data_key = sha256(secret_key)
        if self.is_private_message:
            if recipientPrivKey:
                shared_key = recipientPrivKey.get_shared_key(self.GetPubKey())
            elif authorPrivKey:
                shared_key = authorPrivKey.get_shared_key(self.GetRecipientPubKey())
            else:
                raise Exception("Author or Recipient private key required to get decrypted content of private squeak")
            data_key = xor_bytes(data_key, shared_key)
        iv = self.iv
        ciphertext = self.encContent
        return decrypt_content(data_key, iv, ciphertext)

    def GetDecryptedContentStr(
            self,
            secret_key: bytes,
            authorPrivKey: Optional[SqueakPrivateKey] = None,
            recipientPrivKey: Optional[SqueakPrivateKey] = None,
    ):
        """Return the decrypted content."""
        content = self.GetDecryptedContent(
            secret_key,
            authorPrivKey=authorPrivKey,
            recipientPrivKey=recipientPrivKey,
        )
        return DecodeContent(content)


class CSqueakEncContent(ImmutableSerializable):
    """Squeak encrypted content"""
    __slots__ = ['encContent']

    def __init__(self, encContent=b'\x00'*ENC_CONTENT_LENGTH):
        assert len(encContent) == ENC_CONTENT_LENGTH
        object.__setattr__(self, 'encContent', encContent)

    @classmethod
    def stream_deserialize(cls, f):
        encContent = ser_read(f,ENC_CONTENT_LENGTH)
        return cls(encContent)

    def stream_serialize(self, f):
        assert len(self.encContent) == ENC_CONTENT_LENGTH
        f.write(self.encContent)

    def get_bytes(self):
        return self.encContent

    def __repr__(self):
        return "%s(lx(%s))" % \
            (self.__class__.__name__, b2lx(self.encContent))


class CheckSqueakHeaderError(ValidationError):
    pass


class CheckSqueakError(CheckSqueakHeaderError):
    pass


class CheckSqueakSignatureError(CheckSqueakError):
    pass


class CheckSqueakSecretKeyError(CheckSqueakError):
    pass


def SignSqueak(private_key: SqueakPrivateKey, squeak_header: CSqueakHeader):
    """Generate a signature for the given squeak header.

    private_key (SqueakPrivateKey)
    squeak_header (CSqueakHeader)
    """
    squeak_hash = squeak_header.GetHash()
    return private_key.sign(squeak_hash)


def CheckSqueakSignature(squeak: CSqueak):
    """Check if the given squeak has a valid signature.

    squeak (CSqueak)
    """
    sig = squeak.GetSignature()
    squeak_hash = squeak.GetHash()
    pubkey = squeak.GetPubKey()
    if not pubkey.verify(squeak_hash, sig):
        raise CheckSqueakSignatureError("CheckSqueakSignature() : invalid signature for the given squeak")


def CheckSqueakSecretKey(squeak: CSqueak, secret_key: bytes):
    """Check if the given squeak has a valid secret key

    squeak (CSqueak)
    secret_key (bytes)
    """
    if secret_key is None:
        raise CheckSqueakSecretKeyError("CheckSqueakSecretKey() : invalid secret key for the given squeak")

    if not squeak.is_secret_key_valid(secret_key):
        raise CheckSqueakSecretKeyError("CheckSqueakSecretKey() : invalid secret key for the given squeak")


class InvalidContentLengthError(ValidationError):
    pass


def EncryptContent(data_key: bytes, iv: bytes, content: bytes):
    """Return the ciphertext from the given content.

    data_key (bytes)
    iv (bytes)
    content (bytes)
    """
    if not len(content) == CONTENT_LENGTH:
        raise InvalidContentLengthError("EncryptContent : content length must be %i; got %i" %
                                        (CONTENT_LENGTH, len(content)))
    return encrypt_content(data_key, iv, content)


def HashEncryptedContent(enc_content: bytes):
    """Return the hash of the encrypted content.

    enc_content (bytes)
    """
    squeak_enc_content = CSqueakEncContent(enc_content)
    return squeak_enc_content.GetHash()


def CheckSqueakHeader(squeak_header: CSqueakHeader):
    """Context independent CSqueakHeader checks.
    Raises CSqueakHeaderError if squeak header is invalid.
    """

    # try:
    #     # squeak_header.GetAddress()
    #     assert len(squeak_header.pubKey) == PUB_KEY_LENGTH
    # except CSqueakAddressError:
    #     raise CheckSqueakHeaderError("CheckSqueakError() : pubkey does not have a valid length.")


def CheckSqueak(squeak: CSqueak):
    """Context independent CSqueak checks.

    CheckSqueakHeader() is called first, which may raise a CheckSqueakHeader
    exception, followed by the squeak tests.
    """

    # Squeak header checks
    CheckSqueakHeader(squeak)

    # Content length check
    if not len(squeak.encContent) == ENC_CONTENT_LENGTH:
        raise CheckSqueakError("CheckSqueak() : encContent length does not match the required length")

    # Content hash check
    hash_enc_content = squeak.GetEncContentHash()
    if not hash_enc_content == squeak.hashEncContent:
        raise CheckSqueakError("CheckSqueak() : hashEncContent does not match hash of encContent")

    # Signature check
    CheckSqueakSignature(squeak)


def MakeSqueak(
        private_key: SqueakPrivateKey,
        content: bytes,
        block_height: int,
        block_hash: bytes,
        timestamp: int,
        reply_to: Optional[bytes] = None,
        recipient: Optional[SqueakPublicKey] = None,
):
    """Create a new squeak.

    Returns a tuple of (squeak, secret_key)

    private_key (SqueakPrivatekey)
    content (bytes)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    reply_to (Optional[bytes])
    recipient (Optional[SqueakPublickey])
    """
    secret_key = generate_secret_key()
    data_key = sha256(secret_key)
    if recipient:
        shared_key = private_key.get_shared_key(recipient)
        data_key = xor_bytes(data_key, shared_key)
    initialization_vector = generate_initialization_vector()
    enc_content = EncryptContent(data_key, initialization_vector, content)
    hash_enc_content = HashEncryptedContent(enc_content)
    payment_point_encoded = payment_point_bytes_from_scalar_bytes(secret_key)
    nonce = generate_nonce()
    author_public_key = private_key.get_public_key()
    squeak = CSqueak(
        hashEncContent=hash_enc_content,
        hashReplySqk=reply_to or b'\x00'*HASH_LENGTH,
        hashBlock=block_hash,
        nBlockHeight=block_height,
        pubKey=author_public_key.to_bytes(),
        recipientPubKey=recipient.to_bytes() if recipient else b'\x00'*PUB_KEY_LENGTH,
        paymentPoint=payment_point_encoded,
        iv=initialization_vector,
        nTime=timestamp,
        nNonce=nonce,
        encContent=enc_content,
    )
    sig = SignSqueak(private_key, squeak)
    squeak.SetSignature(sig)
    return squeak, secret_key


def EncodeContent(content: str):
    """Convert a string into utf-8 encoded bytes of the required length."""
    encoded = content.encode('utf-8')
    padded = encoded.ljust(CONTENT_LENGTH, b"\x00")
    return padded


def DecodeContent(data: bytes):
    """Convert utf-8 encoded bytes to a string."""
    unpadded = data.rstrip(b"\00")
    content = unpadded.decode("utf-8", "strict")
    return content


def MakeSqueakFromStr(
        private_key: SqueakPrivateKey,
        content_str: str,
        block_height: int,
        block_hash: bytes,
        timestamp: int,
        reply_to: Optional[bytes] = None,
        recipient: Optional[SqueakPublicKey] = None,
):
    """Create a new squeak from a string of content.

    Returns a tuple of (squeak, secret_key)

    private_key (CSigningkey)
    content_str (str)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    reply_to (Optional[bytes])
    recipient (Optional[SqueakPublickey])
    """
    reply_to = reply_to or b'\x00'*HASH_LENGTH
    content = EncodeContent(content_str)
    return MakeSqueak(
        private_key,
        content,
        block_height,
        block_hash,
        timestamp,
        reply_to=reply_to,
        recipient=recipient,
    )


__all__ = (
    'ENC_CONTENT_LENGTH',
    'CSqueakHeader',
    'CSqueak',
    'SignSqueak',
    'EncryptContent',
    'EncryptDataKey',
    'CheckSqueakHeader',
    'CheckSqueak',
    'MakeSqueak',
)
