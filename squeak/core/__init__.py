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
from abc import ABC
from abc import abstractmethod
from typing import Optional
from typing import Tuple

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


class CBaseSqueak(ABC):
    """The base of a squeak (for both squeak and resqueak)"""

    @abstractmethod
    def get_header(self) -> ImmutableSerializable:
        """Return the header
        """

    @abstractmethod
    def GetSignature(self):
        """Return the signature."""

    @abstractmethod
    def SetSignature(self, sig):
        """Set the signature."""

    def GetHash(self) -> bytes:
        """Return the hash
        Note that this is the hash of the header.
        """
        return self.get_header().GetHash()

    def CheckSignature(self):
        """Check if the given squeak has a valid signature.

        squeak (CSqueak)
        """
        sig = self.GetSignature()
        squeak_hash = self.GetHash()
        pubkey = self.GetPubKey()
        if not pubkey.verify(squeak_hash, sig):
            raise CheckSqueakSignatureError("CheckSqueakSignature() : invalid signature for the given squeak")


class CBaseSqueakHeader(ImmutableSerializable):
    """The base of a squeak header (for both squeak and resqueak)"""
    __slots__ = ['nVersion', 'hashReplySqk', 'hashBlock', 'nBlockHeight', 'pubKey', 'nTime', 'nNonce']

    def __init__(self, nVersion=SQUEAK_VERSION, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, nTime=0, nNonce=0):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashReplySqk) == HASH_LENGTH
        object.__setattr__(self, 'hashReplySqk', hashReplySqk)
        assert len(hashBlock) == HASH_LENGTH
        object.__setattr__(self, 'hashBlock', hashBlock)
        object.__setattr__(self, 'nBlockHeight', nBlockHeight)
        assert len(pubKey) == PUB_KEY_LENGTH
        object.__setattr__(self, 'pubKey', pubKey)
        object.__setattr__(self, 'nTime', nTime)
        object.__setattr__(self, 'nNonce', nNonce)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashReplySqk = ser_read(f,HASH_LENGTH)
        hashBlock = ser_read(f,HASH_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        pubKey = ser_read(f, PUB_KEY_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(
            nVersion=nVersion,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            nTime=nTime,
            nNonce=nNonce,
        )

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)
        assert len(self.hashBlock) == HASH_LENGTH
        f.write(self.hashBlock)
        f.write(struct.pack(b"<i", self.nBlockHeight))
        assert len(self.pubKey) == PUB_KEY_LENGTH
        f.write(self.pubKey)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nNonce))

    @property
    def is_reply(self):
        """Return True if the squeak is a reply to another squeak."""
        return not self.hashReplySqk == b'\x00'*HASH_LENGTH

    def GetPubKey(self):
        """Return the squeak author pub key."""
        return SqueakPublicKey.from_bytes(self.pubKey)

    @property
    def is_resqueak(self):
        """Return True if the squeak is a resqueak."""
        raise NotImplementedError()


class CSqueakHeader(CBaseSqueakHeader):
    """A squeak header"""
    __slots__ = ['encContent', 'recipientPubKey', 'paymentPoint', 'iv']

    def __init__(self, nVersion=SQUEAK_VERSION, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, nTime=0, nNonce=0, encContent=b'\x00'*ENC_CONTENT_LENGTH, recipientPubKey=b'\x00'*PUB_KEY_LENGTH, paymentPoint=b'\x00'*PAYMENT_POINT_LENGTH, iv=b'\x00'*CIPHER_BLOCK_LENGTH):
        super(CSqueakHeader, self).__init__(
            nVersion=nVersion,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            nTime=nTime,
            nNonce=nNonce,
        )
        assert len(encContent) == ENC_CONTENT_LENGTH
        object.__setattr__(self, 'encContent', encContent)
        assert len(recipientPubKey) == PUB_KEY_LENGTH
        object.__setattr__(self, 'recipientPubKey', recipientPubKey)
        assert len(paymentPoint) == PAYMENT_POINT_LENGTH
        object.__setattr__(self, 'paymentPoint', paymentPoint)
        assert len(iv) == CIPHER_BLOCK_LENGTH
        object.__setattr__(self, 'iv', iv)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashReplySqk = ser_read(f,HASH_LENGTH)
        hashBlock = ser_read(f,HASH_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        pubKey = ser_read(f, PUB_KEY_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        # Extra fields below.
        encContent = ser_read(f,ENC_CONTENT_LENGTH)
        recipientPubKey = ser_read(f, PUB_KEY_LENGTH)
        paymentPoint = ser_read(f,PAYMENT_POINT_LENGTH)
        iv = ser_read(f,CIPHER_BLOCK_LENGTH)
        return cls(
            nVersion=nVersion,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            nTime=nTime,
            nNonce=nNonce,
            encContent=encContent,
            recipientPubKey=recipientPubKey,
            paymentPoint=paymentPoint,
            iv=iv,
        )

    def stream_serialize(self, f):
        super(CSqueakHeader, self).stream_serialize(f)
        assert len(self.encContent) == ENC_CONTENT_LENGTH
        f.write(self.encContent)
        assert len(self.recipientPubKey) == PUB_KEY_LENGTH
        f.write(self.recipientPubKey)
        assert len(self.paymentPoint) == PAYMENT_POINT_LENGTH
        f.write(self.paymentPoint)
        assert len(self.iv) == CIPHER_BLOCK_LENGTH
        f.write(self.iv)

    @property
    def is_resqueak(self):
        """Return True if the squeak is a resqueak."""
        return False

    @property
    def is_private_message(self):
        """Return True if the squeak is a reply to another squeak."""
        return self.recipientPubKey != b'\x00'*PUB_KEY_LENGTH

    def is_secret_key_valid(self, secret_key: bytes):
        """Return True if the secret key is valid."""
        payment_point_encoded = payment_point_bytes_from_scalar_bytes(secret_key)
        return payment_point_encoded == self.paymentPoint

    def GetRecipientPubKey(self):
        """Return the recipient pub key."""
        if not self.is_private_message:
            return None
        return SqueakPublicKey.from_bytes(self.recipientPubKey)

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

    def __repr__(self):
        return "%s(nVersion: %i, encContent: lx(%s), hashReplySqk: lx(%s), hashBlock: lx(%s), nBlockHeight: %s, pubKey: %r, recipientPubKey: %r, paymentPoint: b2lx(%s), iv: lx(%s), nTime: %s, nNonce: 0x%08x)" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.encContent), b2lx(self.hashReplySqk),
             b2lx(self.hashBlock), self.nBlockHeight, b2lx(self.pubKey), b2lx(self.pubKey), b2lx(self.paymentPoint), b2lx(self.iv), self.nTime, self.nNonce)


class CSqueak(CBaseSqueak, CSqueakHeader):
    """A squeak including the encrypted content in it"""
    __slots__ = ['sig']

    def __init__(self, nVersion=1, encContent=b'\x00'*ENC_CONTENT_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, recipientPubKey=b'\x00'*PUB_KEY_LENGTH, paymentPoint=b'\x00'*PAYMENT_POINT_LENGTH, iv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0, sig=b'\x00'*SIGNATURE_LENGTH):
        """Create a new squeak"""
        super(CSqueak, self).__init__(
            nVersion=nVersion,
            encContent=encContent,
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
        object.__setattr__(self, 'sig', sig)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CSqueak, cls).stream_deserialize(f)
        sig = ser_read(f, SIGNATURE_LENGTH)
        object.__setattr__(self, 'sig', sig)
        return self

    def stream_serialize(self, f):
        super(CSqueak, self).stream_serialize(f)
        assert len(self.sig) == SIGNATURE_LENGTH
        f.write(self.sig)

    def get_header(self):
        """Return the squeak header
        Returned header is a new object.
        """
        return CSqueakHeader(
            nVersion=self.nVersion,
            encContent=self.encContent,
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

    def GetSignature(self):
        """Return the signature."""
        return self.sig

    def SetSignature(self, sig):
        """Set the signature."""
        object.__setattr__(self, 'sig', sig)


class CResqueakHeader(CBaseSqueakHeader):
    """A resqueak including the hash of the resqueaked squeak."""
    __slots__ = ['hashResqueakSqk']

    def __init__(self, nVersion=1, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, nTime=0, nNonce=0, hashResqueakSqk=b'\x00'*HASH_LENGTH):
        """Create a new resqueak"""
        super(CResqueakHeader, self).__init__(
            nVersion=nVersion,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            nTime=nTime,
            nNonce=nNonce,
        )
        assert len(hashResqueakSqk) == HASH_LENGTH
        object.__setattr__(self, 'hashResqueakSqk', hashResqueakSqk)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashReplySqk = ser_read(f,HASH_LENGTH)
        hashBlock = ser_read(f,HASH_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        pubKey = ser_read(f, PUB_KEY_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        hashResqueakSqk = ser_read(f,HASH_LENGTH)
        return cls(
            nVersion=nVersion,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            nTime=nTime,
            nNonce=nNonce,
            hashResqueakSqk=hashResqueakSqk
        )

    def stream_serialize(self, f):
        super(CResqueakHeader, self).stream_serialize(f)
        assert len(self.hashResqueakSqk) == HASH_LENGTH
        f.write(self.hashResqueakSqk)

    def GetResqueakHash(self):
        """Return the signature."""
        return self.hashResqueakSqk

    @property
    def is_resqueak(self):
        """Return True if the squeak is a resqueak."""
        return True

    def __repr__(self):
        return "%s(nVersion: %i, hashReplySqk: lx(%s), hashBlock: lx(%s), nBlockHeight: %s, pubKey: %r, nTime: %s, nNonce: 0x%08x, hashReplySqk: lx(%s))" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.hashReplySqk),
             b2lx(self.hashBlock), self.nBlockHeight, b2lx(self.pubKey), self.nTime, self.nNonce,
             b2lx(self.hashReplySqk))


class CResqueak(CBaseSqueak, CResqueakHeader):
    """A resqueak including the signature"""
    __slots__ = ['sig']

    def __init__(self, nVersion=1, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, pubKey=b'\x00'*PUB_KEY_LENGTH, nTime=0, nNonce=0, hashResqueakSqk=b'\x00'*HASH_LENGTH, sig=b'\x00'*SIGNATURE_LENGTH):
        """Create a new resqueak"""
        super(CResqueak, self).__init__(
            nVersion=nVersion,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            pubKey=pubKey,
            nTime=nTime,
            nNonce=nNonce,
            hashResqueakSqk=hashResqueakSqk
        )
        object.__setattr__(self, 'sig', sig)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CResqueak, cls).stream_deserialize(f)
        sig = ser_read(f, SIGNATURE_LENGTH)
        object.__setattr__(self, 'sig', sig)
        return self

    def stream_serialize(self, f):
        super(CResqueak, self).stream_serialize(f)
        assert len(self.sig) == SIGNATURE_LENGTH
        f.write(self.sig)

    def get_header(self):
        """Return the resqueak header
        Returned header is a new object.
        """
        return CResqueakHeader(
            nVersion=self.nVersion,
            hashReplySqk=self.hashReplySqk,
            hashBlock=self.hashBlock,
            nBlockHeight=self.nBlockHeight,
            pubKey=self.pubKey,
            nTime=self.nTime,
            nNonce=self.nNonce,
            hashResqueakSqk=self.hashResqueakSqk
        )

    def GetSignature(self):
        """Return the signature."""
        return self.sig

    def SetSignature(self, sig):
        """Set the signature."""
        object.__setattr__(self, 'sig', sig)


class CheckSqueakHeaderError(ValidationError):
    pass


class CheckSqueakError(CheckSqueakHeaderError):
    pass


class CheckSqueakSignatureError(CheckSqueakError):
    pass


class CheckSqueakSecretKeyError(CheckSqueakError):
    pass


def SignSqueak(private_key: SqueakPrivateKey, base_squeak_header: CBaseSqueakHeader):
    """Generate a signature for the given base squeak header.

    private_key (SqueakPrivateKey)
    base_squeak_header (CBaseSQueakheader)
    """
    squeak_hash = base_squeak_header.GetHash()
    return private_key.sign(squeak_hash)


def CheckSqueakSignature(base_squeak: CBaseSqueak):
    """Check if the given squeak has a valid signature.

    base_squeak (CBaseSqueak)
    """
    return base_squeak.CheckSignature()


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


# def HashEncryptedContent(enc_content: bytes):
#     """Return the hash of the encrypted content.

#     enc_content (bytes)
#     """
#     squeak_enc_content = CSqueakEncContent(enc_content)
#     return squeak_enc_content.GetHash()


def CheckSqueak(base_squeak: CBaseSqueak):
    """Context independent CBaseSqueak checks.

    CheckSqueakHeader() is called first, which may raise a CheckSqueakHeader
    exception, followed by the squeak tests.
    """

    # Signature check
    CheckSqueakSignature(base_squeak)


def MakeSqueak(
        private_key: SqueakPrivateKey,
        content: bytes,
        block_height: int,
        block_hash: bytes,
        timestamp: int,
        reply_to: Optional[bytes] = None,
        recipient: Optional[SqueakPublicKey] = None,
) -> Tuple[CSqueak, bytes]:
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
    payment_point_encoded = payment_point_bytes_from_scalar_bytes(secret_key)
    nonce = generate_nonce()
    author_public_key = private_key.get_public_key()
    squeak = CSqueak(
        encContent=enc_content,
        hashReplySqk=reply_to or b'\x00'*HASH_LENGTH,
        hashBlock=block_hash,
        nBlockHeight=block_height,
        pubKey=author_public_key.to_bytes(),
        recipientPubKey=recipient.to_bytes() if recipient else b'\x00'*PUB_KEY_LENGTH,
        paymentPoint=payment_point_encoded,
        iv=initialization_vector,
        nTime=timestamp,
        nNonce=nonce,
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
) -> Tuple[CSqueak, bytes]:
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


def MakeResqueak(
        private_key: SqueakPrivateKey,
        resqueak_hash: bytes,
        block_height: int,
        block_hash: bytes,
        timestamp: int,
        reply_to: Optional[bytes] = None,
) -> CResqueak:
    """Create a new resqueak.

    Returns a resqueak

    private_key (SqueakPrivatekey)
    resqueak_hash (bytes)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    reply_to (Optional[bytes])
    """
    nonce = generate_nonce()
    author_public_key = private_key.get_public_key()
    resqueak = CResqueak(
        hashReplySqk=reply_to or b'\x00'*HASH_LENGTH,
        hashBlock=block_hash,
        nBlockHeight=block_height,
        pubKey=author_public_key.to_bytes(),
        nTime=timestamp,
        nNonce=nonce,
        hashResqueakSqk=resqueak_hash,
    )
    sig = SignSqueak(private_key, resqueak)
    resqueak.SetSignature(sig)
    return resqueak


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
