import struct

from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2lx

from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import generate_nonce
from squeak.core.encryption import ENCRYPTION_PUB_KEY_LENGTH
from squeak.core.encryption import ENCRYPTED_DATA_KEY_LENGTH
from squeak.core.encryption import INITIALIZATION_VECTOR_LENGTH
from squeak.core.signing import CVerifyingKey
from squeak.core.signing import PUB_KEY_LENGTH


# Core definitions
ENC_CONTENT_LENGTH = 1136  # This is the length of cipher text when content length is 280*4.
HASH_LENGTH = 32
SQUEAK_VERSION = 1


class ValidationError(Exception):
    """Base class for all squeak validation errors
    Everything that is related to validating the squeak,
    content, signature, etc. is derived from this class.
    """


class CSqueakHeader(ImmutableSerializable):
    """A squeak header"""
    __slots__ = ['nVersion', 'hashEncContent', 'vchPubkey', 'vchEncPubkey', 'vchEncDatakey', 'vchIv', 'nBlockHeight', 'hashBlock', 'hashReplySqk', 'nTime', 'nNonce']

    def __init__(self, nVersion=SQUEAK_VERSION, hashEncContent=b'\x00'*HASH_LENGTH, vchPubkey=b'\x00'*PUB_KEY_LENGTH, vchEncPubkey=b'\x00'*ENCRYPTION_PUB_KEY_LENGTH, vchEncDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, vchIv=b'\x00'*INITIALIZATION_VECTOR_LENGTH, nBlockHeight=-1, hashBlock=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, nTime=0, nNonce=0):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashEncContent) == HASH_LENGTH
        object.__setattr__(self, 'hashEncContent', hashEncContent)
        assert len(vchPubkey) == PUB_KEY_LENGTH
        object.__setattr__(self, 'vchPubkey', vchPubkey)
        assert len(vchEncPubkey) == ENCRYPTION_PUB_KEY_LENGTH
        object.__setattr__(self, 'vchEncPubkey', vchEncPubkey)
        assert len(vchEncDatakey) == ENCRYPTED_DATA_KEY_LENGTH
        object.__setattr__(self, 'vchEncDatakey', vchEncDatakey)
        assert len(vchIv) == INITIALIZATION_VECTOR_LENGTH
        object.__setattr__(self, 'vchIv', vchIv)
        object.__setattr__(self, 'nBlockHeight', nBlockHeight)
        assert len(hashBlock) == HASH_LENGTH
        object.__setattr__(self, 'hashBlock', hashBlock)
        assert len(hashReplySqk) == HASH_LENGTH
        object.__setattr__(self, 'hashReplySqk', hashReplySqk)
        object.__setattr__(self, 'nTime', nTime)
        object.__setattr__(self, 'nNonce', nNonce)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashEncContent = ser_read(f,HASH_LENGTH)
        vchPubkey = ser_read(f,PUB_KEY_LENGTH)
        vchEncPubkey = ser_read(f,ENCRYPTION_PUB_KEY_LENGTH)
        vchEncDatakey = ser_read(f,ENCRYPTED_DATA_KEY_LENGTH)
        vchIv = ser_read(f,INITIALIZATION_VECTOR_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        hashBlock = ser_read(f,HASH_LENGTH)
        hashReplySqk = ser_read(f,HASH_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(nVersion, hashEncContent, vchPubkey, vchEncPubkey, vchEncDatakey, vchIv, nBlockHeight, hashBlock, hashReplySqk, nTime, nNonce)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashEncContent) == HASH_LENGTH
        f.write(self.hashEncContent)
        assert len(self.vchPubkey) == PUB_KEY_LENGTH
        f.write(self.vchPubkey)
        assert len(self.vchEncPubkey) == ENCRYPTION_PUB_KEY_LENGTH
        f.write(self.vchEncPubkey)
        assert len(self.vchEncDatakey) == ENCRYPTED_DATA_KEY_LENGTH
        f.write(self.vchEncDatakey)
        assert len(self.vchIv) == INITIALIZATION_VECTOR_LENGTH
        f.write(self.vchIv)
        f.write(struct.pack(b"<i", self.nBlockHeight))
        assert len(self.hashBlock) == HASH_LENGTH
        f.write(self.hashBlock)
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nNonce))

    @property
    def is_reply(self):
        """Return True if the squeak is a reply to another squeak."""
        return self.hashReplySqk != b'\x00'*HASH_LENGTH

    def __repr__(self):
        return "%s(%i, lx(%s), lx(%s), lx(%s), lx(%s), lx(%s), %s, lx(%s), lx(%s), %s, 0x%08x)" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.hashEncContent), b2lx(self.vchPubkey),
             b2lx(self.vchEncPubkey), b2lx(self.vchEncDatakey), b2lx(self.vchIv), self.nBlockHeight,
             b2lx(self.hashBlock), b2lx(self.hashReplySqk), self.nTime, self.nNonce)


class CSqueak(CSqueakHeader):
    """A squeak including the encrypted text content in it"""
    __slots__ = ['encContent']

    def __init__(self, nVersion=1, hashEncContent=b'\x00'*HASH_LENGTH, vchPubkey=b'\x00'*PUB_KEY_LENGTH, vchEncPubkey=b'\x00'*ENCRYPTION_PUB_KEY_LENGTH, vchEncDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, vchIv=b'\x00'*INITIALIZATION_VECTOR_LENGTH, nBlockHeight=-1, hashBlock=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, nTime=0, nNonce=0, encContent=None):
        """Create a new squeak"""
        super(CSqueak, self).__init__(nVersion, hashEncContent, vchPubkey, vchEncPubkey, vchEncDatakey, vchIv, nBlockHeight, hashBlock, hashReplySqk, nTime, nNonce)
        if encContent is None:
            encContent = CSqueakEncContent(b'\00'*ENC_CONTENT_LENGTH)
        object.__setattr__(self, 'encContent', encContent)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CSqueak, cls).stream_deserialize(f)
        encContent = CSqueakEncContent.stream_deserialize(f)
        object.__setattr__(self, 'encContent', encContent)
        return self

    def stream_serialize(self, f):
        super(CSqueak, self).stream_serialize(f)
        CSqueakEncContent.stream_serialize(self.encContent, f)

    def get_header(self):
        """Return the squeak header
        Returned header is a new object.
        """
        return CSqueakHeader(
            nVersion=self.nVersion,
            hashEncContent=self.hashEncContent,
            vchPubkey=self.vchPubkey,
            vchEncPubkey=self.vchEncPubkey,
            vchEncDatakey=self.vchEncDatakey,
            vchIv=self.vchIv,
            nBlockHeight=self.nBlockHeight,
            hashBlock=self.hashBlock,
            hashReplySqk=self.hashReplySqk,
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


class CSqueakEncContent(ImmutableSerializable):
    """A squeak header"""
    __slots__ = ['vchEncContent']

    def __init__(self, vchEncContent=b'\x00'*ENC_CONTENT_LENGTH):
        assert len(vchEncContent) == ENC_CONTENT_LENGTH
        object.__setattr__(self, 'vchEncContent', vchEncContent)

    @classmethod
    def stream_deserialize(cls, f):
        vchEncContent = ser_read(f,ENC_CONTENT_LENGTH)
        return cls(vchEncContent)

    def stream_serialize(self, f):
        assert len(self.vchEncContent) == ENC_CONTENT_LENGTH
        f.write(self.vchEncContent)

    def __repr__(self):
        return "%s(lx(%s))" % \
            (self.__class__.__name__, b2lx(self.vchEncContent))


class CheckSqueakSignatureError(ValidationError):
    pass


def SignSqueak(signing_key, squeak_header):
    """Generate a signature for the given squeak header

    signing_key (CSigningKey)
    squeak_header (CSqueakHeader)
    """
    return signing_key.sign(squeak_header.GetHash())


def VerifySqueak(squeak_header, signature):
    """Check if the given signature is valid

    squeak_header (CSqueakHeader)
    signature (bytes)
    """
    verifying_key = CVerifyingKey.deserialize(squeak_header.vchPubkey)
    if not verifying_key.verify(squeak_header.GetHash(), signature):
        raise CheckSqueakSignatureError("VerifySqueak() : invalid signature for the given squeak header")


def EncryptContent(data_key, iv, content):
    """Return the ciphertext from the given content.

    data_key (bytes)
    iv (bytes)
    content (bytes)
    """
    return CSqueakEncContent(encrypt_content(data_key, iv, content))


def DecryptContent(squeak, decryption_key):
    """Return the decrypted content.

    squeak (Squeak)
    decryption_key (CDecryptionKey)
    """
    data_key_cipher = squeak.vchEncDatakey
    data_key = decryption_key.decrypt(data_key_cipher)
    iv = squeak.vchIv
    ciphertext = squeak.encContent.vchEncContent
    return decrypt_content(data_key, iv, ciphertext)


def EncryptDataKey(encryption_key, data_key):
    """Return the ciphertext from the given content.

    encryption_key (CEncryptionKey)
    data_key (bytes)
    """
    return encryption_key.encrypt(data_key)


class CheckSqueakHeaderError(ValidationError):
    pass


class CheckSqueakError(CheckSqueakHeaderError):
    pass


def CheckSqueakHeader(squeak_header):
    """Context independent CSqueakHeader checks.
    Raises CSqueakHeaderError if squeak header is invalid.
    """
    # TODO: implement
    pass


def CheckSqueak(squeak):
    """Context independent CSqueak checks.

    CheckSqueakHeader() is called first, which may raise a CheckSqueakHeader
    exception, followed the squeak tests. CheckContent() is called for content.
    """
    hash_enc_content = squeak.encContent.GetHash()
    if not hash_enc_content == squeak.hashEncContent:
        raise CheckSqueak("CheckSqueak() : hashEncContent does not match hash of encContent")


def MakeSqueak(signing_key, content, reply_to, block_height, block_hash, timestamp):
    """Create a new squeak.

    signing_key (CSigningkey)
    content (bytes)
    reply_to (bytes)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    """
    data_key = generate_data_key()
    initialization_vector = generate_initialization_vector()
    enc_content = EncryptContent(data_key, initialization_vector, content)
    decryption_key = CDecryptionKey.generate()
    encryption_key = decryption_key.get_encryption_key()
    data_key_cipher = EncryptDataKey(encryption_key, data_key)
    nonce = generate_nonce()
    verifying_key = signing_key.get_verifying_key()
    squeak = CSqueak(
        hashEncContent=enc_content.GetHash(),
        vchPubkey=verifying_key.serialize(),
        vchEncPubkey=encryption_key.serialize(),
        vchEncDatakey=data_key_cipher,
        vchIv=initialization_vector,
        nBlockHeight=block_height,
        hashBlock=block_hash,
        hashReplySqk=reply_to,
        nTime=timestamp,
        nNonce=nonce,
        encContent=enc_content,
    )
    signature = SignSqueak(signing_key, squeak)
    return squeak, decryption_key, signature


__all__ = (
    'ENC_CONTENT_LENGTH',
    'CSqueakHeader',
    'CSqueak',
    'SignSqueak',
    'VerifySqueak',
    'EncryptContent',
    'DecryptContent',
    'EncryptDataKey',
    'CheckSqueakHeader',
    'CheckSqueak',
    'MakeSqueak',
)
