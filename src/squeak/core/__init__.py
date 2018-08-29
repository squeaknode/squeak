import struct

from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.core.serialize import VarStringSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2lx

from squeak.core.encryption import encrypt_assymetric
from squeak.core.encryption import decrypt_assymetric
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import decrypt_content
from squeak.core.signing import deserialize_verifying_key
from squeak.core.signing import sign
from squeak.core.signing import verify


# Core definitions
MAX_SQUEAK_SIZE = 1136  # This is the length of cipher text when content length is 280*4.
PUB_KEY_LENGTH = 33
ENCRYPTION_PUB_KEY_LENGTH = 162
DATA_KEY_LENGTH = 32
ENCRYPTED_DATA_KEY_LENGTH = 128
INITIALIZATION_VECTOR_LENGTH = 16
HASH_LENGTH = 32


class CSqueakHeader(ImmutableSerializable):
    """A squeak header"""
    __slots__ = ['nVersion', 'vchPubkey', 'vchEncPubkey', 'vchEncDatakey', 'vchIv', 'nBlockHeight', 'hashBlock', 'hashReplySqk', 'nTime', 'nNonce']

    def __init__(self, nVersion=1, vchPubkey=b'\x00'*PUB_KEY_LENGTH, vchEncPubkey=b'\x00'*ENCRYPTION_PUB_KEY_LENGTH, vchEncDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, vchIv=b'\x00'*INITIALIZATION_VECTOR_LENGTH, nBlockHeight=-1, hashBlock=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, nTime=0, nNonce=0):
        object.__setattr__(self, 'nVersion', nVersion)
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
        vchPubkey = ser_read(f,PUB_KEY_LENGTH)
        vchEncPubkey = ser_read(f,ENCRYPTION_PUB_KEY_LENGTH)
        vchEncDatakey = ser_read(f,ENCRYPTED_DATA_KEY_LENGTH)
        vchIv = ser_read(f,INITIALIZATION_VECTOR_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        hashBlock = ser_read(f,HASH_LENGTH)
        hashReplySqk = ser_read(f,HASH_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(nVersion, vchPubkey, vchEncPubkey, vchEncDatakey, vchIv, nBlockHeight, hashBlock, hashReplySqk, nTime, nNonce)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
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
        return "%s(%i, lx(%s), lx(%s), lx(%s), lx(%s), %s, lx(%s), lx(%s), %s, 0x%08x)" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.vchPubkey), b2lx(self.vchEncPubkey),
             b2lx(self.vchEncDatakey), b2lx(self.vchIv), self.nBlockHeight, b2lx(self.hashBlock),
             b2lx(self.hashReplySqk), self.nTime, self.nNonce)


class CSqueak(CSqueakHeader):
    """A squeak including the encrypted text content in it"""
    __slots__ = ['strEncContent']

    def __init__(self, nVersion=1, vchPubkey=b'\x00'*PUB_KEY_LENGTH, vchEncPubkey=b'\x00'*ENCRYPTION_PUB_KEY_LENGTH, vchEncDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, vchIv=b'\x00'*INITIALIZATION_VECTOR_LENGTH, nBlockHeight=-1, hashBlock=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, nTime=0, nNonce=0, strEncContent=b''):
        """Create a new squeak"""
        super(CSqueak, self).__init__(nVersion, vchPubkey, vchEncPubkey, vchEncDatakey, vchIv, nBlockHeight, hashBlock, hashReplySqk, nTime, nNonce)
        assert len(strEncContent) <= MAX_SQUEAK_SIZE
        object.__setattr__(self, 'strEncContent', strEncContent)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CSqueak, cls).stream_deserialize(f)
        strEncContent = VarStringSerializer.stream_deserialize(f)
        object.__setattr__(self, 'strEncContent', strEncContent)
        return self

    def stream_serialize(self, f):
        super(CSqueak, self).stream_serialize(f)
        assert len(self.strEncContent) <= MAX_SQUEAK_SIZE
        VarStringSerializer.stream_serialize(self.strEncContent, f)

    def get_header(self):
        """Return the squeak header
        Returned header is a new object.
        """
        return CSqueakHeader(
            nVersion=self.nVersion,
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


def SignSqueak(signing_key, squeak):
    """Generate a signature for the given squeak

    signing_key (CKey)
    squeak (Squeak)
    """
    return sign(squeak.GetHash(), signing_key)


def VerifySqueak(squeak, signature):
    """Return True iff the given signature is valid

    squeak (Squeak)
    signature (bytes)
    """
    verifying_key = deserialize_verifying_key(squeak.vchPubkey)
    return verify(squeak.GetHash(), signature, verifying_key)


def EncryptContent(data_key, iv, content):
    """Return the ciphertext from the given content.

    data_key (bytes)
    iv (bytes)
    squeak (Squeak)
    """
    return encrypt_content(data_key, iv, content)


def DecryptContent(squeak, decryption_key):
    """Return the decrypted content.

    squeak (Squeak)
    decryption_key (RSAPrivateKey)
    """
    data_key_cipher = squeak.vchEncDatakey
    data_key = decrypt_assymetric(data_key_cipher, decryption_key)
    iv = squeak.vchIv
    ciphertext = squeak.strEncContent
    return decrypt_content(data_key, iv, ciphertext)


def EncryptDataKey(encryption_key, data_key):
    """Return the ciphertext from the given content.

    encryption_key (RSAPublicKey)
    data_key (bytes)
    """
    return encrypt_assymetric(data_key, encryption_key)


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
    # TODO: implement
    pass


__all__ = (
    'MAX_SQUEAK_SIZE',
    'CSqueakHeader',
    'CSqueak',
    'SignSqueak',
    'VerifySqueak',
    'EncryptContent',
    'DecryptContent',
    'EncryptDataKey',
    'CheckSqueakHeader',
    'CheckSqueak',
)
