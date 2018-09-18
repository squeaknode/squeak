import struct

from bitcoin.core.serialize import BytesSerializer
from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2lx
from bitcoin.wallet import CBitcoinAddressError

from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import generate_nonce
from squeak.core.encryption import ENCRYPTION_PUB_KEY_LENGTH
from squeak.core.encryption import ENCRYPTED_DATA_KEY_LENGTH
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.script import CScript
from squeak.core.script import VerifyScript
from squeak.core.signing import CSqueakAddress


# Core definitions
CONTENT_LENGTH = 1120  # 280*4
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
    __slots__ = ['nVersion', 'hashEncContent', 'hashReplySqk', 'hashBlock', 'nBlockHeight', 'scriptPubKey', 'vchEncryptionKey', 'vchEncDatakey', 'vchIv', 'nTime', 'nNonce']

    def __init__(self, nVersion=SQUEAK_VERSION, hashEncContent=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, scriptPubKey=CScript(), vchEncryptionKey=b'\x00'*ENCRYPTION_PUB_KEY_LENGTH, vchEncDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, vchIv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashEncContent) == HASH_LENGTH
        object.__setattr__(self, 'hashEncContent', hashEncContent)
        assert len(hashReplySqk) == HASH_LENGTH
        object.__setattr__(self, 'hashReplySqk', hashReplySqk)
        assert len(hashBlock) == HASH_LENGTH
        object.__setattr__(self, 'hashBlock', hashBlock)
        object.__setattr__(self, 'nBlockHeight', nBlockHeight)
        object.__setattr__(self, 'scriptPubKey', scriptPubKey)
        assert len(vchEncryptionKey) == ENCRYPTION_PUB_KEY_LENGTH
        object.__setattr__(self, 'vchEncryptionKey', vchEncryptionKey)
        assert len(vchEncDatakey) == ENCRYPTED_DATA_KEY_LENGTH
        object.__setattr__(self, 'vchEncDatakey', vchEncDatakey)
        assert len(vchIv) == CIPHER_BLOCK_LENGTH
        object.__setattr__(self, 'vchIv', vchIv)
        object.__setattr__(self, 'nTime', nTime)
        object.__setattr__(self, 'nNonce', nNonce)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashEncContent = ser_read(f,HASH_LENGTH)
        hashReplySqk = ser_read(f,HASH_LENGTH)
        hashBlock = ser_read(f,HASH_LENGTH)
        nBlockHeight = struct.unpack(b"<i", ser_read(f,4))[0]
        scriptPubKey = CScript(BytesSerializer.stream_deserialize(f))
        vchEncryptionKey = ser_read(f,ENCRYPTION_PUB_KEY_LENGTH)
        vchEncDatakey = ser_read(f,ENCRYPTED_DATA_KEY_LENGTH)
        vchIv = ser_read(f,CIPHER_BLOCK_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(nVersion, hashEncContent, hashReplySqk, hashBlock, nBlockHeight, scriptPubKey, vchEncryptionKey, vchEncDatakey, vchIv, nTime, nNonce)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashEncContent) == HASH_LENGTH
        f.write(self.hashEncContent)
        assert len(self.hashReplySqk) == HASH_LENGTH
        f.write(self.hashReplySqk)
        assert len(self.hashBlock) == HASH_LENGTH
        f.write(self.hashBlock)
        f.write(struct.pack(b"<i", self.nBlockHeight))
        BytesSerializer.stream_serialize(self.scriptPubKey, f)
        assert len(self.vchEncryptionKey) == ENCRYPTION_PUB_KEY_LENGTH
        f.write(self.vchEncryptionKey)
        assert len(self.vchEncDatakey) == ENCRYPTED_DATA_KEY_LENGTH
        f.write(self.vchEncDatakey)
        assert len(self.vchIv) == CIPHER_BLOCK_LENGTH
        f.write(self.vchIv)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nNonce))

    @property
    def is_reply(self):
        """Return True if the squeak is a reply to another squeak."""
        return not self.hashReplySqk == b'\x00'*HASH_LENGTH

    def GetAddress(self):
        """Return the squeak author adress."""
        return CSqueakAddress.from_scriptPubKey(self.scriptPubKey)

    def __repr__(self):
        return "%s(%i, lx(%s), lx(%s), lx(%s), %s, %r, lx(%s), lx(%s), lx(%s), %s, 0x%08x)" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.hashEncContent), b2lx(self.hashReplySqk),
             b2lx(self.hashBlock), self.nBlockHeight, self.scriptPubKey, b2lx(self.vchEncryptionKey),
             b2lx(self.vchEncDatakey), b2lx(self.vchIv), self.nTime, self.nNonce)


class CSqueak(CSqueakHeader):
    """A squeak including the encrypted content in it"""
    __slots__ = ['encContent']

    def __init__(self, nVersion=1, hashEncContent=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, scriptPubKey=CScript(), vchEncryptionKey=b'\x00'*ENCRYPTION_PUB_KEY_LENGTH, vchEncDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, vchIv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0, encContent=None):
        """Create a new squeak"""
        super(CSqueak, self).__init__(nVersion, hashEncContent, hashReplySqk, hashBlock, nBlockHeight, scriptPubKey, vchEncryptionKey, vchEncDatakey, vchIv, nTime, nNonce)
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
            hashReplySqk=self.hashReplySqk,
            hashBlock=self.hashBlock,
            nBlockHeight=self.nBlockHeight,
            scriptPubKey=self.scriptPubKey,
            vchEncryptionKey=self.vchEncryptionKey,
            vchEncDatakey=self.vchEncDatakey,
            vchIv=self.vchIv,
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
    """Squeak encrypted content"""
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


class VerifySqueakSignatureError(ValidationError):
    pass


def SignSqueak(signing_key, squeak_header):
    """Generate a signature script for the given squeak header

    signing_key (CSigningKey)
    squeak_header (CSqueakHeader)
    """
    return signing_key.sign_to_scriptSig(squeak_header.GetHash())


def VerifySqueakSignature(squeak_header, sig_script):
    """Check if the given signature script is valid

    squeak_header (CSqueakHeader)
    sig_script (CScript)
    """
    hash = squeak_header.GetHash()
    pubkey_script = squeak_header.scriptPubKey
    if not VerifyScript(sig_script, pubkey_script, hash):
        raise VerifySqueakSignatureError("VerifySqueakSignature() : invalid signature for the given squeak header")


class InvalidContentLengthError(ValidationError):
    pass


def EncryptContent(data_key, iv, content):
    """Return the ciphertext from the given content.

    data_key (bytes)
    iv (bytes)
    content (bytes)
    """
    if not len(content) == CONTENT_LENGTH:
        raise InvalidContentLengthError("EncryptContent : content length must be %i; got %i" %
                                        (CONTENT_LENGTH, len(content)))
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

    # Pubkey script check
    try:
        squeak_header.GetAddress()
    except CBitcoinAddressError:
        raise CheckSqueakHeaderError("CheckSqueakError() : scriptPubKey does not convert to a valid address")


def CheckSqueak(squeak):
    """Context independent CSqueak checks.

    CheckSqueakHeader() is called first, which may raise a CheckSqueakHeader
    exception, followed by the squeak tests.
    """

    # Squeak header checks
    CheckSqueakHeader(squeak)

    # Content length check
    if not len(squeak.encContent.vchEncContent) == ENC_CONTENT_LENGTH:
        raise CheckSqueakError("CheckSqueak() : encContent length does not match the required length")

    # Content hash check
    hash_enc_content = squeak.encContent.GetHash()
    if not hash_enc_content == squeak.hashEncContent:
        raise CheckSqueakError("CheckSqueak() : hashEncContent does not match hash of encContent")


def MakeSqueak(signing_key, content, block_height, block_hash, timestamp, reply_to=b'\x00'*HASH_LENGTH):
    """Create a new squeak.

    signing_key (CSigningkey)
    content (bytes)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    reply_to (bytes)
    """
    data_key = generate_data_key()
    initialization_vector = generate_initialization_vector()
    enc_content = EncryptContent(data_key, initialization_vector, content)
    decryption_key = CDecryptionKey.generate()
    encryption_key = decryption_key.get_encryption_key()
    data_key_cipher = EncryptDataKey(encryption_key, data_key)
    nonce = generate_nonce()
    verifying_key = signing_key.get_verifying_key()
    squeak_address = CSqueakAddress.from_verifying_key(verifying_key)
    pubkey_script = squeak_address.to_scriptPubKey()
    squeak = CSqueak(
        hashEncContent=enc_content.GetHash(),
        hashReplySqk=reply_to,
        hashBlock=block_hash,
        nBlockHeight=block_height,
        scriptPubKey=pubkey_script,
        vchEncryptionKey=encryption_key.serialize(),
        vchEncDatakey=data_key_cipher,
        vchIv=initialization_vector,
        nTime=timestamp,
        nNonce=nonce,
        encContent=enc_content,
    )
    sig_script = SignSqueak(signing_key, squeak)
    return squeak, decryption_key, sig_script


__all__ = (
    'ENC_CONTENT_LENGTH',
    'CSqueakHeader',
    'CSqueak',
    'SignSqueak',
    'VerifySqueakSignature',
    'EncryptContent',
    'DecryptContent',
    'EncryptDataKey',
    'CheckSqueakHeader',
    'CheckSqueak',
    'MakeSqueak',
)
