import struct

from bitcoin.core import b2lx
from bitcoin.core.serialize import BytesSerializer
from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.core.serialize import ser_read
from bitcoin.core.serialize import SerializationTruncationError

from squeak.core.encryption import CDecryptionKey
from squeak.core.encryption import CEncryptionKey
from squeak.core.encryption import ENCRYPTED_DATA_KEY_LENGTH
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector
from squeak.core.encryption import generate_nonce
from squeak.core.hashing import sha256
from squeak.core.script import CScript
from squeak.core.script import EvalScriptError
from squeak.core.script import MakeSigScript
from squeak.core.script import VerifyScript
from squeak.core.script import VerifyScriptError
from squeak.core.signing import CSqueakAddress
from squeak.core.signing import CSqueakAddressError


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
    __slots__ = ['nVersion', 'hashEncContent', 'hashReplySqk', 'hashBlock', 'nBlockHeight', 'vchScriptPubKey', 'vchEncryptionKey', 'encDatakey', 'iv', 'nTime', 'nNonce']

    def __init__(self, nVersion=SQUEAK_VERSION, hashEncContent=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, vchScriptPubKey=b'', vchEncryptionKey=b'', encDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, iv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashEncContent) == HASH_LENGTH
        object.__setattr__(self, 'hashEncContent', hashEncContent)
        assert len(hashReplySqk) == HASH_LENGTH
        object.__setattr__(self, 'hashReplySqk', hashReplySqk)
        assert len(hashBlock) == HASH_LENGTH
        object.__setattr__(self, 'hashBlock', hashBlock)
        object.__setattr__(self, 'nBlockHeight', nBlockHeight)
        object.__setattr__(self, 'vchScriptPubKey', vchScriptPubKey)
        object.__setattr__(self, 'vchEncryptionKey', vchEncryptionKey)
        assert len(encDatakey) == ENCRYPTED_DATA_KEY_LENGTH
        object.__setattr__(self, 'encDatakey', encDatakey)
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
        vchScriptPubKey = BytesSerializer.stream_deserialize(f)
        vchEncryptionKey = BytesSerializer.stream_deserialize(f)
        encDatakey = ser_read(f,ENCRYPTED_DATA_KEY_LENGTH)
        iv = ser_read(f,CIPHER_BLOCK_LENGTH)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(
            nVersion=nVersion,
            hashEncContent=hashEncContent,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            vchScriptPubKey=vchScriptPubKey,
            vchEncryptionKey=vchEncryptionKey,
            encDatakey=encDatakey,
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
        BytesSerializer.stream_serialize(self.vchScriptPubKey, f)
        BytesSerializer.stream_serialize(self.vchEncryptionKey, f)
        assert len(self.encDatakey) == ENCRYPTED_DATA_KEY_LENGTH
        f.write(self.encDatakey)
        assert len(self.iv) == CIPHER_BLOCK_LENGTH
        f.write(self.iv)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nNonce))

    @property
    def is_reply(self):
        """Return True if the squeak is a reply to another squeak."""
        return not self.hashReplySqk == b'\x00'*HASH_LENGTH

    def GetAddress(self):
        """Return the squeak author address."""
        script_pubkey = self.GetScriptPubkey()
        return CSqueakAddress.from_scriptPubKey(script_pubkey)

    def GetScriptPubkey(self):
        """Return the pubkey script."""
        return CScript(self.vchScriptPubKey)

    def SetScriptPubkeyBytes(self, vchScriptPubKey):
        """Set the pubkey script bytes."""
        self.vchScriptPubKey = vchScriptPubKey

    def __repr__(self):
        return "%s(nVersion: %i, hashEncContent: lx(%s), hashReplySqk: lx(%s), hashBlock: lx(%s), nBlockHeight: %s, vchScriptPubKey: %r, vchEncryptionKey: b2lx(%s), encDatakey: b2lx(%s), iv: lx(%s), nTime: %s, nNonce: 0x%08x)" % \
            (self.__class__.__name__, self.nVersion, b2lx(self.hashEncContent), b2lx(self.hashReplySqk),
             b2lx(self.hashBlock), self.nBlockHeight, self.vchScriptPubKey, b2lx(self.vchEncryptionKey), b2lx(self.encDatakey), b2lx(self.iv), self.nTime, self.nNonce)


class CSqueak(CSqueakHeader):
    """A squeak including the encrypted content in it"""
    __slots__ = ['encContent', 'vchScriptSig', 'vchDecryptionKey']

    def __init__(self, nVersion=1, hashEncContent=b'\x00'*HASH_LENGTH, hashReplySqk=b'\x00'*HASH_LENGTH, hashBlock=b'\x00'*HASH_LENGTH, nBlockHeight=-1, vchScriptPubKey=b'', vchEncryptionKey=b'', encDatakey=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH, iv=b'\x00'*CIPHER_BLOCK_LENGTH, nTime=0, nNonce=0, encContent=b'\x00'*ENC_CONTENT_LENGTH, vchScriptSig=b'', vchDecryptionKey=b''):
        """Create a new squeak"""
        super(CSqueak, self).__init__(
            nVersion=nVersion,
            hashEncContent=hashEncContent,
            hashReplySqk=hashReplySqk,
            hashBlock=hashBlock,
            nBlockHeight=nBlockHeight,
            vchScriptPubKey=vchScriptPubKey,
            vchEncryptionKey=vchEncryptionKey,
            encDatakey=encDatakey,
            iv=iv,
            nTime=nTime,
            nNonce=nNonce,
        )
        object.__setattr__(self, 'encContent', encContent)
        object.__setattr__(self, 'vchScriptSig', vchScriptSig)
        object.__setattr__(self, 'vchDecryptionKey', vchDecryptionKey)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CSqueak, cls).stream_deserialize(f)
        encContent = ser_read(f,ENC_CONTENT_LENGTH)
        object.__setattr__(self, 'encContent', encContent)
        vchScriptSig = CScript(BytesSerializer.stream_deserialize(f))
        object.__setattr__(self, 'vchScriptSig', vchScriptSig)
        vchDecryptionKey = BytesSerializer.stream_deserialize(f)
        object.__setattr__(self, 'vchDecryptionKey', vchDecryptionKey)
        return self

    def stream_serialize(self, f):
        super(CSqueak, self).stream_serialize(f)
        assert len(self.encContent) == ENC_CONTENT_LENGTH
        f.write(self.encContent)
        BytesSerializer.stream_serialize(self.vchScriptSig, f)
        BytesSerializer.stream_serialize(self.vchDecryptionKey, f)

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
            vchScriptPubKey=self.vchScriptPubKey,
            vchEncryptionKey=self.vchEncryptionKey,
            encDatakey=self.encDatakey,
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

    def GetScriptSig(self):
        """Return the signature script."""
        return CScript(self.vchScriptSig)

    def SetScriptSigBytes(self, vchScriptSig):
        """Set the signature script bytes."""
        object.__setattr__(self, 'vchScriptSig', vchScriptSig)

    def SetDecryptionKey(self, decryption_key):
        """Set the decryption key.
        """
        object.__setattr__(self, 'vchDecryptionKey', decryption_key)

    def ClearDecryptionKey(self):
        """Set the decryption key.
        """
        self.SetDecryptionKey(b'')

    def GetDecryptionKey(self):
        """Return the squeak decryption key."""
        if not self.HasDecryptionKey():
            return None
        return CDecryptionKey.from_bytes(self.vchDecryptionKey)

    def HasDecryptionKey(self):
        """Return true if the decryption key is set."""
        return len(self.vchDecryptionKey) > 0

    def GetEncryptionKey(self):
        """Return the squeak encryption key."""
        if not self.vchEncryptionKey:
            return None
        return CEncryptionKey.from_bytes(self.vchEncryptionKey)

    def GetDecryptedContent(self):
        """Return the decrypted content."""
        decryption_key = self.GetDecryptionKey()
        data_key_cipher = self.encDatakey
        data_key = decryption_key.decrypt(data_key_cipher)
        iv = self.iv
        ciphertext = self.encContent
        return decrypt_content(data_key, iv, ciphertext)

    def GetDecryptedContentStr(self):
        """Return the decrypted content."""
        content = self.GetDecryptedContent()
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


class CheckSqueakDecryptionKeyError(CheckSqueakError):
    pass


def SignSqueak(signing_key, squeak_header):
    """Generate a signature script for the given squeak header

    signing_key (CSigningKey)
    squeak_header (CSqueakHeader)
    """
    squeak_hash = squeak_header.GetHash()
    signature = signing_key.sign(squeak_hash)
    verifying_key = signing_key.get_verifying_key()
    return MakeSigScript(signature, verifying_key)


def CheckSqueakSignature(squeak):
    """Check if the given squeak has a valid signature

    squeak (CSqueak)
    """
    sig_script = squeak.GetScriptSig()
    squeak_hash = squeak.GetHash()
    pubkey_script = squeak.GetScriptPubkey()
    try:
        VerifyScript(sig_script, pubkey_script, squeak_hash)
    except (VerifyScriptError, EvalScriptError):
        raise CheckSqueakSignatureError("CheckSqueakSignature() : invalid signature for the given squeak")


def CheckSqueakDecryptionKey(squeak):
    """Check if the given squeak has a valid decryption key

    squeak (CSqueak)
    """
    try:
        decryption_key = squeak.GetDecryptionKey()
        encryption_key = squeak.GetEncryptionKey()
    except SerializationTruncationError:
        raise CheckSqueakDecryptionKeyError("CheckSqueakDecryptionKey() : invalid decryption key for the given squeak")

    if decryption_key is None:
        raise CheckSqueakDecryptionKeyError("CheckSqueakDecryptionKey() : invalid decryption key for the given squeak")

    expected_proof = generate_data_key()
    challenge = encryption_key.encrypt(expected_proof)
    try:
        proof = decryption_key.decrypt(challenge)
    except ValueError:
        raise CheckSqueakDecryptionKeyError("CheckSqueakDecryptionKey() : invalid decryption key for the given squeak")
    if not proof == expected_proof:
        raise CheckSqueakDecryptionKeyError("CheckSqueakDecryptionKey() : invalid decryption key for the given squeak")


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
    return encrypt_content(data_key, iv, content)


def HashEncryptedContent(enc_content):
    """Return the hash of the encrypted content.

    enc_content (bytes)
    """
    squeak_enc_content = CSqueakEncContent(enc_content)
    return squeak_enc_content.GetHash()


def EncryptDataKey(encryption_key, data_key):
    """Return the ciphertext from the given content.
    encryption_key (CEncryptionKey)
    data_key (bytes)
    """
    return encryption_key.encrypt(data_key)


def HashDataKey(data_key):
    """Return the hash of the data key.

    data_key (bytes)
    """
    return sha256(data_key)


def CheckSqueakHeader(squeak_header):
    """Context independent CSqueakHeader checks.
    Raises CSqueakHeaderError if squeak header is invalid.
    """

    # Pubkey script check
    try:
        squeak_header.GetAddress()
    except CSqueakAddressError:
        raise CheckSqueakHeaderError("CheckSqueakError() : vchScriptPubKey does not convert to a valid address")


def CheckSqueak(squeak, skipDecryptionCheck=False):
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

    # Sig Script check
    CheckSqueakSignature(squeak)

    # Decryption key check
    if not skipDecryptionCheck:
        CheckSqueakDecryptionKey(squeak)


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
    hash_enc_content = HashEncryptedContent(enc_content)
    decryption_key = CDecryptionKey.generate()
    encryption_key = decryption_key.get_encryption_key()
    data_key_cipher = EncryptDataKey(encryption_key, data_key)
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
        vchEncryptionKey=encryption_key.get_bytes(),
        encDatakey=data_key_cipher,
        iv=initialization_vector,
        nTime=timestamp,
        nNonce=nonce,
        encContent=enc_content,
        vchDecryptionKey=decryption_key.get_bytes(),
    )
    sig_script = SignSqueak(signing_key, squeak)
    squeak.SetScriptSigBytes(bytes(sig_script))
    return squeak


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


def MakeSqueakFromStr(signing_key, content_str, block_height, block_hash, timestamp, reply_to=b'\x00'*HASH_LENGTH):
    """Create a new squeak from a string of content.

    signing_key (CSigningkey)
    content_str (str)
    block_height (int)
    block_hash (bytes)
    timestamp (int)
    reply_to (bytes)
    """
    content = EncodeContent(content_str)
    return MakeSqueak(
        signing_key,
        content,
        block_height,
        block_hash,
        timestamp,
        reply_to,
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
