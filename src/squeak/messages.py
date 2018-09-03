import time
import struct
import hashlib
import random

from io import BytesIO as _BytesIO

from bitcoin.messages import MsgSerializable as BitcoinMsgSerializable
from bitcoin.messages import msg_version as bitcoin_msg_version
from bitcoin.messages import msg_verack as bitcoin_msg_verack
from bitcoin.messages import msg_addr as bitcoin_msg_addr
from bitcoin.messages import msg_getaddr as bitcoin_msg_getaddr
from bitcoin.messages import msg_ping as bitcoin_msg_ping
from bitcoin.messages import msg_pong as bitcoin_msg_pong
from bitcoin.net import CAddress
from bitcoin.core.serialize import VectorSerializer
from bitcoin.core.serialize import VarStringSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2x
from bitcoin.core import b2lx

import squeak
from squeak.core import CSqueak
from squeak.core import CSqueakHeader
from squeak.core import HASH_LENGTH
from squeak.core.encryption import ENCRYPTED_DATA_KEY_LENGTH
from squeak.core.encryption import DATA_KEY_LENGTH
from squeak.core.signing import SIGNATURE_LENGTH
from squeak.net import CInv
from squeak.net import CSqueakLocator
from squeak.net import PROTO_VERSION


USER_AGENT = (b'/python-squeak:' +
              squeak.__version__.encode('ascii') + b'/')


class MsgSerializable(object):

    def to_bytes(self):
        f = _BytesIO()
        self.msg_ser(f)
        body = f.getvalue()
        res = squeak.params.MESSAGE_START
        res += self.command
        res += b"\x00" * (12 - len(self.command))
        res += struct.pack(b"<I", len(body))

        # add checksum
        th = hashlib.sha256(body).digest()
        h = hashlib.sha256(th).digest()
        res += h[:4]

        res += body
        return res

    @classmethod
    def from_bytes(cls, b, protover=PROTO_VERSION):
        f = _BytesIO(b)
        return MsgSerializable.stream_deserialize(f, protover=protover)

    @classmethod
    def stream_deserialize(cls, f, protover=PROTO_VERSION):
        recvbuf = ser_read(f, 4 + 12 + 4 + 4)

        # check magic
        if recvbuf[:4] != squeak.params.MESSAGE_START:
            raise ValueError("Invalid message start '%s', expected '%s'" %
                             (b2x(recvbuf[:4]), b2x(squeak.params.MESSAGE_START)))

        # remaining header fields: command, msg length, checksum
        command = recvbuf[4:4+12].split(b"\x00", 1)[0]
        msglen = struct.unpack(b"<i", recvbuf[4+12:4+12+4])[0]
        checksum = recvbuf[4+12+4:4+12+4+4]

        # read message body
        recvbuf += ser_read(f, msglen)

        msg = recvbuf[4+12+4+4:4+12+4+4+msglen]
        th = hashlib.sha256(msg).digest()
        h = hashlib.sha256(th).digest()
        if checksum != h[:4]:
            raise ValueError("got bad checksum %s" % repr(recvbuf))
            recvbuf = recvbuf[4+12+4+4+msglen:]

        if command in messagemap:
            cls = messagemap[command]
            return cls.msg_deser(_BytesIO(msg))
        else:
            print("Command '%s' not in messagemap" % repr(command))
            return None


class msg_version(MsgSerializable, bitcoin_msg_version):

    def __init__(
            self,
            nServices=1,
            nTime=None,
            addrTo=None,
            addrFrom=None,
            nNonce=None,
            strSubVer=USER_AGENT,
            nStartingHeight=-1,
            fRelay=True,
            protover=PROTO_VERSION,
    ):
        super(msg_version, self).__init__(protover)
        self.nVersion = protover
        self.nServices = nServices
        self.nTime = nTime or int(time.time())
        self.addrTo = addrTo or CAddress(PROTO_VERSION)
        self.addrFrom = addrFrom or CAddress(PROTO_VERSION)
        self.nNonce = nNonce or random.SystemRandom().getrandbits(64)
        self.strSubVer = strSubVer
        self.nStartingHeight = nStartingHeight
        self.fRelay = fRelay


class msg_verack(MsgSerializable, bitcoin_msg_verack):
    pass


class msg_addr(MsgSerializable, bitcoin_msg_addr):

    def __init__(self, addrs=None, protover=PROTO_VERSION):
        super(msg_addr, self).__init__(protover)
        self.addrs = addrs or []


class msg_inv(MsgSerializable, BitcoinMsgSerializable):
    command = b"inv"

    def __init__(self, inv=None, protover=PROTO_VERSION):
        super(msg_inv, self).__init__(protover)
        self.inv = inv or []

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.inv = VectorSerializer.stream_deserialize(CInv, f)
        return c

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CInv, self.inv, f)

    def __repr__(self):
        return "msg_inv(inv=%s)" % (repr(self.inv))


class msg_getdata(MsgSerializable, BitcoinMsgSerializable):
    command = b"getdata"

    def __init__(self, inv=None, protover=PROTO_VERSION):
        super(msg_getdata, self).__init__(protover)
        self.inv = inv or []

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.inv = VectorSerializer.stream_deserialize(CInv, f)
        return c

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CInv, self.inv, f)

    def __repr__(self):
        return "msg_getdata(inv=%s)" % (repr(self.inv))


class msg_notfound(MsgSerializable, BitcoinMsgSerializable):
    command = b"notfound"

    def __init__(self, inv=None, protover=PROTO_VERSION):
        super(msg_notfound, self).__init__(protover)
        self.inv = inv or []

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.inv = VectorSerializer.stream_deserialize(CInv, f)
        return c

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CInv, self.inv, f)

    def __repr__(self):
        return "msg_notfound(inv=%s)" % (repr(self.inv))


class msg_getheaders(MsgSerializable, BitcoinMsgSerializable):
    command = b"getheaders"

    def __init__(self, locator=None, protover=PROTO_VERSION):
        super(msg_getheaders, self).__init__(protover)
        self.locator = locator or CSqueakLocator()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.locator = CSqueakLocator.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        self.locator.stream_serialize(f)

    def __repr__(self):
        return "msg_getheaders(locator=%s)" % (repr(self.locator))


class msg_getsqueaks(MsgSerializable, BitcoinMsgSerializable):
    command = b"getsqueaks"

    def __init__(self, locator=None, protover=PROTO_VERSION):
        super(msg_getsqueaks, self).__init__(protover)
        self.locator = locator or CSqueakLocator()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.locator = CSqueakLocator.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        self.locator.stream_serialize(f)

    def __repr__(self):
        return "msg_getsqueaks(locator=%s)" % (repr(self.locator))


class msg_headers(MsgSerializable, BitcoinMsgSerializable):
    command = b"headers"

    def __init__(self, headers=None, protover=PROTO_VERSION):
        super(msg_headers, self).__init__(protover)
        self.headers = headers or []

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.headers = VectorSerializer.stream_deserialize(CSqueakHeader, f)
        return c

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CSqueakHeader, self.headers, f)

    def __repr__(self):
        return "msg_headers(headers=%s)" % (repr(self.headers))


class msg_getaddr(MsgSerializable, bitcoin_msg_getaddr):
    pass


class msg_ping(MsgSerializable, bitcoin_msg_ping):
    pass


class msg_pong(MsgSerializable, bitcoin_msg_pong):
    pass


class msg_getoffer(MsgSerializable, BitcoinMsgSerializable):
    command = b"getoffer"

    def __init__(
            self,
            squeak_hash=b'\x00'*HASH_LENGTH,
            challenge=b'\x00'*ENCRYPTED_DATA_KEY_LENGTH,
            protover=PROTO_VERSION,
    ):
        super(msg_getoffer, self).__init__(protover)
        self.squeak_hash = squeak_hash
        self.challenge = challenge

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak_hash = ser_read(f, HASH_LENGTH)
        c.challenge = ser_read(f, ENCRYPTED_DATA_KEY_LENGTH)
        return c

    def msg_ser(self, f):
        assert len(self.squeak_hash) == HASH_LENGTH
        f.write(self.squeak_hash)
        assert len(self.challenge) == ENCRYPTED_DATA_KEY_LENGTH
        f.write(self.challenge)

    def __repr__(self):
        return "msg_getoffer(squeakhash=lx(%s) challenge=lx(%s))" % \
            (b2lx(self.squeak_hash), b2lx(self.challenge))


class msg_offer(MsgSerializable, BitcoinMsgSerializable):
    command = b"offer"

    def __init__(
            self,
            squeak=None,
            proof=b'\x00'*DATA_KEY_LENGTH,
            signature=b'\x00'*SIGNATURE_LENGTH,
            price=0,
            protover=PROTO_VERSION,
    ):
        super(msg_offer, self).__init__(protover)
        self.squeak = squeak or CSqueak()
        self.proof = proof
        self.signature = signature
        self.price = price

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak = CSqueak.stream_deserialize(f)
        c.proof = ser_read(f, DATA_KEY_LENGTH)
        c.signature = ser_read(f, SIGNATURE_LENGTH)
        c.price = struct.unpack(b"<I", ser_read(f, 4))[0]
        return c

    def msg_ser(self, f):
        self.squeak.stream_serialize(f)
        assert len(self.proof) == DATA_KEY_LENGTH
        f.write(self.proof)
        assert len(self.signature) == SIGNATURE_LENGTH
        f.write(self.signature)
        f.write(struct.pack(b"<I", self.price))

    def __repr__(self):
        return "msg_offer(squeak=%s signature=lx(%s) proof=lx(%s) price=%i)" % \
            (repr(self.squeak), b2lx(self.signature), b2lx(self.proof), self.price)


class msg_acceptoffer(MsgSerializable, BitcoinMsgSerializable):
    command = b"acceptoffer"

    def __init__(
            self,
            squeak_hash=b'\x00'*HASH_LENGTH,
            protover=PROTO_VERSION,
    ):
        super(msg_acceptoffer, self).__init__(protover)
        self.squeak_hash = squeak_hash

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak_hash = ser_read(f, HASH_LENGTH)
        return c

    def msg_ser(self, f):
        assert len(self.squeak_hash) == HASH_LENGTH
        f.write(self.squeak_hash)

    def __repr__(self):
        return "msg_acceptoffer(squeakhash=lx(%s))" % \
            (b2lx(self.squeak_hash))


class msg_invoice(MsgSerializable, BitcoinMsgSerializable):
    command = b"invoice"

    def __init__(
            self,
            squeak_hash=b'\x00'*HASH_LENGTH,
            payment_info=b'',
            protover=PROTO_VERSION,
    ):
        super(msg_invoice, self).__init__(protover)
        self.squeak_hash = squeak_hash
        self.payment_info = payment_info

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak_hash = ser_read(f, HASH_LENGTH)
        c.payment_info = VarStringSerializer.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        assert len(self.squeak_hash) == HASH_LENGTH
        f.write(self.squeak_hash)
        VarStringSerializer.stream_serialize(self.payment_info, f)

    def __repr__(self):
        return "msg_invoice(squeakhash=lx(%s) payment_info=%s)" % \
            (b2lx(self.squeak_hash), self.payment_info)


class msg_fulfill(MsgSerializable, BitcoinMsgSerializable):
    command = b"fulfill"

    def __init__(
            self,
            squeak_hash=b'\x00'*HASH_LENGTH,
            decryption_key=b'',
            protover=PROTO_VERSION,
    ):
        super(msg_fulfill, self).__init__(protover)
        self.squeak_hash = squeak_hash
        self.decryption_key = decryption_key

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak_hash = ser_read(f, HASH_LENGTH)
        c.decryption_key = VarStringSerializer.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        assert len(self.squeak_hash) == HASH_LENGTH
        f.write(self.squeak_hash)
        VarStringSerializer.stream_serialize(self.decryption_key, f)

    def __repr__(self):
        return "msg_fulfill(squeakhash=lx(%s) decryption_key=lx(%s))" % \
            (b2lx(self.squeak_hash), b2lx(self.decryption_key))


msg_classes = [msg_version, msg_verack, msg_addr, msg_inv, msg_getdata,
               msg_notfound, msg_getsqueaks, msg_getheaders, msg_headers,
               msg_getaddr, msg_ping, msg_pong, msg_getoffer, msg_offer,
               msg_acceptoffer, msg_invoice, msg_fulfill]

messagemap = {}
for cls in msg_classes:
    messagemap[cls.command] = cls
