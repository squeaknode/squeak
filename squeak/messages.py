import hashlib
import random
import struct
import time
from io import BytesIO as _BytesIO

import bitcoin  # noqa: F401
from bitcoin.core import b2x
from bitcoin.core.serialize import ser_read
from bitcoin.core.serialize import VarStringSerializer
from bitcoin.core.serialize import VectorSerializer
from bitcoin.messages import msg_addr as bitcoin_msg_addr
from bitcoin.messages import msg_alert as bitcoin_msg_alert
from bitcoin.messages import msg_getaddr as bitcoin_msg_getaddr
from bitcoin.messages import msg_ping as bitcoin_msg_ping
from bitcoin.messages import msg_pong as bitcoin_msg_pong
from bitcoin.messages import msg_verack as bitcoin_msg_verack
from bitcoin.messages import msg_version as bitcoin_msg_version
from bitcoin.messages import MsgSerializable as BitcoinMsgSerializable
from bitcoin.net import CAddress

import squeak
import squeak.params
from squeak.core import CSqueak
from squeak.net import CInv
from squeak.net import CSqueakLocator
from squeak.net import PROTO_VERSION
from squeak.core import HASH_LENGTH


USER_AGENT = b'/python-squeak:' + \
             squeak.__version__.encode('ascii') + b'/'


class MsgSerializable(object):

    def to_bytes(self):
        f = _BytesIO()
        self.msg_ser(f)
        body = f.getvalue()
        res = squeak.params.params.MESSAGE_START
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
        if recvbuf[:4] != squeak.params.params.MESSAGE_START:
            raise ValueError("Invalid message start '%s', expected '%s'" %
                             (b2x(recvbuf[:4]), b2x(squeak.params.params.MESSAGE_START)))

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
        inv = VectorSerializer.stream_deserialize(CInv, f)
        return cls(inv)

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
        inv = VectorSerializer.stream_deserialize(CInv, f)
        return cls(inv)

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
        inv = VectorSerializer.stream_deserialize(CInv, f)
        return cls(inv)

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CInv, self.inv, f)

    def __repr__(self):
        return "msg_notfound(inv=%s)" % (repr(self.inv))


class msg_getsqueaks(MsgSerializable, BitcoinMsgSerializable):
    command = b"getsqueaks"

    def __init__(self, locator=None, protover=PROTO_VERSION):
        super(msg_getsqueaks, self).__init__(protover)
        self.locator = locator or CSqueakLocator()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        locator = CSqueakLocator.stream_deserialize(f)
        return cls(locator)

    def msg_ser(self, f):
        self.locator.stream_serialize(f)

    def __repr__(self):
        return "msg_getsqueaks(locator=%s)" % (repr(self.locator))


class msg_subscribe(MsgSerializable, BitcoinMsgSerializable):
    command = b"subscribe"

    def __init__(self, locator=None, protover=PROTO_VERSION):
        super(msg_subscribe, self).__init__(protover)
        self.locator = locator or CSqueakLocator()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        locator = CSqueakLocator.stream_deserialize(f)
        return cls(locator)

    def msg_ser(self, f):
        self.locator.stream_serialize(f)

    def __repr__(self):
        return "msg_subscribe(locator=%s)" % (repr(self.locator))


class msg_squeak(MsgSerializable, BitcoinMsgSerializable):
    command = b"squeak"

    def __init__(self, squeak=None, protover=PROTO_VERSION):
        super(msg_squeak, self).__init__(protover)
        self.squeak = squeak or CSqueak()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        squeak = CSqueak.stream_deserialize(f)
        return cls(squeak)

    def msg_ser(self, f):
        self.squeak.stream_serialize(f)

    def __repr__(self):
        return "msg_squeak(squeak=%s)" % (repr(self.squeak))


class msg_getaddr(MsgSerializable, bitcoin_msg_getaddr):
    pass


class msg_ping(MsgSerializable, bitcoin_msg_ping):
    pass


class msg_pong(MsgSerializable, bitcoin_msg_pong):
    pass


class msg_alert(MsgSerializable, bitcoin_msg_alert):
    pass


class msg_offer(MsgSerializable, BitcoinMsgSerializable):
    command = b"offer"

    def __init__(
            self,
            hashSqk=b'\x00'*HASH_LENGTH,
            nonce=b'\x00'*HASH_LENGTH,
            strPaymentInfo=b'',
            host=b'',
            port=0,
            protover=PROTO_VERSION,
    ):
        super(msg_offer, self).__init__(protover)
        self.hashSqk = hashSqk
        self.nonce = nonce
        self.strPaymentInfo = strPaymentInfo
        self.host = host
        self.port = port

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        hashSqk = ser_read(f, HASH_LENGTH)
        nonce = ser_read(f, HASH_LENGTH)
        strPaymentInfo = VarStringSerializer.stream_deserialize(f)
        host = VarStringSerializer.stream_deserialize(f)
        port = struct.unpack(b"<i", ser_read(f, 4))[0]
        return cls(hashSqk, nonce, strPaymentInfo, host, port)

    def msg_ser(self, f):
        assert len(self.hashSqk) == HASH_LENGTH
        f.write(self.hashSqk)
        assert len(self.nonce) == HASH_LENGTH
        f.write(self.nonce)
        VarStringSerializer.stream_serialize(self.strPaymentInfo, f)
        VarStringSerializer.stream_serialize(self.host, f)
        f.write(struct.pack(b"<i", self.port))

    def __repr__(self):
        return "msg_offer(hashSqk=%s nonce=%s strPaymentInfo=%s host=%s port=%i)" % \
            (self.hashSqk, self.nonce, self.strPaymentInfo, self.host, self.port)


msg_classes = [msg_version, msg_verack, msg_addr, msg_inv, msg_getdata,
               msg_notfound, msg_getsqueaks, msg_subscribe,
               msg_squeak, msg_getaddr, msg_ping, msg_pong, msg_alert,
               msg_offer]

messagemap = {}
for cls in msg_classes:
    messagemap[cls.command] = cls
