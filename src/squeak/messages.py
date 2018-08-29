import struct
import hashlib

from io import BytesIO as _BytesIO

import bitcoin
from bitcoin.messages import MsgSerializable as BitcoinMsgSerializable
from bitcoin.messages import msg_version as bitcoin_msg_version
from bitcoin.messages import msg_verack as bitcoin_msg_verack
from bitcoin.messages import msg_addr as bitcoin_msg_addr
from bitcoin.messages import msg_alert as bitcoin_msg_alert
from bitcoin.messages import msg_getdata as bitcoin_msg_getdata
from bitcoin.messages import msg_notfound as bitcoin_msg_notfound
from bitcoin.messages import msg_getaddr as bitcoin_msg_getaddr
from bitcoin.messages import msg_ping as bitcoin_msg_ping
from bitcoin.messages import msg_pong as bitcoin_msg_pong
from bitcoin.messages import msg_reject as bitcoin_msg_reject
from bitcoin.core.serialize import VectorSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2x
from bitcoin.net import PROTO_VERSION

import squeak
from squeak.core import CSqueakHeader
from squeak.net import CInv
from squeak.net import CSqueakLocator


USER_AGENT = (b'/python-squeak:' +
              squeak.__version__.encode('ascii') + b'/')


class MsgSerializable(object):

    @classmethod
    def from_bytes(cls, b, protover=PROTO_VERSION):
        f = _BytesIO(b)
        return MsgSerializable.stream_deserialize(f, protover=protover)

    @classmethod
    def stream_deserialize(cls, f, protover=PROTO_VERSION):
        recvbuf = ser_read(f, 4 + 12 + 4 + 4)

        # check magic
        if recvbuf[:4] != bitcoin.params.MESSAGE_START:
            raise ValueError("Invalid message start '%s', expected '%s'" %
                             (b2x(recvbuf[:4]), b2x(bitcoin.params.MESSAGE_START)))

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

    def __init__(self, protover=PROTO_VERSION, user_agent=USER_AGENT):
        super(msg_version, self).__init__(protover=protover)
        self.strSubVer = user_agent


class msg_verack(MsgSerializable, bitcoin_msg_verack):
    pass


class msg_addr(MsgSerializable, bitcoin_msg_addr):
    pass


class msg_alert(MsgSerializable, bitcoin_msg_alert):
    pass


class msg_inv(MsgSerializable, BitcoinMsgSerializable):
    command = b"inv"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_inv, self).__init__(protover)
        self.inv = []

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.inv = VectorSerializer.stream_deserialize(CInv, f)
        return c

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CInv, self.inv, f)

    def __repr__(self):
        return "msg_inv(inv=%s)" % (repr(self.inv))


class msg_getdata(MsgSerializable, bitcoin_msg_getdata):
    command = b"getdata"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_getdata, self).__init__(protover)
        self.inv = []

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.inv = VectorSerializer.stream_deserialize(CInv, f)
        return c

    def msg_ser(self, f):
        VectorSerializer.stream_serialize(CInv, self.inv, f)

    def __repr__(self):
        return "msg_getdata(inv=%s)" % (repr(self.inv))


class msg_notfound(MsgSerializable, bitcoin_msg_notfound):
    command = b"notfound"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_notfound, self).__init__(protover)
        self.inv = []

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

    def __init__(self, protover=PROTO_VERSION):
        super(msg_getheaders, self).__init__(protover)
        self.locator = CSqueakLocator()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.locator = CSqueakLocator.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        self.locator.stream_serialize(f)
        pass

    def __repr__(self):
        return "msg_getheaders(locator=%s)" % (repr(666))


class msg_getsqueaks(MsgSerializable, BitcoinMsgSerializable):
    command = b"getsqueaks"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_getsqueaks, self).__init__(protover)
        self.locator = CSqueakLocator()

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.locator = CSqueakLocator.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        self.locator.stream_serialize(f)
        pass

    def __repr__(self):
        return "msg_getsqueaks(locator=%s)" % (repr(self.locator))


class msg_headers(MsgSerializable, BitcoinMsgSerializable):
    command = b"headers"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_headers, self).__init__(protover)
        self.headers = []

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


class msg_reject(MsgSerializable, bitcoin_msg_reject):
    pass


msg_classes = [msg_version, msg_verack, msg_addr, msg_alert, msg_inv,
               msg_getdata, msg_notfound, msg_getsqueaks, msg_getheaders,
               msg_headers, msg_getaddr, msg_ping, msg_pong, msg_reject]

messagemap = {}
for cls in msg_classes:
    messagemap[cls.command] = cls
