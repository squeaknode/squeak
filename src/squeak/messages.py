import struct
import hashlib

from io import BytesIO as _BytesIO


import bitcoin
from bitcoin.messages import msg_version as MsgSerializable
from bitcoin.messages import msg_version as bitcoin_msg_version
from bitcoin.messages import msg_verack as bitcoin_msg_verack
from bitcoin.messages import msg_addr as bitcoin_msg_addr
from bitcoin.messages import msg_alert as bitcoin_msg_alert
from bitcoin.messages import msg_inv as bitcoin_msg_inv
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
from squeak.net import CSqueakLocator


USER_AGENT = (b'/python-squeak:' +
              squeak.__version__.encode('ascii') + b'/')


class SqueakMsgSerializable(object):

    @classmethod
    def from_bytes(cls, b, protover=PROTO_VERSION):
        f = _BytesIO(b)
        return SqueakMsgSerializable.stream_deserialize(f, protover=protover)

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


class msg_version(SqueakMsgSerializable, bitcoin_msg_version):

    def __init__(self, protover=PROTO_VERSION, user_agent=USER_AGENT):
        super(msg_version, self).__init__(protover=protover)
        self.strSubVer = user_agent


class msg_verack(SqueakMsgSerializable, bitcoin_msg_verack):
    pass


class msg_addr(SqueakMsgSerializable, bitcoin_msg_addr):
    pass


class msg_alert(SqueakMsgSerializable, bitcoin_msg_alert):
    pass


class msg_inv(SqueakMsgSerializable, bitcoin_msg_inv):
    pass


class msg_getdata(SqueakMsgSerializable, bitcoin_msg_getdata):
    pass


class msg_notfound(SqueakMsgSerializable, bitcoin_msg_notfound):
    pass


class msg_getheaders(SqueakMsgSerializable, MsgSerializable):
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


class msg_getsqueaks(SqueakMsgSerializable, MsgSerializable):
    command = b"getsqueaks"

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

    def __repr__(self):
        return "msg_getsqueaks(locator=%s)" % (repr(self.locator))


class msg_headers(SqueakMsgSerializable, MsgSerializable):
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


class msg_getaddr(SqueakMsgSerializable, bitcoin_msg_getaddr):
    pass


class msg_ping(SqueakMsgSerializable, bitcoin_msg_ping):
    pass


class msg_pong(SqueakMsgSerializable, bitcoin_msg_pong):
    pass


class msg_reject(SqueakMsgSerializable, bitcoin_msg_reject):
    pass


msg_classes = [msg_version, msg_verack, msg_addr, msg_alert, msg_inv,
               msg_getdata, msg_notfound, msg_getsqueaks, msg_getheaders,
               msg_headers, msg_getaddr, msg_ping, msg_pong, msg_reject]

messagemap = {}
for cls in msg_classes:
    messagemap[cls.command] = cls
