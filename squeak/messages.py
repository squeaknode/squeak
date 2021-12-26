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
import hashlib
import random
import struct
import time
from io import BytesIO as _BytesIO

import bitcoin  # noqa: F401
from bitcoin.core import b2lx
from bitcoin.core import b2x
from bitcoin.core.serialize import ser_read
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

import squeak.params
from squeak.core import CSqueak
from squeak.core import HASH_LENGTH
from squeak.core import SECRET_KEY_LENGTH
from squeak.net import CInv
from squeak.net import COffer
from squeak.net import CSqueakLocator
from squeak.net import PROTO_VERSION


MSG_SQUEAK = 1
MSG_SECRET_KEY = 2

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


class msg_secretkey(MsgSerializable, BitcoinMsgSerializable):
    command = b"secretkey"

    def __init__(self, hashSqk=None, secretKey=None, offer=None, protover=PROTO_VERSION):
        super(msg_secretkey, self).__init__(protover)
        self.hashSqk = hashSqk or b'\x00'*HASH_LENGTH
        self.secretKey = secretKey or b'\x00'*SECRET_KEY_LENGTH
        self.offer = offer

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        hashSqk = ser_read(f, HASH_LENGTH)
        secretKey = ser_read(f, SECRET_KEY_LENGTH)
        markerbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        flagbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        if markerbyte == 0 and flagbyte == 1:
            offer = COffer.stream_deserialize(f)
        else:
            offer = None
        return cls(hashSqk, secretKey, offer)

    def msg_ser(self, f):
        assert len(self.hashSqk) == HASH_LENGTH
        f.write(self.hashSqk)
        assert len(self.secretKey) == SECRET_KEY_LENGTH
        f.write(self.secretKey)
        if self.offer is None:
            f.write(b'\x00')  # Marker
            f.write(b'\x00')  # Flag
        else:
            f.write(b'\x00')  # Marker
            f.write(b'\x01')  # Flag
            self.offer.stream_serialize(f)

    def has_secret_key(self):
        """True if secret key is included."""
        return self.secretKey != b'\x00'*SECRET_KEY_LENGTH

    def has_offer(self):
        """True if offer is included."""
        return self.offer is not None

    def __repr__(self):
        return "msg_secretkey(hashSqk=lx(%s) secretKey=lx(%s) offer=%s)" % \
            (b2lx(self.hashSqk), b2lx(self.secretKey), self.offer)


msg_classes = [msg_version, msg_verack, msg_addr, msg_inv, msg_getdata,
               msg_notfound, msg_getsqueaks, msg_subscribe,
               msg_squeak, msg_getaddr, msg_ping, msg_pong, msg_alert,
               msg_secretkey]

messagemap = {}
for cls in msg_classes:
    messagemap[cls.command] = cls  # type: ignore
