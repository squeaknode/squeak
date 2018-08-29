import struct
import hashlib

from io import BytesIO as _BytesIO

import bitcoin
from bitcoin.messages import MsgSerializable as BitcoinMsgSerializable
from bitcoin.messages import msg_version as bitcoin_msg_version
from bitcoin.messages import msg_verack as bitcoin_msg_verack
from bitcoin.messages import msg_addr as bitcoin_msg_addr
from bitcoin.messages import msg_alert as bitcoin_msg_alert
from bitcoin.messages import msg_getaddr as bitcoin_msg_getaddr
from bitcoin.messages import msg_ping as bitcoin_msg_ping
from bitcoin.messages import msg_pong as bitcoin_msg_pong
from bitcoin.messages import msg_reject as bitcoin_msg_reject
from bitcoin.core.serialize import VectorSerializer
from bitcoin.core.serialize import VarStringSerializer
from bitcoin.core.serialize import ser_read
from bitcoin.core import b2x
from bitcoin.core import b2lx

import squeak
from squeak.core import CSqueak
from squeak.core import CSqueakHeader
from squeak.core import HASH_LENGTH
from squeak.core import ENCRYPTED_DATA_KEY_LENGTH
from squeak.core import DATA_KEY_LENGTH
from squeak.net import CInv
from squeak.net import CSqueakLocator
from squeak.net import PROTO_VERSION


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


class msg_getdata(MsgSerializable, BitcoinMsgSerializable):
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


class msg_notfound(MsgSerializable, BitcoinMsgSerializable):
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


class msg_offer(MsgSerializable, BitcoinMsgSerializable):
    command = b"offer"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_offer, self).__init__(protover)
        self.squeak = CSqueak()
        self.signature = b''
        self.price = 0

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak = CSqueak.stream_deserialize(f)
        c.signature = VarStringSerializer.stream_deserialize(f)
        c.price = struct.unpack(b"<i", ser_read(f, 4))[0]
        return c

    def msg_ser(self, f):
        self.squeak.stream_serialize(f)
        VarStringSerializer.stream_serialize(self.signature, f)
        f.write(struct.pack(b"<i", self.price))
        pass

    def __repr__(self):
        return "msg_offer(squeak=%s signature=lx(%s) price=%i)" % \
            (repr(self.squeak), b2lx(self.signature), self.price)


class msg_acceptoffer(MsgSerializable, BitcoinMsgSerializable):
    command = b"acceptoffer"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_acceptoffer, self).__init__(protover)
        self.squeak_hash = b'\x00'*HASH_LENGTH
        self.challenge = b'\x00'*ENCRYPTED_DATA_KEY_LENGTH

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
        return "msg_acceptoffer(squeakhash=lx(%s) challenge=lx(%s))" % \
            (b2lx(self.squeak_hash), b2lx(self.challenge))


class msg_invoice(MsgSerializable, BitcoinMsgSerializable):
    command = b"invoice"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_invoice, self).__init__(protover)
        self.squeak_hash = b'\x00'*HASH_LENGTH
        self.proof = b'\x00'*DATA_KEY_LENGTH
        self.payment_info = b''

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak_hash = ser_read(f, HASH_LENGTH)
        c.proof = ser_read(f, DATA_KEY_LENGTH)
        c.payment_info = VarStringSerializer.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        assert len(self.squeak_hash) == HASH_LENGTH
        f.write(self.squeak_hash)
        assert len(self.proof) == DATA_KEY_LENGTH
        f.write(self.proof)
        VarStringSerializer.stream_serialize(self.payment_info, f)

    def __repr__(self):
        return "msg_invoice(squeakhash=lx(%s) proof=lx(%s) payment_info=%s)" % \
            (b2lx(self.squeak_hash), b2lx(self.proof), self.payment_info)


class msg_fulfill(MsgSerializable, BitcoinMsgSerializable):
    command = b"fulfill"

    def __init__(self, protover=PROTO_VERSION):
        super(msg_fulfill, self).__init__(protover)
        self.squeak_hash = b'\x00'*HASH_LENGTH
        self.encryption_key = b''

    @classmethod
    def msg_deser(cls, f, protover=PROTO_VERSION):
        c = cls()
        c.squeak_hash = ser_read(f, HASH_LENGTH)
        c.encryption_key = VarStringSerializer.stream_deserialize(f)
        return c

    def msg_ser(self, f):
        assert len(self.squeak_hash) == HASH_LENGTH
        f.write(self.squeak_hash)
        VarStringSerializer.stream_serialize(self.encryption_key, f)

    def __repr__(self):
        return "msg_fulfill(squeakhash=lx(%s) encryption_key=lx(%s))" % \
            (b2lx(self.squeak_hash), b2lx(self.encryption_key))


msg_classes = [msg_version, msg_verack, msg_addr, msg_alert, msg_inv,
               msg_getdata, msg_notfound, msg_getsqueaks, msg_getheaders,
               msg_headers, msg_getaddr, msg_ping, msg_pong, msg_reject,
               msg_offer, msg_acceptoffer, msg_invoice, msg_fulfill]

messagemap = {}
for cls in msg_classes:
    messagemap[cls.command] = cls
