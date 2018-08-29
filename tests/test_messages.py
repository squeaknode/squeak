import unittest

from io import BytesIO

from squeak.messages import MsgSerializable
from squeak.messages import msg_version
from squeak.messages import msg_verack
from squeak.messages import msg_addr
from squeak.messages import msg_alert
from squeak.messages import msg_inv
from squeak.messages import msg_getdata
from squeak.messages import msg_getsqueaks
from squeak.messages import msg_notfound
from squeak.messages import msg_getheaders
from squeak.messages import msg_headers
from squeak.messages import msg_getaddr
from squeak.messages import msg_ping
from squeak.messages import msg_pong
from squeak.messages import msg_reject


class MessageTestCase(unittest.TestCase):
    def serialization_test(self, cls):
        m = cls()
        mSerialized = m.to_bytes()
        mDeserialzed = cls.from_bytes(mSerialized)
        mSerialzedTwice = mDeserialzed.to_bytes()
        self.assertEqual(mSerialized, mSerialzedTwice)
        self.assertTrue(isinstance(mDeserialzed, MsgSerializable))


class Test_msg_version(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_version, self).serialization_test(msg_version)

    def test_user_agent(self):
        m = msg_version()
        self.assertTrue(b'squeak' in m.strSubVer)


class Test_msg_verack(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_verack, self).serialization_test(msg_verack)


class Test_msg_addr(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_addr, self).serialization_test(msg_addr)


class Test_msg_alert(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_alert, self).serialization_test(msg_alert)


class Test_msg_inv(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_inv, self).serialization_test(msg_inv)


class Test_msg_getdata(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getdata, self).serialization_test(msg_getdata)


class Test_msg_getsqueaks(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getsqueaks, self).serialization_test(msg_getsqueaks)


class Test_msg_notfound(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_notfound, self).serialization_test(msg_notfound)


class Test_msg_getheaders(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getheaders, self).serialization_test(msg_getheaders)


class Test_msg_headers(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_headers, self).serialization_test(msg_headers)


class Test_msg_getaddr(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getaddr, self).serialization_test(msg_getaddr)


class Test_msg_ping(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_ping, self).serialization_test(msg_ping)


class Test_msg_pong(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_pong, self).serialization_test(msg_pong)


class Test_msg_reject(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_reject, self).serialization_test(msg_reject)


class Test_messages(unittest.TestCase):
    verackbytes = b'\xf9\xbe\xb4\xd9verack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00]\xf6\xe0\xe2'

    def test_read_msg_verack(self):
        f = BytesIO(self.verackbytes)
        m = MsgSerializable.stream_deserialize(f)
        self.assertEqual(m.command, msg_verack.command)
        self.assertTrue(isinstance(m, MsgSerializable))

    def test_fail_invalid_message(self):
        bad_verack_bytes = b'\xf8' + self.verackbytes[1:]
        f = BytesIO(bad_verack_bytes)
        with self.assertRaises(ValueError):
            MsgSerializable.stream_deserialize(f)

    def test_msg_verack_to_bytes(self):
        m = msg_verack()
        b = m.to_bytes()
        self.assertEqual(self.verackbytes, b)
