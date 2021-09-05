import unittest
from io import BytesIO

from squeak.messages import msg_addr
from squeak.messages import msg_alert
from squeak.messages import msg_getaddr
from squeak.messages import msg_getdata
from squeak.messages import msg_getsqueaks
from squeak.messages import msg_subscribe
from squeak.messages import msg_inv
from squeak.messages import msg_notfound
from squeak.messages import msg_offer
from squeak.messages import msg_ping
from squeak.messages import msg_pong
from squeak.messages import msg_secretkey
from squeak.messages import msg_squeak
from squeak.messages import msg_verack
from squeak.messages import msg_version
from squeak.messages import MsgSerializable


class MessageTestCase(unittest.TestCase):
    def serialization_test(self, cls):
        m = cls()
        mSerialized = m.to_bytes()
        mDeserialzed = cls.from_bytes(mSerialized)
        mSerialzedTwice = mDeserialzed.to_bytes()
        self.assertEqual(mSerialized, mSerialzedTwice)
        self.assertTrue(isinstance(mDeserialzed, MsgSerializable))
        self.assertTrue(isinstance(str(mDeserialzed), str))

        msg_name = 'msg_' + m.command.decode("utf-8")
        self.assertTrue(msg_name in str(m))


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


class Test_msg_inv(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_inv, self).serialization_test(msg_inv)


class Test_msg_getdata(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getdata, self).serialization_test(msg_getdata)


class Test_msg_getsqueaks(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getsqueaks, self).serialization_test(msg_getsqueaks)


class Test_msg_subscribe(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_subscribe, self).serialization_test(msg_subscribe)


class Test_msg_notfound(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_notfound, self).serialization_test(msg_notfound)


class Test_msg_squeak(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_squeak, self).serialization_test(msg_squeak)


class Test_msg_getaddr(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getaddr, self).serialization_test(msg_getaddr)


class Test_msg_ping(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_ping, self).serialization_test(msg_ping)


class Test_msg_pong(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_pong, self).serialization_test(msg_pong)


class Test_msg_alert(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_alert, self).serialization_test(msg_alert)


class Test_msg_offer(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_offer, self).serialization_test(msg_offer)


class Test_msg_secretkey(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_secretkey, self).serialization_test(msg_secretkey)


class Test_messages(unittest.TestCase):
    verackbytes = b'\xb4n\x83\xfeverack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00]\xf6\xe0\xe2'

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
