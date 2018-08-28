import unittest

from io import BytesIO

from squeak.messages import msg_getheaders
from squeak.messages import msg_version
from squeak.messages import msg_verack
from squeak.messages import SqueakMsgSerializable


class MessageTestCase(unittest.TestCase):
    def serialization_test(self, cls):
        m = cls()
        mSerialized = m.to_bytes()
        mDeserialzed = cls.from_bytes(mSerialized)
        mSerialzedTwice = mDeserialzed.to_bytes()
        self.assertEqual(mSerialized, mSerialzedTwice)


class Test_msg_version(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_version, self).serialization_test(msg_version)

    def test_user_agent(self):
        m = msg_version()
        self.assertTrue(b'squeak' in m.strSubVer)


class Test_msg_getheaders(MessageTestCase):
    def test_serialization(self):
        super(Test_msg_getheaders, self).serialization_test(msg_getheaders)


class Test_messages(unittest.TestCase):
    verackbytes = b'\xf9\xbe\xb4\xd9verack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00]\xf6\xe0\xe2'

    def test_read_msg_verack(self):
        f = BytesIO(self.verackbytes)
        m = SqueakMsgSerializable.stream_deserialize(f)
        self.assertEqual(m.command, msg_verack.command)
        print(m)
        self.assertTrue(isinstance(m, SqueakMsgSerializable))

    def test_fail_invalid_message(self):
        bad_verack_bytes = b'\xf8' + self.verackbytes[1:]
        f = BytesIO(bad_verack_bytes)
        with self.assertRaises(ValueError):
            SqueakMsgSerializable.stream_deserialize(f)

    def test_msg_verack_to_bytes(self):
        m = msg_verack()
        b = m.to_bytes()
        self.assertEqual(self.verackbytes, b)
