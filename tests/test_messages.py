import unittest

from squeak.messages import msg_version


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
