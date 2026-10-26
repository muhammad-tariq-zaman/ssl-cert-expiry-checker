import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main


class FakeSSLSock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getpeercert(self):
        return {"notAfter": "Jan 30 00:00:00 2027 GMT"}


class FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestSSL(unittest.TestCase):
    def test_warning_status(self):
        now = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
        with mock.patch("main.socket.create_connection", return_value=FakeSock()), \
             mock.patch("main.ssl.create_default_context") as ctx_mock:
            ctx_mock.return_value.wrap_socket.return_value = FakeSSLSock()
            r = main.check_host("example.test", now=now)
        self.assertEqual(r["status"], "WARNING")
        self.assertEqual(r["days_left"], 29)

    def test_error_is_reported_not_invented(self):
        with mock.patch("main.socket.create_connection", side_effect=OSError("dns fail")):
            r = main.check_host("bad.test")
        self.assertEqual(r["status"], "ERROR")
        self.assertIsNone(r["days_left"])


if __name__ == "__main__":
    unittest.main()
