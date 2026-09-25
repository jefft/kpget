import os
import subprocess
import unittest
from unittest import mock

from kpget import yubikey

FIXED_MESSAGE = "ykman printed something other than hex; refusing to continue"


class ParseResponseTest(unittest.TestCase):
    def test_hex_output(self):
        self.assertEqual(yubikey.parse_response("A1B2\n"), b"\xa1\xb2")

    def test_odd_length_rejected(self):
        with self.assertRaises(yubikey.YubikeyError):
            yubikey.parse_response("abc\n")

    def test_secret_never_echoed_in_errors(self):
        with self.assertRaises(yubikey.YubikeyError) as ctx:
            yubikey.parse_response("deadbeefzz\n")
        self.assertEqual(str(ctx.exception), FIXED_MESSAGE)


class CalculateTest(unittest.TestCase):
    def fake_run(self, returncode=0, stdout="", stderr=""):
        calls = []

        def run(argv, capture_output, text):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

        run.calls = calls
        return run

    def test_default_invocation_is_sudo_ykman(self):
        runner = self.fake_run(stdout="aabb\n")
        with mock.patch.dict(os.environ):
            os.environ.pop("KPGET_YKMAN", None)
            self.assertEqual(yubikey.calculate("cafe", run=runner), b"\xaa\xbb")
        self.assertEqual(runner.calls, [["sudo", "ykman", "otp", "calculate", "1", "cafe"]])

    def test_kpget_ykman_override(self):
        runner = self.fake_run(stdout="aabb\n")
        with mock.patch.dict(os.environ, {"KPGET_YKMAN": "ykman"}):
            self.assertEqual(yubikey.calculate("cafe", run=runner), b"\xaa\xbb")
        self.assertEqual(runner.calls, [["ykman", "otp", "calculate", "1", "cafe"]])

    def test_missing_yubikey_classified(self):
        runner = self.fake_run(returncode=1, stderr="ERROR: No YubiKey detected!")
        with self.assertRaises(yubikey.YubikeyMissingError) as ctx:
            yubikey.calculate(run=runner)
        self.assertEqual(str(ctx.exception), "ERROR: No YubiKey detected!")

    def test_other_failure_stays_plain_error(self):
        runner = self.fake_run(returncode=1, stderr="Failed to write to the YubiKey")
        with self.assertRaises(yubikey.YubikeyError) as ctx:
            yubikey.calculate(run=runner)
        self.assertNotIsInstance(ctx.exception, yubikey.YubikeyMissingError)
        self.assertEqual(str(ctx.exception), "Failed to write to the YubiKey")

    def test_missing_yubikey_also_matches_stdout(self):
        runner = self.fake_run(returncode=1, stdout="No YubiKey found!", stderr="")
        with self.assertRaises(yubikey.YubikeyMissingError):
            yubikey.calculate(run=runner)

    def test_failure_raises_with_stderr(self):
        runner = self.fake_run(returncode=1, stderr="ykman: slot 1 not configured for challenge-response")
        with self.assertRaises(yubikey.YubikeyError) as ctx:
            yubikey.calculate(run=runner)
        self.assertNotIsInstance(ctx.exception, yubikey.YubikeyMissingError)
        self.assertEqual(str(ctx.exception), "ykman: slot 1 not configured for challenge-response")
