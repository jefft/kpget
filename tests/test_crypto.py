import base64
import unittest

from kpget import crypto


class CryptoTest(unittest.TestCase):
    def test_roundtrip(self):
        key = bytes(range(32))
        sealed = crypto.seal(key, b"association-public-key")
        self.assertTrue(sealed.startswith(crypto.V2_PREFIX))
        self.assertEqual(crypto.unseal(key, sealed), b"association-public-key")

    def test_wrong_key_fails_closed(self):
        sealed = crypto.seal(b"a" * 32, b"secret")
        with self.assertRaises(crypto.SealError):
            crypto.unseal(b"b" * 32, sealed)

    def test_tampering_detected(self):
        key = b"k" * 32
        sealed = crypto.seal(key, b"secret")
        raw = bytearray(base64.b64decode(sealed[len(crypto.V2_PREFIX):]))
        raw[-1] ^= 0x01
        tampered = crypto.V2_PREFIX + base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(crypto.SealError):
            crypto.unseal(key, tampered)

    def test_derive_key_is_sha256_of_response(self):
        self.assertEqual(
            crypto.derive_key(b"abc"),
            bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        )

    def test_unseal_rejects_foreign_scheme(self):
        with self.assertRaises(crypto.SealError):
            crypto.unseal(b"k" * 32, "U2FsdGVkX1whatever")
