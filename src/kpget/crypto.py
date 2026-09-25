"""Sealing of KeepassXC association secrets.

PyNaCl SecretBox (XSalsa20-Poly1305, authenticated). The key is
sha256(Yubikey challenge-response), so a sealed row can only be opened while
the Yubikey is present -- and a tampered or corrupt row fails closed instead
of decrypting to garbage.
"""
from __future__ import annotations

import base64
import hashlib

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

V2_PREFIX = "v2:"


class SealError(Exception):
    """A stored association secret could not be decrypted."""


def derive_key(response: bytes) -> bytes:
    """Turn the raw Yubikey response into a 32-byte SecretBox key.

    No password KDF is needed: the response is a uniformly random key, not a
    password anyone could guess.
    """
    return hashlib.sha256(response).digest()


def seal(key: bytes, plaintext: bytes) -> str:
    box = SecretBox(key)
    return V2_PREFIX + base64.b64encode(bytes(box.encrypt(plaintext))).decode("ascii")


def unseal(key: bytes, stored: str) -> bytes:
    if not stored.startswith(V2_PREFIX):
        raise SealError("not a v2-sealed secret")
    try:
        return SecretBox(key).decrypt(base64.b64decode(stored[len(V2_PREFIX):]))
    except CryptoError as exc:
        raise SealError("decryption failed (wrong Yubikey response or corrupt row)") from exc
