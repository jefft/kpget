"""Yubikey challenge-response: the only way to derive the sealing key.

Slot 1 must be programmed for challenge-response with touch required:
    ykman otp chalresp --touch --generate 1
The touch is the security boundary -- no process, not even one running as
root, can mint the sealing key while the user is away from the keyboard.

KPGET_YKMAN overrides the ykman invocation (default: "sudo ykman"), e.g.
    KPGET_YKMAN=ykman kpget URL        # udev rules grant user access
"""
from __future__ import annotations

import os
import shlex
import subprocess

DEFAULT_CHALLENGE = "2a1d815e52ab9fbb7e0cc60a37d6d668ca943598"


class YubikeyError(Exception):
    pass


class YubikeyMissingError(YubikeyError):
    """ykman reports no Yubikey connected."""


def calculate(challenge: str = DEFAULT_CHALLENGE, run=subprocess.run) -> bytes:
    """Challenge slot 1 and return the raw response bytes."""
    cmd = shlex.split(os.environ.get("KPGET_YKMAN") or "sudo ykman")
    proc = run([*cmd, "otp", "calculate", "1", challenge], capture_output=True, text=True)
    if proc.returncode != 0:
        text = (proc.stderr or "") + (proc.stdout or "")
        if "no yubikey" in text.lower():
            raise YubikeyMissingError(proc.stderr.strip() or "no Yubikey detected")
        raise YubikeyError(proc.stderr.strip() or "ykman failed")
    return parse_response(proc.stdout)


def parse_response(stdout: str) -> bytes:
    try:
        return bytes.fromhex(stdout.strip().lower())
    except ValueError:
        # stdout of a successful calculate IS the secret: never echo it back,
        # not even in an error message.
        raise YubikeyError("ykman printed something other than hex; refusing to continue") from None
