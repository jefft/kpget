import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from kpget import secretspec_register as reg


class ClaimDirTest(unittest.TestCase):
    def test_xdg_config_home_wins(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/custom/cfg"}):
            self.assertEqual(reg.claim_dir(), Path("/custom/cfg/secretspec/providers.d"))

    def test_falls_back_to_home_config(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                reg.claim_dir(), Path.home() / ".config" / "secretspec" / "providers.d"
            )


class WriteClaimTest(unittest.TestCase):
    def test_writes_json_with_kpget_env_and_tight_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "providers.d"
            claim = reg.write_claim(directory, Path("/venv/bin/kpget-secretspec-provider"))
            payload = json.loads(claim.read_text())
            self.assertEqual(payload["executable"], "/venv/bin/kpget-secretspec-provider")
            self.assertEqual(payload["environment"], ["KPGET_*"])
            self.assertEqual(claim.name, "kpget.secretspec.json")
            self.assertFalse(claim.stat().st_mode & 0o022)
            self.assertFalse(directory.stat().st_mode & 0o022)

    def test_rewrite_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "providers.d"
            first = reg.write_claim(directory, Path("/a"))
            second = reg.write_claim(directory, Path("/a"))
            self.assertEqual(first, second)
            self.assertEqual(json.loads(first.read_text())["executable"], "/a")


class TightenTest(unittest.TestCase):
    def test_strips_group_write_along_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            venv_bin = root / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            exe = venv_bin / "kpget-secretspec-provider"
            exe.write_text("#!/bin/sh\n")
            for path in (root, root / ".venv", venv_bin):
                path.chmod(0o775)
            exe.chmod(0o775)
            reg.tighten_executable(exe, root)
            for path in (root, root / ".venv", venv_bin, exe):
                self.assertFalse(path.stat().st_mode & 0o022, path)
            self.assertTrue(exe.stat().st_mode & 0o111, "must stay executable")


class MainTest(unittest.TestCase):
    def test_end_to_end_writes_claim_for_fake_venv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            venv_bin = root / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            exe = venv_bin / "kpget-secretspec-provider"
            exe.write_text("#!/bin/sh\n")
            exe.chmod(0o775)
            fake_python = venv_bin / "python"
            fake_python.write_text("")
            config = Path(tmp) / "cfg"
            out = io.StringIO()
            with mock.patch.object(reg.sys, "executable", str(fake_python)), \
                    mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config)}):
                with redirect_stdout(out):
                    self.assertEqual(reg.main(project_root=root), 0)
            claim = config / "secretspec" / "providers.d" / "kpget.secretspec.json"
            payload = json.loads(claim.read_text())
            self.assertEqual(payload["executable"], str(exe))
            self.assertIn("re-run", out.getvalue())

    def test_missing_endpoint_exits_with_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_python = Path(tmp) / "python"
            fake_python.write_text("")
            err = io.StringIO()
            with mock.patch.object(reg.sys, "executable", str(fake_python)), \
                    mock.patch("sys.stderr", err):
                with self.assertRaises(SystemExit) as ctx:
                    reg.main(project_root=Path(tmp))
            self.assertIn("uv sync", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
