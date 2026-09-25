import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from keepassxc_proxy_client import protocol
from nacl.public import PublicKey

from kpget import cli, store, yubikey


class NormalizeArgvTest(unittest.TestCase):
    def test_bare_url_becomes_get(self):
        self.assertEqual(cli._normalize_argv(["example.com"]), ["get", "example.com"])
        self.assertEqual(
            cli._normalize_argv(["https://x.example"]), ["get", "https://x.example"]
        )
        self.assertEqual(cli._normalize_argv(["migrate"]), ["migrate"])

    def test_commands_pass_through(self):
        self.assertEqual(cli._normalize_argv(["list"]), ["list"])
        self.assertEqual(cli._normalize_argv(["rm", "3"]), ["rm", "3"])
        self.assertEqual(cli._normalize_argv(["get", "x"]), ["get", "x"])
        self.assertEqual(cli._normalize_argv([]), [])
        self.assertEqual(cli._normalize_argv(["--help"]), ["--help"])


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(
            os.environ, {"KPGET_DB": os.path.join(tmp.name, "test.db")}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_command_shows_help(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main([]), 2)
        self.assertIn("usage", out.getvalue())

    def test_list_empty_reports_to_stderr(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.main(["list"]), 0)
        self.assertIn("No connections", err.getvalue())

    def test_list_shows_rows(self):
        store.add(store.connect(), "cli", "v2:abc")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["list"]), 0)
        self.assertIn("cli", out.getvalue())
        self.assertIn("created", out.getvalue())

    def test_get_without_connections_fails_before_yubikey(self):
        # Empty database: must fail without any Yubikey interaction.
        self.assertEqual(cli.main(["example.com"]), 1)

    def test_get_prints_manual_fallback_without_yubikey(self):
        store.add(store.connect(), "cli", "v2:abc", "aabb", "WorkDB")

        class _FakeProbe:
            def connect(self):
                pass

            def get_databasehash(self):
                return "aabb"

        err = io.StringIO()
        out = io.StringIO()
        with mock.patch("kpget.cli.protocol.Connection", return_value=_FakeProbe()), \
                mock.patch("kpget.cli.yubikey.calculate",
                           side_effect=yubikey.YubikeyMissingError("No YubiKey detected!")), \
                mock.patch("sys.stdin", io.StringIO("piped-secret\n")):
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(cli.main(["example.com"]), 0)
        self.assertEqual(out.getvalue(), "piped-secret\n")
        text = err.getvalue()
        self.assertIn("no Yubikey detected -- manual fallback", text)
        self.assertIn("https://example.com", text)
        self.assertIn("WorkDB", text)

    def test_get_without_yubikey_prompts_hidden_on_tty(self):
        store.add(store.connect(), "cli", "v2:abc", "aabb", "WorkDB")

        class _FakeProbe:
            def connect(self):
                pass

            def get_databasehash(self):
                return "aabb"

        err = io.StringIO()
        out = io.StringIO()
        with mock.patch("kpget.cli.protocol.Connection", return_value=_FakeProbe()), \
                mock.patch("kpget.cli.yubikey.calculate",
                           side_effect=yubikey.YubikeyMissingError("No YubiKey detected!")), \
                mock.patch("kpget.cli.getpass.getpass", return_value="typed-secret"), \
                mock.patch("sys.stdin", mock.Mock()):
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(cli.main(["example.com"]), 0)
        self.assertEqual(out.getvalue(), "typed-secret\n")

    def test_get_without_yubikey_empty_stdin_fails(self):
        store.add(store.connect(), "cli", "v2:abc", "aabb", "WorkDB")

        class _FakeProbe:
            def connect(self):
                pass

            def get_databasehash(self):
                return "aabb"

        err = io.StringIO()
        with mock.patch("kpget.cli.protocol.Connection", return_value=_FakeProbe()), \
                mock.patch("kpget.cli.yubikey.calculate",
                           side_effect=yubikey.YubikeyMissingError("No YubiKey detected!")), \
                mock.patch("sys.stdin", io.StringIO("")):
            with redirect_stderr(err):
                self.assertEqual(cli.main(["example.com"]), 1)
        self.assertIn("no password received", err.getvalue())

    def test_label_names_row_and_list_shows_it(self):
        rowid = store.add(store.connect(), "cli", "v2:abc", "aabb", None)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.main(["label", str(rowid), "WorkDB"]), 0)
        self.assertIn("labelled 'WorkDB'", err.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(["list"])
        self.assertIn("WorkDB", out.getvalue())

    def test_label_unknown_rowid_fails(self):
        self.assertEqual(cli.main(["label", "99", "WorkDB"]), 1)

    def test_labelled_row_is_used_by_manual_fallback(self):
        rowid = store.add(store.connect(), "cli", "v2:abc", "aabb", None)
        cli.main(["label", str(rowid), "WorkDB"])

        class _FakeProbe:
            def connect(self):
                pass

            def get_databasehash(self):
                return "aabb"

        err = io.StringIO()
        with mock.patch("kpget.cli.protocol.Connection", return_value=_FakeProbe()), \
                mock.patch("kpget.cli.yubikey.calculate",
                           side_effect=yubikey.YubikeyMissingError("No YubiKey detected!")), \
                mock.patch("sys.stdin", io.StringIO("piped\n")):
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(cli.main(["example.com"]), 0)
        self.assertIn("'WorkDB'", err.getvalue())

    def test_register_stores_explicit_label(self):
        class _FakeRegisterSession:
            associate_id = "kpget-cli"
            id_public_key = PublicKey(b"\x22" * 32)

            def connect(self):
                pass

            def associate(self):
                pass

            def test_associate(self):
                pass

            def dump_associate(self):
                return ("kpget-cli", b"\x22" * 32)

            def get_databasehash(self):
                return "ccdd"

            def send_encrypted_message(self, msg):
                pass

            def get_encrypted_response(self):
                return {"success": "true", "groups": 42}

        err = io.StringIO()
        with mock.patch("kpget.cli.protocol.Connection", return_value=_FakeRegisterSession()), \
                mock.patch("kpget.cli.yubikey.calculate", return_value=b"\x01" * 32):
            with redirect_stderr(err):
                self.assertEqual(cli.main(["register", "MyVault"]), 0)
        rows = store.rows(store.connect())
        self.assertEqual(rows[-1].database_name, "MyVault")
        self.assertIn("MyVault", err.getvalue())

    def test_register_touch_failure_leaves_no_side_effects(self):
        class _FakeRegisterSession:
            associate_id = "kpget-cli"
            id_public_key = PublicKey(b"\x22" * 32)
            calls = []

            def connect(self):
                self.calls.append("connect")

            def associate(self):
                self.calls.append("associate")

            def test_associate(self):
                pass

            def dump_associate(self):
                self.calls.append("dump_associate")
                return ("kpget-cli", b"\x22" * 32)

            def get_databasehash(self):
                return "ccdd"

        fake = _FakeRegisterSession()
        with mock.patch("kpget.cli.protocol.Connection", return_value=fake), \
                mock.patch("kpget.cli.yubikey.calculate",
                           side_effect=yubikey.YubikeyMissingError("No YubiKey detected!")):
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(cli.main(["register", "MyVault"]), 1)
        self.assertEqual(fake.calls, ["connect"])  # associate never ran
        self.assertIn("no Yubikey detected", err.getvalue())
        self.assertEqual(store.rows(store.connect()), [])

    def test_register_prompts_for_label_when_protocol_name_missing(self):
        class _TtyStringIO(io.StringIO):
            def isatty(self):
                return True

        class _FakeRegisterSession:
            associate_id = "kpget-cli"
            id_public_key = PublicKey(b"\x22" * 32)

            def connect(self):
                pass

            def associate(self):
                pass

            def test_associate(self):
                pass

            def dump_associate(self):
                return ("kpget-cli", b"\x22" * 32)

            def get_databasehash(self):
                return "ccdd"

            def send_encrypted_message(self, msg):
                pass

            def get_encrypted_response(self):
                return {"success": "true", "groups": [{"children": []}]}

        err = io.StringIO()
        with mock.patch("kpget.cli.protocol.Connection", return_value=_FakeRegisterSession()), \
                mock.patch("kpget.cli.yubikey.calculate", return_value=b"\x01" * 32), \
                mock.patch("sys.stdin", _TtyStringIO("MyVault\n")):
            with redirect_stderr(err):
                self.assertEqual(cli.main(["register"]), 0)
        rows = store.rows(store.connect())
        self.assertEqual(rows[-1].database_name, "MyVault")
        self.assertIn("Enter a name for this database", err.getvalue())
        self.assertIn("MyVault", err.getvalue())

    def test_unknown_word_is_argparse_error_not_a_query(self):
        # Regression: a removed/typo'd command used to be treated as a URL,
        # triggering a Yubikey touch for a bogus address.
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["migrate"])
        self.assertEqual(ctx.exception.code, 2)

    def test_rm_then_list(self):
        rowid = store.add(store.connect(), "cli", "v2:abc")
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.main(["rm", str(rowid)]), 0)
        self.assertIn("deleted row", err.getvalue())
        self.assertEqual(store.rows(store.connect()), [])

    def test_rm_unknown_rowid_fails(self):
        self.assertEqual(cli.main(["rm", "7"]), 1)


class _FakeSession:
    def __init__(self, responses):
        self.associate_id = "kpget-cli"
        self.id_public_key = PublicKey(b"\x11" * 32)
        self.responses = list(responses)
        self.sent = []

    def send_encrypted_message(self, msg):
        self.sent.append(msg)

    def get_encrypted_response(self):
        outcome = self.responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome



class DatabaseNameTest(unittest.TestCase):
    def test_plain_request_succeeds_without_keys(self):
        session = _FakeSession([{"success": "true", "groups": [{"name": "WorkDB", "children": []}]}])
        self.assertEqual(cli._database_name(session), "WorkDB")
        self.assertNotIn("keys", session.sent[0])

    def test_retries_with_association_key_attached(self):
        session = _FakeSession([
            protocol.ResponseUnsuccesfulException({"error": "Association failed"}),
            {"success": "true", "groups": [{"name": "PersonalDB", "children": []}]},
        ])
        self.assertEqual(cli._database_name(session), "PersonalDB")
        self.assertNotIn("keys", session.sent[0])
        self.assertEqual(session.sent[1]["keys"][0]["id"], "kpget-cli")

    def test_object_shaped_groups(self):
        session = _FakeSession([
            {"success": "true", "groups": {"name": "WorkDB", "uuid": "abc", "children": []}},
        ])
        self.assertEqual(cli._database_name(session), "WorkDB")

    def test_uuid_keyed_groups(self):
        session = _FakeSession([
            {"success": "true", "groups": {"abc123": {"name": "HomeDB", "children": []}}},
        ])
        self.assertEqual(cli._database_name(session), "HomeDB")

    def test_total_failure_reports_reason_and_returns_none(self):
        session = _FakeSession([
            protocol.ResponseUnsuccesfulException({"error": "Association failed"}),
            protocol.ResponseUnsuccesfulException({"error": "Association failed"}),
        ])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertIsNone(cli._database_name(session))
        self.assertIn("database name unavailable", err.getvalue())
        self.assertIn("Association failed", err.getvalue())

    def test_unrecognised_shape_reports_payload(self):
        session = _FakeSession([{"success": "true", "groups": 42}, {"success": "true", "groups": 42}])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertIsNone(cli._database_name(session))
        self.assertIn("unexpected groups shape: 42", err.getvalue())
