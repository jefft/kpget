"""kpget: fetch passwords from KeepassXC, sealed behind a Yubikey.

The KeepassXC browser-integration association key is never stored in the
clear: it is sealed with a key only your Yubikey can produce (slot 1,
touch required). Commands:

    kpget register      associate with the loaded database (name it 'kpget-cli')
    kpget URL           print the first password for URL (same as 'get')
    kpget list          rowid / name / database / created
    kpget rm ROWID      forget a connection (prune dead rows)
    kpget unlock        ask KeepassXC to unlock the database

Overrides: KPGET_DB (database path), KPGET_YKMAN (ykman invocation).
"""
from __future__ import annotations
import argparse
import base64
import getpass
import os
import sqlite3
import sys

from keepassxc_proxy_client import protocol
from nacl.exceptions import CryptoError

from . import crypto, store, yubikey

COMMANDS = ("register", "list", "label", "rm", "unlock", "get")
# Errors that mean "operation failed" rather than "kpget is broken".
_EXPECTED_ERRORS = (
    crypto.SealError,
    yubikey.YubikeyError,
    store.StoreError,
    protocol.ResponseUnsuccesfulException,
    CryptoError,
    sqlite3.Error,
    OSError,
)


def _fail(message: str) -> int:
    print(f"kpget: {message}", file=sys.stderr)
    return 1

def _runtime_dir() -> None:
    # Root shells (su/sudo) lose XDG_RUNTIME_DIR; the KeepassXC socket lives
    # in the desktop user's runtime directory. If the path is unknowable,
    # fall through and let the library use its own default.
    try:
        uid = store.db_path().parent.stat().st_uid
    except OSError:
        return
    os.environ.setdefault("XDG_RUNTIME_DIR", "/run/user/%d" % uid)


def _normalize_argv(argv: list[str]) -> list[str]:
    # `kpget example.com` == `kpget get example.com`. Anything else that is
    # neither a command nor URL-shaped (typos, removed commands) falls
    # through to argparse's invalid-choice error instead of triggering a
    # Yubikey touch for a bogus URL.
    if (
        argv
        and argv[0] not in COMMANDS
        and not argv[0].startswith("-")
        and ("://" in argv[0] or "." in argv[0])
    ):
        return ["get", *argv]
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kpget", description="Fetch a password from KeepassXC, sealed behind a Yubikey."
    )
    sub = parser.add_subparsers(dest="command", metavar="command")

    p_register = sub.add_parser("register", help="associate with the currently loaded database")
    p_register.add_argument(
        "label", nargs="?", default=None,
        help="human name for the database (shown by list and the no-Yubikey fallback)",
    )
    p_register.set_defaults(func=cmd_register)
    sub.add_parser("list", help="list stored connections").set_defaults(func=cmd_list)
    sub.add_parser(
        "unlock", help="ask KeepassXC to unlock the database (triggers its dialog)"
    ).set_defaults(func=cmd_unlock)
    p_rm = sub.add_parser("rm", help="delete a stored connection by rowid (see list)")
    p_rm.add_argument("rowid", type=int)
    p_rm.set_defaults(func=cmd_rm)
    p_label = sub.add_parser("label", help="name a stored connection by rowid (see list)")
    p_label.add_argument("rowid", type=int)
    p_label.add_argument("name")
    p_label.set_defaults(func=cmd_label)
    p_get = sub.add_parser("get", help="print the first password for URL")
    p_get.add_argument("url")
    p_get.set_defaults(func=cmd_get)
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = _normalize_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(args_list)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    _runtime_dir()
    try:
        return func(args)
    except _EXPECTED_ERRORS as exc:
        return _fail(str(exc) or type(exc).__name__)


def _database_name(session) -> str | None:
    """Human label for the active database: KeepassXC names the root group
    after the database it belongs to. Some releases only serve this action
    when the request itself carries the association key, so retry once with
    keys attached (mirroring get-logins, which provably works)."""
    key = base64.b64encode(session.id_public_key._public_key).decode("ascii")
    last_error: Exception | None = None
    for extra in ({}, {"keys": [{"id": session.associate_id, "key": key}]}):
        try:
            session.send_encrypted_message({"action": "get-database-groups", **extra})
            return _extract_name(session.get_encrypted_response())
        except (KeyError, IndexError, TypeError, protocol.ResponseUnsuccesfulException, CryptoError) as exc:
            last_error = exc
    print(f"kpget: database name unavailable ({last_error!r}); using hash only", file=sys.stderr)
    return None


def _extract_name(response) -> str:
    """The protocol documents groups as an array with the root group first,
    but at least one build serves an object instead -- accept both, and
    report the actual shape if neither matches."""
    groups = response["groups"]
    root = groups[0] if isinstance(groups, list) else groups
    if isinstance(root, dict) and isinstance(root.get("name"), str):
        return root["name"]
    if isinstance(root, dict):
        for value in root.values():
            if isinstance(value, dict) and isinstance(value.get("name"), str):
                return value["name"]
    shape = repr(groups)
    raise KeyError("unexpected groups shape: " + (shape[:200] + "..." if len(shape) > 200 else shape))


def _manual_fetch(url: str, rows, active_hash: str) -> int:
    """No Yubikey: nothing can be unsealed. Point the user at the entry in
    KeepassXC, then read the password on stdin and re-emit it on stdout, so
    `kpget URL` behaves identically for callers with or without the key."""
    label = next(
        (r.database_name for r in rows if r.database_hash == active_hash and r.database_name),
        active_hash[:12],
    )
    print("kpget: no Yubikey detected -- manual fallback:", file=sys.stderr)
    print(f"  1. Open and unlock the '{label}' database in KeepassXC.", file=sys.stderr)
    print(f"  2. Find the entry whose URL matches: {url}", file=sys.stderr)
    print("  3. Copy its password, paste it at the prompt, press Enter.", file=sys.stderr)
    print("  (kpget cannot unseal its associations while the key is absent.)", file=sys.stderr)
    try:
        if sys.stdin.isatty():
            password = getpass.getpass(f"Enter password for {url}: ")
        else:
            password = sys.stdin.readline().rstrip("\r\n")
    except (EOFError, KeyboardInterrupt):
        return _fail("no password received on stdin")
    if not password:
        return _fail("no password received on stdin")
    print(password)
    return 0


def cmd_register(args) -> int:
    print("Creating a connection to the currently loaded KeepassXC database;", file=sys.stderr)
    print("enter the name 'kpget-cli' in the KeepassXC dialog.", file=sys.stderr)
    session = protocol.Connection()
    session.connect()
    # Touch BEFORE associating: a failed touch then leaves no side effects
    # anywhere -- no orphaned association inside KeepassXC, no local row.
    try:
        key = crypto.derive_key(yubikey.calculate())
    except yubikey.YubikeyMissingError:
        return _fail("no Yubikey detected; plug it in and retry -- register cannot seal without it")
    session.associate()
    try:
        session.test_associate()
    except protocol.ResponseUnsuccesfulException:
        return _fail("the newly created association is invalid; aborting")
    name, public_key = session.dump_associate()
    database_hash = session.get_databasehash()
    database_name = args.label or _database_name(session)
    if database_name is None and sys.stdin.isatty():
        sys.stderr.write("Enter a name for this database (Enter to skip): ")
        sys.stderr.flush()
        try:
            database_name = sys.stdin.readline().strip() or None
        except (EOFError, KeyboardInterrupt):
            database_name = None
    sealed = crypto.seal(key, base64.b64encode(public_key))
    conn = store.connect()
    rowid = store.add(conn, name, sealed, database_hash, database_name)
    print(
        f"kpget: stored association '{name}' for database"
        f" '{database_name or database_hash[:12]}' (rowid {rowid});"
        " it can now be used with 'kpget URL'.",
        file=sys.stderr,
    )
    return 0


def cmd_get(args) -> int:
    url = args.url
    if "://" not in url:
        url = "https://" + url
    conn = store.connect()
    rows = store.rows(conn)
    if not rows:
        return _fail("no KeepassXC connections exist; run 'kpget register' first")
    probe = protocol.Connection()
    try:
        probe.connect()
        active_hash = probe.get_databasehash()
    except OSError as exc:
        return _fail(
            f"cannot reach the KeepassXC browser socket (is KeepassXC running with browser integration?): {exc}"
        )
    active_name = next(
        (row.database_name for row in rows if row.database_hash == active_hash), None
    )
    print(f"kpget: active database: {active_name or active_hash[:12]}", file=sys.stderr)
    try:
        key = crypto.derive_key(yubikey.calculate())
    except yubikey.YubikeyMissingError:
        return _manual_fetch(url, rows, active_hash)
    for row in rows:
        if row.database_hash and row.database_hash != active_hash:
            print(
                f"kpget: row {row.rowid} ('{row.name}') belongs to another database"
                f" ('{row.database_name or row.database_hash[:12]}'); skipping",
                file=sys.stderr,
            )
            continue
        try:
            public_key_b64 = crypto.unseal(key, row.sealed).decode("ascii")
        except crypto.SealError as exc:
            print(f"kpget: row {row.rowid} ('{row.name}'): {exc}; skipping", file=sys.stderr)
            continue
        session = protocol.Connection()
        try:
            session.connect()
        except OSError as exc:
            return _fail(
                f"cannot reach the KeepassXC browser socket (is KeepassXC running with browser integration?): {exc}"
            )
        session.load_associate(row.name, base64.b64decode(public_key_b64))
        try:
            session.test_associate()
        except protocol.ResponseUnsuccesfulException:
            print(f"kpget: row {row.rowid} ('{row.name}'): association rejected; skipping", file=sys.stderr)
            continue
        if row.database_hash != active_hash or not row.database_name:
            store.update_database(conn, row.rowid, active_hash, _database_name(session))
        try:
            entries = session.get_logins(url)
        except protocol.ResponseUnsuccesfulException:
            print(f"kpget: row {row.rowid} ('{row.name}'): query failed; skipping", file=sys.stderr)
            continue
        if entries:
            print(entries[0].get("password", ""))
            return 0
        print(f"kpget: row {row.rowid} ('{row.name}'): no logins for {url}", file=sys.stderr)
    return _fail(f"no password entry for {url}")


def cmd_list(args) -> int:
    rows = store.rows(store.connect())
    if not rows:
        print("No connections stored.", file=sys.stderr)
        return 0
    print(f"{'rowid':>5}  {'name':<20} {'database':<24} {'hash':<14} created")
    for row in rows:
        database = row.database_name or "-"
        hash_id = row.database_hash[:12] if row.database_hash else "-"
        print(f"{row.rowid:>5}  {row.name:<20} {database:<24} {hash_id:<14} {row.created_at or '-'}")
    return 0


def cmd_rm(args) -> int:
    conn = store.connect()
    known = {row.rowid: row for row in store.rows(conn)}
    row = known.get(args.rowid)
    if row is None:
        return _fail(f"no connection with rowid {args.rowid}")
    store.delete(conn, args.rowid)
    print(f"kpget: deleted row {args.rowid} ('{row.name}', {row.created_at or 'date unknown'})", file=sys.stderr)
    return 0


def cmd_label(args) -> int:
    conn = store.connect()
    row = next((r for r in store.rows(conn) if r.rowid == args.rowid), None)
    if row is None:
        return _fail(f"no connection with rowid {args.rowid}")
    store.update_database(conn, args.rowid, row.database_hash, args.name)
    print(f"kpget: row {args.rowid} labelled '{args.name}'.", file=sys.stderr)
    return 0


def cmd_unlock(args) -> int:
    rows = store.rows(store.connect())
    if not rows:
        return _fail("no KeepassXC connections exist; run 'kpget register' first")
    try:
        key = crypto.derive_key(yubikey.calculate())
    except yubikey.YubikeyMissingError:
        return _fail("no Yubikey detected; plug it in and retry -- unlock cannot unseal without it")
    for row in rows:
        try:
            public_key_b64 = crypto.unseal(key, row.sealed).decode("ascii")
        except crypto.SealError:
            continue
        session = protocol.Connection()
        try:
            session.connect()
            session.load_associate(row.name, base64.b64decode(public_key_b64))
            session.test_associate(trigger_unlock=True)
        except (protocol.ResponseUnsuccesfulException, CryptoError, OSError):
            continue
        print(
            f"kpget: association '{row.name}' is valid; KeepassXC shows its unlock dialog"
            " if the database was locked.",
            file=sys.stderr,
        )
        return 0
    return _fail("no valid association; run 'kpget register'")
