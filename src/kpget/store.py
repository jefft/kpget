"""Sqlite storage of KeepassXC association secrets (sealed via crypto.py).

The database is personal data: it is never committed, and permissions are
tightened to 0600 on every open. All queries are parameterized -- the
association name arrives from a KeepassXC GUI text field and must never be
interpolated into SQL.
"""
from __future__ import annotations

import collections
import os
import shutil
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

DB_NAME = "keepassclient.db"

Row = collections.namedtuple("Row", "rowid name sealed created_at database_hash database_name")


class StoreError(Exception):
    pass


def db_path() -> Path:
    override = os.environ.get("KPGET_DB")
    if override:
        return Path(override)
    # Default to the user's XDG data dir. The old editable-install default
    # (Path(__file__).parents[2]) is broken for any non-editable install --
    # e.g. a Nix-installed copy, where it resolves into the read-only store.
    xdg_data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(xdg_data) / "kpget" / DB_NAME


def _legacy_db_path() -> Path:
    # Pre-XDG location; only ever correct for an editable install
    # (<repo>/src/kpget/store.py -> <repo>/keepassclient.db).
    return Path(__file__).resolve().parents[2] / DB_NAME


def _migrate_legacy_db(path: Path) -> None:
    """Copy a legacy editable-install DB into the new XDG location, once."""
    legacy = _legacy_db_path()
    if legacy != path and legacy.is_file() and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy, path)
        print(f"kpget: migrated {legacy} -> {path}", file=sys.stderr)


def connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Only migrate when using the default location. An explicit KPGET_DB means
    # "use exactly this file", not "migrate the legacy DB for me".
    if "KPGET_DB" not in os.environ:
        _migrate_legacy_db(path)
    first = not path.exists()
    conn = sqlite3.connect(path, timeout=5)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS connections"
        " (name varchar(255), public_key_encrypted varchar(255), created_at varchar(32))"
    )
    _add_column_if_missing(conn, "connections", "created_at", "varchar(32)")
    _add_column_if_missing(conn, "connections", "database_hash", "varchar(64)")
    _add_column_if_missing(conn, "connections", "database_name", "varchar(255)")
    conn.commit()
    _harden(path)
    if first:
        print(f"kpget: created {path}", file=sys.stderr)
    return conn


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _harden(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o177:
        os.chmod(path, 0o600)
        print(f"kpget: tightened permissions on {path} ({mode:03o} -> 600)", file=sys.stderr)


def rows(conn: sqlite3.Connection) -> list[Row]:
    return [
        Row(*record)
        for record in conn.execute(
            "SELECT rowid, name, public_key_encrypted, created_at, database_hash, database_name"
            " FROM connections ORDER BY rowid"
        )
    ]


def add(
    conn: sqlite3.Connection,
    name: str,
    sealed: str,
    database_hash: str | None = None,
    database_name: str | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO connections (name, public_key_encrypted, created_at, database_hash, database_name)"
        " VALUES (?, ?, ?, ?, ?)",
        (
            name,
            sealed,
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            database_hash,
            database_name,
        ),
    )
    conn.commit()
    return cur.lastrowid


def update_database(
    conn: sqlite3.Connection, rowid: int, database_hash: str, database_name: str | None
) -> None:
    cur = conn.execute(
        "UPDATE connections SET database_hash = ?, database_name = ? WHERE rowid = ?",
        (database_hash, database_name, rowid),
    )
    conn.commit()
    if cur.rowcount != 1:
        raise StoreError(f"row {rowid} disappeared while updating")


def delete(conn: sqlite3.Connection, rowid: int) -> None:
    cur = conn.execute("DELETE FROM connections WHERE rowid = ?", (rowid,))
    conn.commit()
    if cur.rowcount != 1:
        raise StoreError(f"no connection with rowid {rowid}")
