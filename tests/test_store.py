import os
import sqlite3
import stat
import tempfile
import unittest
from unittest import mock

from kpget import store


class StoreTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "test.db")
        patcher = mock.patch.dict(os.environ, {"KPGET_DB": self.path})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_init_is_idempotent_and_starts_empty(self):
        store.connect().close()
        conn = store.connect()
        self.assertEqual(store.rows(conn), [])

    def test_add_list_delete_roundtrip(self):
        conn = store.connect()
        rowid = store.add(conn, "cli", "v2:abc")
        rows = store.rows(conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].rowid, rows[0].name, rows[0].sealed), (rowid, "cli", "v2:abc"))
        self.assertIsNotNone(rows[0].created_at)
        store.delete(conn, rowid)
        self.assertEqual(store.rows(conn), [])

    def test_hostile_name_survives_and_table_intact(self):
        # Regression: the bash tool interpolated this GUI-supplied field
        # straight into the INSERT statement.
        conn = store.connect()
        hostile = "O'Brien'); DROP TABLE connections;--"
        store.add(conn, hostile, "v2:abc")
        self.assertEqual(store.rows(conn)[0].name, hostile)
        self.assertEqual(len(store.rows(conn)), 1)

    def test_database_identity_roundtrip(self):
        conn = store.connect()
        rowid = store.add(conn, "kpget-cli", "v2:abc", "hash1", "WorkDB")
        row = store.rows(conn)[0]
        self.assertEqual((row.database_hash, row.database_name), ("hash1", "WorkDB"))
        store.update_database(conn, rowid, "hash2", "PersonalDB")
        row = store.rows(conn)[0]
        self.assertEqual((row.database_hash, row.database_name), ("hash2", "PersonalDB"))

    def test_delete_missing_rowid_raises(self):
        with self.assertRaises(store.StoreError):
            store.delete(store.connect(), 999)

    def test_permissions_tightened(self):
        os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o644))
        store.connect().close()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_opens_two_column_schema(self):
        # Databases created by the old bash tool lack created_at.
        old = sqlite3.connect(self.path)
        old.execute(
            "CREATE TABLE connections (name varchar(255), public_key_encrypted varchar(255))"
        )
        old.execute("INSERT INTO connections VALUES ('cli', 'sealed-blob')")
        old.commit()
        old.close()
        rows = store.rows(store.connect())
        self.assertEqual((rows[0].name, rows[0].sealed), ("cli", "sealed-blob"))
        self.assertIsNone(rows[0].created_at)
