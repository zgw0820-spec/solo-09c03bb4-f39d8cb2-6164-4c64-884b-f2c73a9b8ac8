"""SQLite 存储层：版本表、单例行状态表、操作流水表。

所有写操作通过 DB.txn()（BEGIN IMMEDIATE）串行化，
比较-交换条件（如 base_version、current_op_seq）与修改在同一事务内完成。
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint   TEXT NOT NULL UNIQUE,
  domain        TEXT NOT NULL,
  subject       TEXT NOT NULL,
  san           TEXT NOT NULL,
  not_before    TEXT NOT NULL,
  not_after     TEXT NOT NULL,
  cert_pem      TEXT NOT NULL,
  key_pem       TEXT NOT NULL,
  status        TEXT NOT NULL,          -- candidate|active|superseded|failed
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  active_version_id INTEGER,
  current_op_seq    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ops (
  seq              INTEGER PRIMARY KEY,
  version_id       INTEGER NOT NULL,    -- 目标版本
  base_version_id  INTEGER NOT NULL,    -- 提交时页面所见的在用版本
  state            TEXT NOT NULL,       -- activating|pending_verify|succeeded|failed|superseded
  detail           TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
"""


class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def init_schema(self) -> None:
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.execute(
                "INSERT OR IGNORE INTO state (id, active_version_id, current_op_seq)"
                " VALUES (1, NULL, 0)"
            )

    @contextmanager
    def txn(self):
        """串行化的 IMMEDIATE 事务；读多行状态也用它保证一致性。"""
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self.conn.close()
