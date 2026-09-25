"""存储层：SQLite 模式、轻量迁移、行映射与审计日志。"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from common import ApiError, iso

DB_PATH = Path(__file__).with_name("data.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS key_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  issuer TEXT NOT NULL,
  version INTEGER NOT NULL,
  secret_hex TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','retired')),
  created_at TEXT NOT NULL,
  retired_at TEXT,
  renewal_deadline TEXT,
  UNIQUE(issuer, version)
);
CREATE TABLE IF NOT EXISTS templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  issuer TEXT NOT NULL,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  fields_json TEXT NOT NULL,
  validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
  status TEXT NOT NULL CHECK(status IN ('active','disabled')),
  created_at TEXT NOT NULL,
  UNIQUE(issuer, code)
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id INTEGER NOT NULL REFERENCES templates(id),
  issuer TEXT NOT NULL,
  holder_id TEXT NOT NULL,
  claims_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed','superseded')),
  key_version INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL,
  revocation_reason TEXT,
  revocation_effective_at TEXT,
  superseded_at TEXT,
  UNIQUE(template_id, holder_id, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
  ON credentials(template_id, holder_id)
  WHERE status IN ('active','disputed');
CREATE TABLE IF NOT EXISTS disputes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id INTEGER NOT NULL REFERENCES credentials(id),
  raised_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
  resolution TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS renewals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  old_credential_id INTEGER NOT NULL REFERENCES credentials(id) UNIQUE,
  new_credential_id INTEGER NOT NULL REFERENCES credentials(id),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  old_invalid_at TEXT NOT NULL,
  renewal_deadline TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  details_json TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        # 兼容换版功能之前创建的本地库：补齐新增列（CHECK 约束变化需重建库）。
        self._ensure_column("key_versions", "renewal_deadline", "renewal_deadline TEXT")
        self._ensure_column("credentials", "superseded_at", "superseded_at TEXT")
        self.conn.commit()

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        names = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in names:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    def close(self) -> None:
        self.conn.close()


def get_row(conn: sqlite3.Connection, table: str, identity: int) -> sqlite3.Row:
    row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
    if not row:
        raise ApiError(404, "对象不存在")
    return row


def credential_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "template_id": row["template_id"], "issuer": row["issuer"], "holder_id": row["holder_id"],
        "claims": json.loads(row["claims_json"]), "issued_at": row["issued_at"], "valid_until": row["valid_until"],
        "status": row["status"], "key_version": row["key_version"], "revocation_reason": row["revocation_reason"],
        "revocation_effective_at": row["revocation_effective_at"], "superseded_at": row["superseded_at"],
    }
