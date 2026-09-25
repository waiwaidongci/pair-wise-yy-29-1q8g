"""续签存储：续签关系表、旧凭证失效时间字段与凭证表结构迁移。

CREDENTIALS_DDL 是 credentials 表的权威定义，app.py 建库时同样引用，
此处负责对旧版本数据库做原地迁移（放宽状态约束、补充续签列）。
"""
from __future__ import annotations

import sqlite3

CREDENTIALS_DDL = """
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
  renewal_invalid_at TEXT,
  UNIQUE(template_id, holder_id, idempotency_key)
);
"""

ONE_LIVE_CREDENTIAL_INDEX_DDL = """
CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
  ON credentials(template_id, holder_id)
  WHERE status IN ('active','disputed');
"""

RENEWALS_DDL = """
CREATE TABLE IF NOT EXISTS renewals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  old_credential_id INTEGER NOT NULL UNIQUE REFERENCES credentials(id),
  new_credential_id INTEGER NOT NULL UNIQUE REFERENCES credentials(id),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  old_invalid_at TEXT NOT NULL,
  old_key_version INTEGER NOT NULL,
  new_key_version INTEGER NOT NULL
);
"""

# 重建表时需要保留的既有列（renewal_invalid_at 由迁移新增）。
_LEGACY_CREDENTIAL_COLUMNS = (
    "id,template_id,issuer,holder_id,claims_json,issued_at,valid_until,"
    "status,key_version,idempotency_key,revocation_reason,revocation_effective_at"
)


class RenewalStore:
    """续签关系与旧凭证失效时间的持久化。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.init_schema()

    def init_schema(self) -> None:
        self._migrate_credentials()
        self.conn.executescript(RENEWALS_DDL)
        self.conn.commit()

    def _migrate_credentials(self) -> None:
        table = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='credentials'"
        ).fetchone()
        if table and "superseded" not in table["sql"]:
            # 旧库的状态约束不含 superseded，按 SQLite 官方步骤重建表。
            self.conn.execute("PRAGMA foreign_keys=OFF")
            self.conn.execute("PRAGMA legacy_alter_table=ON")
            try:
                with self.conn:
                    self.conn.execute("ALTER TABLE credentials RENAME TO credentials_legacy")
                    self.conn.execute(CREDENTIALS_DDL.replace("IF NOT EXISTS ", "", 1))
                    self.conn.execute(
                        f"INSERT INTO credentials({_LEGACY_CREDENTIAL_COLUMNS}) "
                        f"SELECT {_LEGACY_CREDENTIAL_COLUMNS} FROM credentials_legacy"
                    )
                    self.conn.execute("DROP TABLE credentials_legacy")
                    self.conn.execute(ONE_LIVE_CREDENTIAL_INDEX_DDL)
            finally:
                self.conn.execute("PRAGMA legacy_alter_table=OFF")
                self.conn.execute("PRAGMA foreign_keys=ON")
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(credentials)")}
        if "renewal_invalid_at" not in columns:
            self.conn.execute("ALTER TABLE credentials ADD COLUMN renewal_invalid_at TEXT")
            self.conn.commit()

    def find_by_old(self, old_credential_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM renewals WHERE old_credential_id=?", (old_credential_id,)
        ).fetchone()

    def find_by_id(self, renewal_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM renewals WHERE id=?", (renewal_id,)).fetchone()

    def mark_superseded(self, credential_id: int, invalid_at: str) -> None:
        """把旧凭证移出有效集合（释放同模板同持有人的唯一约束）并写明失效时间。"""
        self.conn.execute(
            "UPDATE credentials SET status='superseded', renewal_invalid_at=? WHERE id=?",
            (invalid_at, credential_id),
        )

    def insert_successor(self, old: sqlite3.Row, key_version: int, issued_at: str) -> int:
        """以当前密钥为同模板同持有人换发新版本，沿用原声明与有效期。"""
        cur = self.conn.execute(
            """INSERT INTO credentials(template_id,issuer,holder_id,claims_json,issued_at,valid_until,status,key_version,idempotency_key)
               VALUES(?,?,?,?,?,?, 'active',?,?)""",
            (
                old["template_id"], old["issuer"], old["holder_id"], old["claims_json"],
                issued_at, old["valid_until"], key_version, f"renewal:{old['id']}",
            ),
        )
        return int(cur.lastrowid)

    def record(
        self,
        old_credential_id: int,
        new_credential_id: int,
        requested_by: str,
        requested_at: str,
        old_invalid_at: str,
        old_key_version: int,
        new_key_version: int,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO renewals(old_credential_id,new_credential_id,requested_by,requested_at,old_invalid_at,old_key_version,new_key_version)
               VALUES(?,?,?,?,?,?,?)""",
            (old_credential_id, new_credential_id, requested_by, requested_at, old_invalid_at, old_key_version, new_key_version),
        )
        return int(cur.lastrowid)

    def list_all(self) -> list[dict]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM renewals ORDER BY id DESC")]
