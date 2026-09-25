"""密钥版本规则：轮换后旧密钥的续签宽限期与可验证截止时间。"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

# 密钥退休（轮换）后，旧版本签出的凭证可继续验证并申请续签的宽限天数。
RENEWAL_GRACE_DAYS = 30


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class KeyRules:
    """密钥版本查询与轮换规则，不感知 HTTP，只返回查询结果。"""

    def __init__(self, conn: sqlite3.Connection, grace_days: int = RENEWAL_GRACE_DAYS):
        if grace_days < 1:
            raise ValueError("续签宽限期至少为 1 天")
        self.conn = conn
        self.grace_days = grace_days

    def active_key(self, issuer: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1",
            (issuer,),
        ).fetchone()

    def key_version(self, issuer: str, version: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (issuer, version)
        ).fetchone()

    def rotation_pending(self, key: sqlite3.Row) -> bool:
        """该密钥签出的凭证是否因轮换而需要续签。"""
        return key["status"] == "retired"

    def renewal_deadline(self, key: sqlite3.Row) -> datetime | None:
        """退休密钥签出的凭证可继续验证的截止时间；未退休返回 None。"""
        if not self.rotation_pending(key) or not key["retired_at"]:
            return None
        return parse_timestamp(key["retired_at"]) + timedelta(days=self.grace_days)
