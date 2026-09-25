"""密钥规则：轮换、当前版本查询与旧版本续签宽限。"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import timedelta

from common import ApiError, iso, now, parse_time

# 旧密钥版本退役后，其签出的凭证仍可验证并允许续签的宽限天数。
RENEWAL_GRACE_DAYS = 30


def active_key(conn: sqlite3.Connection, issuer: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
    ).fetchone()
    if not row:
        raise ApiError(409, "签发方尚未初始化密钥")
    return row


def key_version(conn: sqlite3.Connection, issuer: str, version: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM key_versions WHERE issuer=? AND version=?", (issuer, version)
    ).fetchone()


def renewal_deadline(key: sqlite3.Row) -> str | None:
    """旧密钥版本的续签截止时间；早于本功能退役的密钥按退役时间加宽限期折算。"""
    if key["status"] != "retired":
        return None
    if key["renewal_deadline"]:
        return key["renewal_deadline"]
    if key["retired_at"]:
        return iso(parse_time(key["retired_at"]) + timedelta(days=RENEWAL_GRACE_DAYS))
    return None


def rotate_key(store, actor: str, issuer: str) -> dict:
    """轮换签发方密钥：退役当前版本并记录续签截止，再生成新的当前版本。"""
    conn = store.conn
    deadline = None
    with conn:
        old = conn.execute("SELECT * FROM key_versions WHERE issuer=? AND status='active'", (issuer,)).fetchone()
        version = 1
        if old:
            version = int(old["version"]) + 1
            deadline = iso(now() + timedelta(days=RENEWAL_GRACE_DAYS))
            conn.execute(
                "UPDATE key_versions SET status='retired', retired_at=?, renewal_deadline=? WHERE id=?",
                (iso(), deadline, old["id"]),
            )
        secret_hex = secrets.token_hex(32)
        cur = conn.execute(
            "INSERT INTO key_versions(issuer,version,secret_hex,status,created_at) VALUES(?,?,?,'active',?)",
            (issuer, version, secret_hex, iso()),
        )
        store.audit(actor, "key.rotate", "key_version", cur.lastrowid,
                    {"version": version, "retired_previous": bool(old), "renewal_deadline": deadline})
    return {
        "issuer": issuer, "version": version, "status": "active",
        "public_fingerprint": hashlib.sha256(secret_hex.encode()).hexdigest()[:20],
        "previous_renewal_deadline": deadline,
    }
