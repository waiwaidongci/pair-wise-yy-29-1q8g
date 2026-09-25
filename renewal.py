"""续签判定：换发资格、续签关系与验证时的状态结论。"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

import keys
from common import ApiError, iso, now, parse_time
from store import credential_dict, get_row


def find_renewal(conn: sqlite3.Connection, old_credential_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM renewals WHERE old_credential_id=?", (old_credential_id,)).fetchone()


def status_conclusion(conn: sqlite3.Connection, credential: sqlite3.Row, key: sqlite3.Row, check_at: datetime) -> dict | None:
    """未过期、未撤销、无争议凭证在续签视角下的状态结论；无需续签处理时返回 None。"""
    status = credential["status"]
    if status == "superseded":
        superseded_at = parse_time(credential["superseded_at"])
        if check_at >= superseded_at:
            rel = find_renewal(conn, credential["id"])
            return {
                "valid": False, "status": "superseded",
                "reason": "旧凭证已换发新版本，请出示新凭证",
                "superseded_at": credential["superseded_at"],
                "replaced_by": rel["new_credential_id"] if rel else None,
            }
        status = "active"  # 失效时间之前的历史验证按当时状态判定
    if status == "active" and key["status"] == "retired":
        deadline = keys.renewal_deadline(key)
        if deadline and check_at >= parse_time(deadline):
            return {
                "valid": False, "status": "renewal_overdue",
                "reason": "旧密钥版本已过续签截止时间",
                "renewal_deadline": deadline,
            }
        return {"valid": True, "status": "pending_renewal", "renewal_deadline": deadline}
    return None


def renew(store, actor: str | None, role: str | None, credential_id: int) -> dict:
    """为未过期且无争议的旧版本凭证换发当前密钥版本，并写明旧凭证失效时间。"""
    conn = store.conn
    credential = get_row(conn, "credentials", credential_id)
    existing = find_renewal(conn, credential_id)
    if existing:  # 同一旧凭证重复申请沿用首次结果
        return _renewal_result(conn, existing, replayed=True)
    if not actor:
        raise ApiError(401, "缺少身份")
    is_holder = role == "holder" and actor == credential["holder_id"]
    is_issuer = role == "issuer" and actor == credential["issuer"]
    if not (is_holder or is_issuer):
        raise ApiError(403, "只有持有人或签发方可以续签")
    if credential["status"] == "disputed":
        raise ApiError(409, "争议中的凭证不能续签")
    if credential["status"] == "revoked":
        raise ApiError(409, "已撤销的凭证不能续签")
    if credential["status"] != "active":
        raise ApiError(409, "只有有效凭证可以续签")
    if parse_time(credential["valid_until"]) <= now():
        raise ApiError(409, "已过期凭证不能续签")
    key = keys.active_key(conn, credential["issuer"])
    if int(credential["key_version"]) == int(key["version"]):
        raise ApiError(409, "凭证已使用当前密钥版本，无需续签")
    template = get_row(conn, "templates", credential["template_id"])
    old_key = keys.key_version(conn, credential["issuer"], credential["key_version"])
    deadline = keys.renewal_deadline(old_key) if old_key else None
    renewed_at = now()
    valid_until = renewed_at + timedelta(days=int(template["validity_days"]))
    try:
        with conn:
            # 同一事务内先让旧凭证退出“同模板同持有人唯一有效”集合，再写入新版本。
            conn.execute(
                "UPDATE credentials SET status='superseded', superseded_at=? WHERE id=?",
                (iso(renewed_at), credential_id),
            )
            cur = conn.execute(
                """INSERT INTO credentials(template_id,issuer,holder_id,claims_json,issued_at,valid_until,status,key_version,idempotency_key)
                   VALUES(?,?,?,?,?,?,'active',?,?)""",
                (
                    credential["template_id"], credential["issuer"], credential["holder_id"], credential["claims_json"],
                    iso(renewed_at), iso(valid_until), key["version"], f"renew:{credential_id}",
                ),
            )
            new_credential_id = cur.lastrowid
            cur = conn.execute(
                """INSERT INTO renewals(old_credential_id,new_credential_id,requested_by,requested_at,old_invalid_at,renewal_deadline)
                   VALUES(?,?,?,?,?,?)""",
                (credential_id, new_credential_id, actor, iso(renewed_at), iso(renewed_at), deadline),
            )
            store.audit(actor, "credential.renew", "credential", credential_id, {
                "renewal_id": cur.lastrowid, "new_credential_id": new_credential_id,
                "old_invalid_at": iso(renewed_at), "renewal_deadline": deadline,
            })
    except sqlite3.IntegrityError:
        existing = find_renewal(conn, credential_id)
        if existing:  # 并发重复申请，沿用首次结果
            return _renewal_result(conn, existing, replayed=True)
        raise ApiError(409, "续签冲突，请重试")
    return _renewal_result(conn, get_row(conn, "renewals", cur.lastrowid), replayed=False)


def _renewal_result(conn: sqlite3.Connection, rel: sqlite3.Row, replayed: bool) -> dict:
    return {
        "renewal_id": rel["id"],
        "old_credential_id": rel["old_credential_id"],
        "new_credential_id": rel["new_credential_id"],
        "requested_by": rel["requested_by"],
        "requested_at": rel["requested_at"],
        "old_invalid_at": rel["old_invalid_at"],
        "renewal_deadline": rel["renewal_deadline"],
        "replayed": replayed,
        "old_credential": credential_dict(get_row(conn, "credentials", rel["old_credential_id"])),
        "new_credential": credential_dict(get_row(conn, "credentials", rel["new_credential_id"])),
    }
