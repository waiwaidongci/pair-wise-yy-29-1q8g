"""续签判定：换发资格、旧凭证失效时间与旧版本令牌的验证结论。

判定逻辑与 HTTP 解耦：资格问题以 (status, message) 返回，由调用方转成 ApiError。
"""
from __future__ import annotations

import sqlite3
from datetime import datetime

from key_rules import KeyRules, iso_timestamp, parse_timestamp


class RenewalPolicy:
    def __init__(self, keys: KeyRules):
        self.keys = keys

    def renewal_blocker(self, credential: sqlite3.Row, key: sqlite3.Row, at: datetime) -> tuple[int, str] | None:
        """返回 (status, message) 表示不能续签的原因；None 表示可以续签。"""
        status = credential["status"]
        if status == "superseded":
            return (409, "凭证已换发，请使用新凭证")
        if status == "revoked":
            return (409, "凭证已撤销，不能续签")
        if status == "disputed":
            return (409, "凭证存在未决争议，处理前不能续签")
        if at >= parse_timestamp(credential["valid_until"]):
            return (409, "凭证已过期，不能续签")
        if not self.keys.rotation_pending(key):
            return (409, "密钥尚未轮换，无需续签")
        return None

    def old_credential_invalid_at(self, credential: sqlite3.Row, key: sqlite3.Row) -> datetime:
        """旧凭证失效时间：凭证自身有效期与密钥续签宽限截止的较早者。"""
        expiry = parse_timestamp(credential["valid_until"])
        deadline = self.keys.renewal_deadline(key)
        return min(expiry, deadline) if deadline else expiry

    def verification_conclusion(self, credential: sqlite3.Row, key: sqlite3.Row, at: datetime) -> dict | None:
        """已换发或旧密钥凭证的验证状态结论；无续签相关结论时返回 None。"""
        if credential["status"] == "superseded":
            invalid_at = parse_timestamp(credential["renewal_invalid_at"])
            if at >= invalid_at:
                return {
                    "valid": False,
                    "status": "superseded",
                    "reason": "旧凭证已换发，超过失效时间",
                    "superseded_at": credential["renewal_invalid_at"],
                }
            return {
                "status": "valid_until_supersession",
                "superseded_at": credential["renewal_invalid_at"],
                "reason": "旧凭证已换发，失效前仍可验证",
            }
        deadline = self.keys.renewal_deadline(key)
        if deadline is None:
            return None
        if at >= deadline:
            return {
                "valid": False,
                "status": "renewal_overdue",
                "reason": "密钥已轮换，续签宽限期已过",
                "renew_by": iso_timestamp(deadline),
            }
        return {
            "status": "pending_renewal",
            "renew_by": iso_timestamp(deadline),
            "reason": "密钥已轮换，凭证待续签",
        }
