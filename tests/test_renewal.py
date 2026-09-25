import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ApiError, CredentialService, Store
from common import iso, parse_time


class RenewalFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}], 365)

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def issue_alice(self):
        return self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-1")

    def test_rotation_marks_pending_then_rejects_after_deadline(self):
        credential = self.issue_alice()
        proof = self.service.present("alice", "holder", credential["id"], None)
        self.assertEqual("valid", self.service.verify(proof["token"])["status"])
        rotated = self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        deadline = rotated["previous_renewal_deadline"]
        self.assertIsNotNone(deadline)
        # 截止前：旧令牌显示待续签但仍可验证
        before = self.service.verify(proof["token"])
        self.assertTrue(before["valid"])
        self.assertEqual("pending_renewal", before["status"])
        self.assertEqual(deadline, before["renewal_deadline"])
        # 截止后：拒绝
        after = self.service.verify(proof["token"], at=iso(parse_time(deadline) + timedelta(seconds=1)))
        self.assertFalse(after["valid"])
        self.assertEqual("renewal_overdue", after["status"])

    def test_renew_issues_new_version_and_supersedes_old(self):
        credential = self.issue_alice()
        old_proof = self.service.present("alice", "holder", credential["id"], None)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        renewed = self.service.renew("alice", "holder", credential["id"])
        self.assertFalse(renewed["replayed"])
        self.assertEqual(credential["id"], renewed["old_credential_id"])
        new_cred = renewed["new_credential"]
        self.assertEqual(2, new_cred["key_version"])
        self.assertEqual("active", new_cred["status"])
        self.assertEqual({"name": "Alice"}, new_cred["claims"])
        # 旧凭证写明失效时间
        old_cred = renewed["old_credential"]
        self.assertEqual("superseded", old_cred["status"])
        self.assertEqual(renewed["old_invalid_at"], old_cred["superseded_at"])
        # 续签关系可见
        relations = self.service.state()["renewals"]
        self.assertEqual(1, len(relations))
        self.assertEqual(credential["id"], relations[0]["old_credential_id"])
        self.assertEqual(new_cred["id"], relations[0]["new_credential_id"])
        # 旧令牌被拒绝并指向新凭证
        old_result = self.service.verify(old_proof["token"])
        self.assertFalse(old_result["valid"])
        self.assertEqual("superseded", old_result["status"])
        self.assertEqual(new_cred["id"], old_result["replaced_by"])
        # 新令牌有效
        new_proof = self.service.present("alice", "holder", new_cred["id"], None)
        self.assertEqual("valid", self.service.verify(new_proof["token"])["status"])
        # 换发后的新凭证占据同模板同持有人的唯一有效位置
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-2")
        self.assertEqual(409, ctx.exception.status)

    def test_renew_is_idempotent_and_issuer_can_renew(self):
        credential = self.issue_alice()
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        first = self.service.renew("issuer-a", "issuer", credential["id"])  # 签发方发起
        self.assertFalse(first["replayed"])
        self.assertEqual("issuer-a", first["requested_by"])
        second = self.service.renew("alice", "holder", credential["id"])  # 持有人重复申请
        self.assertTrue(second["replayed"])
        self.assertEqual(first["renewal_id"], second["renewal_id"])
        self.assertEqual(first["new_credential_id"], second["new_credential_id"])
        # 实际换发只审计一次
        renews = [a for a in self.service.state()["audits"] if a["action"] == "credential.renew"]
        self.assertEqual(1, len(renews))

    def test_renew_rejections(self):
        credential = self.issue_alice()
        with self.assertRaises(ApiError) as ctx:  # 未换版无需续签
            self.service.renew("alice", "holder", credential["id"])
        self.assertEqual(409, ctx.exception.status)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        with self.assertRaises(ApiError) as ctx:  # 缺少身份
            self.service.renew(None, None, credential["id"])
        self.assertEqual(401, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:  # 其他持有人
            self.service.renew("bob", "holder", credential["id"])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:  # 监管角色不能续签
            self.service.renew("reg-1", "regulator", credential["id"])
        self.assertEqual(403, ctx.exception.status)
        # 已过期凭证不能续签
        self.service.store.conn.execute(
            "UPDATE credentials SET valid_until=? WHERE id=?", ("2000-01-01T00:00:00Z", credential["id"]))
        self.service.store.conn.commit()
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("issuer-a", "issuer", credential["id"])
        self.assertEqual(409, ctx.exception.status)

    def test_revoked_or_disputed_cannot_renew(self):
        credential = self.issue_alice()
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.service.revoke("issuer-a", "issuer", credential["id"], "误发")
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("issuer-a", "issuer", credential["id"])
        self.assertEqual(409, ctx.exception.status)
        self.service.dispute("alice", "holder", credential["id"], "撤销依据错误")
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("alice", "holder", credential["id"])
        self.assertEqual(409, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
