import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ApiError, CredentialService, Store, iso, now
from key_rules import RENEWAL_GRACE_DAYS, KeyRules
from renewal import RenewalPolicy


class RenewalFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}], 365,
        )
        self.credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "degree": "BSc"}, "issue-1",
        )

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _rotate(self):
        return self.service.rotate_key("issuer-a", "issuer", "issuer-a")

    def test_pending_renewal_then_rejected_after_deadline(self):
        proof = self.service.present("alice", "holder", self.credential["id"], None)
        self._rotate()
        result = self.service.verify(proof["token"])
        self.assertTrue(result["valid"])
        self.assertEqual("pending_renewal", result["status"])
        self.assertIn("renew_by", result)
        overdue = self.service.verify(proof["token"], at=iso(now() + timedelta(days=RENEWAL_GRACE_DAYS + 1)))
        self.assertFalse(overdue["valid"])
        self.assertEqual("renewal_overdue", overdue["status"])
        expired = self.service.verify(proof["token"], at=iso(now() + timedelta(days=400)))
        self.assertEqual("expired", expired["status"])

    def test_holder_renewal_supersedes_old_and_issues_new_version(self):
        old_proof = self.service.present("alice", "holder", self.credential["id"], None)
        self._rotate()
        result = self.service.renew("alice", "holder", self.credential["id"])
        self.assertFalse(result["reused"])
        new_cred = result["new_credential"]
        self.assertEqual("active", new_cred["status"])
        self.assertEqual(2, new_cred["key_version"])
        self.assertEqual(self.credential["valid_until"], new_cred["valid_until"])
        self.assertEqual({"name": "Alice", "degree": "BSc"}, new_cred["claims"])
        old = result["old_credential"]
        self.assertEqual("superseded", old["status"])
        self.assertEqual(result["old_invalid_at"], old["renewal_invalid_at"])
        # 截止前旧令牌显示已换发但仍可验证
        still_ok = self.service.verify(old_proof["token"])
        self.assertTrue(still_ok["valid"])
        self.assertEqual("valid_until_supersession", still_ok["status"])
        self.assertEqual(new_cred["id"], still_ok["renewed_by_credential_id"])
        # 截止后拒绝
        late = self.service.verify(old_proof["token"], at=iso(now() + timedelta(days=RENEWAL_GRACE_DAYS + 1)))
        self.assertFalse(late["valid"])
        self.assertEqual("superseded", late["status"])
        # 新凭证按当前密钥正常验证
        new_proof = self.service.present("alice", "holder", new_cred["id"], None)
        self.assertEqual("valid", self.service.verify(new_proof["token"])["status"])
        # 同模板同持有人仍只有一张有效凭证
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", self.template["id"], "alice",
                               {"name": "Alice", "degree": "BSc"}, "issue-2")
        self.assertEqual(409, ctx.exception.status)

    def test_repeat_renewal_reuses_first_result(self):
        self._rotate()
        first = self.service.renew("alice", "holder", self.credential["id"])
        second = self.service.renew("issuer-a", "issuer", self.credential["id"])
        self.assertTrue(second["reused"])
        self.assertEqual(first["new_credential"]["id"], second["new_credential"]["id"])
        self.assertEqual(first["old_invalid_at"], second["old_invalid_at"])
        self.assertEqual("alice", second["requested_by"])
        again = self.service.renew("alice", "holder", self.credential["id"])
        self.assertTrue(again["reused"])
        self.assertEqual(first["renewal_id"], again["renewal_id"])

    def test_issuer_initiated_renewal(self):
        self._rotate()
        result = self.service.renew("issuer-a", "issuer", self.credential["id"])
        self.assertEqual("issuer-a", result["requested_by"])
        self.assertEqual(2, result["new_credential"]["key_version"])

    def test_renewal_blockers(self):
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("alice", "holder", self.credential["id"])
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("无需续签", ctx.exception.message)
        self._rotate()
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "测试撤销")
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("alice", "holder", self.credential["id"])
        self.assertIn("撤销", ctx.exception.message)
        self.service.dispute("alice", "holder", self.credential["id"], "撤销有误")
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("alice", "holder", self.credential["id"])
        self.assertIn("争议", ctx.exception.message)

    def test_renewal_permissions(self):
        self._rotate()
        with self.assertRaises(ApiError) as ctx:
            self.service.renew("bob", "holder", self.credential["id"])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.service.renew("issuer-b", "issuer", self.credential["id"])
        with self.assertRaises(ApiError):
            self.service.renew("reg-1", "regulator", self.credential["id"])
        with self.assertRaises(ApiError) as ctx:
            self.service.renew(None, "holder", self.credential["id"])
        self.assertEqual(401, ctx.exception.status)

    def test_chained_renewal_across_rotations(self):
        self._rotate()
        first = self.service.renew("alice", "holder", self.credential["id"])
        self._rotate()
        second = self.service.renew("issuer-a", "issuer", first["new_credential"]["id"])
        self.assertEqual(3, second["new_credential"]["key_version"])
        self.assertEqual("superseded", second["old_credential"]["status"])

    def test_renewal_visible_in_state(self):
        self._rotate()
        self.service.renew("alice", "holder", self.credential["id"])
        state = self.service.state()
        self.assertEqual(1, len(state["renewals"]))
        self.assertEqual(self.credential["id"], state["renewals"][0]["old_credential_id"])


class RenewalPolicyTest(unittest.TestCase):
    """不依赖数据库的续签判定。"""

    def setUp(self):
        self.policy = RenewalPolicy(KeyRules(None))

    def test_expired_credential_cannot_renew(self):
        credential = {"status": "active", "valid_until": iso(now() - timedelta(seconds=1))}
        blocker = self.policy.renewal_blocker(credential, {"status": "retired"}, now())
        self.assertEqual(409, blocker[0])
        self.assertIn("过期", blocker[1])

    def test_active_key_needs_no_renewal(self):
        credential = {"status": "active", "valid_until": iso(now() + timedelta(days=10))}
        blocker = self.policy.renewal_blocker(credential, {"status": "active"}, now())
        self.assertEqual(409, blocker[0])
        self.assertIn("无需续签", blocker[1])


if __name__ == "__main__":
    unittest.main()
