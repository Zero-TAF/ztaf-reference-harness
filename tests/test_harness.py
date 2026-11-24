"""Harness loop + Agentic Operations adapter tests (run from repo root)."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sibling in ("ztaf-mandate", "ztaf-evidence"):
    sibling_path = ROOT.parent / sibling
    if sibling_path.exists():
        sys.path.insert(0, str(sibling_path))
sys.path.insert(0, str(ROOT))

from ztaf_evidence.store import EvidenceStore  # noqa: E402
from ztaf_mandate.keys import DictKeyProvider, generate_key  # noqa: E402
from ztaf_mandate.mandate import body_of, mandate_hash, mint  # noqa: E402

from ztaf_harness.ao import (  # noqa: E402
    bootstrap, card_to_policy_fragment, load_discovery_card, load_profile,
    profile_to_subject,
)
from ztaf_harness.loop import DecisionPoint  # noqa: E402
from ztaf_harness.policy import PolicyEngine, validate_policy  # noqa: E402

NOW = datetime.fromisoformat("2026-11-24T00:00:00+00:00")
KID = "test-operations-root"


def build_world(min_grade="TG-2", evidenced="TG-2", shadow=False):
    private, public = generate_key(bytes.fromhex("aa" * 32))
    keys = DictKeyProvider({KID: public})
    root = mint(private, {
        "zt_mandate_version": "0.1.0",
        "mandate_id": "ZT-MND-T-ROOT",
        "mandate_version": 1,
        "issuer": "operations-director",
        "issuer_key_id": KID,
        "subject": "payments-desk",
        "originator": "test operations principal",
        "outcomes": ["issue customer refunds within the payments policy"],
        "constraints": [
            {"type": "outcome-scope", "value": ["issue customer refunds within the payments policy"]},
            {"type": "resource-scope", "value": ["payments-api"]},
            {"type": "budget", "value": {"unit": "EUR", "amount": 5000}},
            {"type": "parameter-bound", "value": {"field": "amount", "op": "max", "bound": 500}},
        ],
        "escalation": {"threshold": "single refund above EUR 200", "channel": "oversight"},
        "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"},
        "required_grade": min_grade,
        "revocation": {"method": "status-list", "endpoint": "file:test"},
    })
    card = load_discovery_card(ROOT / "examples" / "card.json")
    profile = load_profile(ROOT / "examples" / "profile.json")
    boot = bootstrap(card, profile, private, KID, root, NOW)
    chain = [root, boot["mandate"]]
    classes, register = card_to_policy_fragment(card, default_shadow=False)
    for c in classes:
        if shadow:
            c["shadow"] = True
    policy = PolicyEngine({
        "zt_policy_version": "0.1.0",
        "decision_classes": classes,
        "grade_register": {k: evidenced for k in register},
        "deny_by_default": True,
        "agent_can_mutate_policy": False,
        "grade_sufficiency_enabled": True,
        "fail_closed_wiring": True,
    })
    store = EvidenceStore()
    point = DecisionPoint(policy, keys, lambda mid: False, store)
    subject = profile_to_subject(profile)
    return point, chain, subject, store, boot


class TestLoop(unittest.TestCase):
    def test_permit_within_bounds(self):
        point, chain, subject, store, _ = build_world()
        result = point.run({"tool": "payments-api", "operation": "refund",
                            "parameters": {"amount": 150}}, chain, NOW, subject)
        self.assertEqual(result.verdict, "permit")
        self.assertTrue(result.enforced)
        self.assertIsNotNone(result.credential)
        self.assertTrue(result.credential["issued_after_authorisation"])
        self.assertEqual(len(store.export()["records"]), 1)
        ok, _ = store.verify()
        self.assertTrue(ok)

    def test_escalation_produces_bundle_and_approval(self):
        point, chain, subject, store, _ = build_world()

        def oversight(bundle):  # rules on the case, not a prompt
            return "approve"
        oversight.__name__ = "oversight-test"
        result = point.run({"tool": "payments-api", "operation": "refund",
                            "parameters": {"amount": 350}}, chain, NOW, subject,
                           approver=oversight)
        self.assertEqual(result.verdict, "approve")
        self.assertIsNotNone(result.bundle)
        records = store.export()["records"]
        # Three records: the escalation case, the human ruling, and the
        # enforced execution (EVD-1: every decision is a record).
        self.assertEqual([r["decision"] for r in records], ["escalate", "approve", "permit"])
        self.assertEqual(records[0]["evidence_bundle_hash"], result.bundle["bundle_hash"])
        self.assertEqual(records[1]["approver"], "oversight-test")
        self.assertEqual(records[2]["approver"], "oversight-test")

    def test_escalation_without_approver_stops_at_escalate(self):
        point, chain, subject, store, _ = build_world()
        result = point.run({"tool": "payments-api", "operation": "refund",
                            "parameters": {"amount": 350}}, chain, NOW, subject)
        self.assertEqual(result.verdict, "escalate")
        self.assertEqual(result.record["decision"], "escalate")

    def test_deny_no_decision_class(self):
        point, chain, subject, store, _ = build_world()
        result = point.run({"tool": "crm-api", "operation": "lookup",
                            "parameters": {}}, chain, NOW, subject)
        self.assertEqual(result.verdict, "deny")
        self.assertIn("no decision class", " ".join(result.trace))

    def test_deny_grade_insufficiency(self):
        point, chain, subject, store, _ = build_world(min_grade="TG-2", evidenced="TG-1")
        result = point.run({"tool": "payments-api", "operation": "refund",
                            "parameters": {"amount": 100}}, chain, NOW, subject)
        self.assertEqual(result.verdict, "deny")
        self.assertIn("GRADE", " ".join(result.trace))
        self.assertTrue(any(r["rule_applied"] == "POL-GRADE-INSUFFICIENT"
                            for r in store.export()["records"]))

    def test_shadow_mode_records_but_does_not_enforce(self):
        point, chain, subject, store, _ = build_world(shadow=True)
        result = point.run({"tool": "payments-api", "operation": "refund",
                            "parameters": {"amount": 150}}, chain, NOW, subject)
        self.assertFalse(result.enforced)
        self.assertEqual(result.verdict, "permit")

    def test_policy_rejects_agent_mutable_config(self):
        with self.assertRaises(Exception):
            validate_policy({"zt_policy_version": "0.1.0",
                             "decision_classes": [{"id": "x", "tool": "t", "operation": "o"}],
                             "grade_register": {"x": "TG-1"},
                             "deny_by_default": True,
                             "agent_can_mutate_policy": True,
                             "grade_sufficiency_enabled": True,
                             "fail_closed_wiring": True})


class TestAgenticOperationsAdapters(unittest.TestCase):
    def test_card_loads_and_fragment_maps(self):
        card = load_discovery_card(ROOT / "examples" / "card.json")
        classes, register = card_to_policy_fragment(card)
        self.assertEqual(len(classes), 1)
        self.assertEqual(classes[0]["id"], "refund-agent-42.payments-api.refund")
        self.assertEqual(classes[0]["escalation"]["bound"], 200)
        self.assertIn(classes[0]["id"], register)

    def test_profile_subject_binding(self):
        profile = load_profile(ROOT / "examples" / "profile.json")
        self.assertEqual(profile_to_subject(profile), "refund-agent-42")

    def test_bootstrap_mandate_verifies_in_chain(self):
        from ztaf_mandate.chain import verify_chain
        private, public = generate_key(bytes.fromhex("bb" * 32))
        keys = DictKeyProvider({KID: public})
        root = mint(private, {
            "zt_mandate_version": "0.1.0",
            "mandate_id": "ZT-MND-T-ROOT2",
            "mandate_version": 1,
            "issuer": "operations-director",
            "issuer_key_id": KID,
            "subject": "payments-desk",
            "originator": "test operations principal",
            "outcomes": ["issue customer refunds within the payments policy"],
            "constraints": [
                {"type": "outcome-scope", "value": ["issue customer refunds within the payments policy"]},
                {"type": "resource-scope", "value": ["payments-api"]},
                {"type": "budget", "value": {"unit": "EUR", "amount": 5000}},
                {"type": "parameter-bound", "value": {"field": "amount", "op": "max", "bound": 500}},
            ],
            "escalation": {"threshold": "refund above EUR 200", "channel": "oversight"},
            "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"},
            "required_grade": "TG-2",
            "revocation": {"method": "status-list", "endpoint": "file:test"},
        })
        card = load_discovery_card(ROOT / "examples" / "card.json")
        profile = load_profile(ROOT / "examples" / "profile.json")
        boot = bootstrap(card, profile, private, KID, root, NOW)
        result = verify_chain([root, boot["mandate"]], keys, NOW, lambda m: False,
                              subject=profile_to_subject(profile))
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(boot["registry_entry"]["required_grade"], "TG-2")


if __name__ == "__main__":
    unittest.main()
