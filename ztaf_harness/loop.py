"""The decision-point runtime loop (ztaf-architecture, runtime loop document).

One loop per action: resolve → mint/verify → evaluate → grade sufficiency →
escalation → authorise/broker → execute → record → emit. Fail-closed at
every marked point. The agent plane enters with a proposal and receives a
verdict plus, on permit, a single-use scoped credential (ENF-5) — nothing
else crosses boundary B1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from ztaf_evidence.bundle import assemble as assemble_bundle
from ztaf_evidence.store import EvidenceStore
from ztaf_mandate.chain import RevocationChecker, verify_chain
from ztaf_mandate.keys import KeyProvider

from .policy import PolicyEngine, is_shadow

# The reference executor: pure simulation, no side effects. A real
# deployment replaces this with the brokered call (B3).
Executor = Callable[[dict, dict], dict]
Approver = Callable[[dict], str]  # bundle -> "approve" | "deny"


@dataclass
class LoopResult:
    verdict: str                 # permit | deny | escalate | approve
    enforced: bool               # False only in shadow mode (ENF-8)
    trace: list = field(default_factory=list)
    record: Optional[dict] = None
    approval_record: Optional[dict] = None
    bundle: Optional[dict] = None
    credential: Optional[dict] = None


def _record(store: EvidenceStore, *, action, decision_class, rule, decision,
            chain_hash, task_identity, now, required, evidenced,
            approver=None, bundle=None) -> dict:
    """Append a decision record; an evidence-write failure fails the action
    closed (EVD-6)."""
    rec = {
        "zt_record_version": "0.1.0",
        "record_id": f"rec-{now.strftime('%Y%m%d%H%M%S')}-{abs(hash((chain_hash, rule, decision))) % 100000:05d}",
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "task_identity": task_identity,
        "mandate_id": chain_hash and _mandate_id_of(chain_hash),
        "mandate_hash": chain_hash,
        "decision_class": decision_class,
        "action": action,
        "rule_applied": rule,
        "decision": decision,
        "required_grade": required,
        "evidenced_grade": evidenced,
    }
    if approver:
        rec["approver"] = approver
    if bundle:
        rec["evidence_bundle_hash"] = bundle["bundle_hash"]
    store.append(rec)  # raises -> the caller treats the action as not-happened
    return rec


def _mandate_id_of(chain_hash: str) -> str:
    return f"chain:{chain_hash[:24]}"


class DecisionPoint:
    def __init__(
        self,
        policy: PolicyEngine,
        keys: KeyProvider,
        revocation: RevocationChecker,
        store: EvidenceStore,
        executor: Optional[Executor] = None,
    ):
        self.policy = policy
        self.keys = keys
        self.revocation = revocation
        self.store = store
        self.executor = executor or (lambda action, credential: {
            "executed": True, "tool": action["tool"], "operation": action["operation"]
        })

    def run(self, action: dict, chain: list, now: datetime, subject: str,
            approver: Optional[Approver] = None) -> LoopResult:
        trace: list[str] = []
        parameters = action.get("parameters", {})

        # 1. RESOLVE (AUT-1)
        decision_class = self.policy.resolve(action["tool"], action["operation"])
        if decision_class is None:
            trace.append("1 RESOLVE: no decision class — deny (deny-by-default, SEC-10)")
            return LoopResult("deny", True, trace)

        # 2. MINT/VERIFY (MAN-5, SEC-4)
        chain_result = verify_chain(chain, self.keys, now, self.revocation, subject=subject)
        if not chain_result.ok:
            trace.append(f"2 VERIFY: chain failed — deny ({chain_result.reason})")
            rec = self._try_record(action, decision_class["id"], "POL-CHAIN-FAIL", "deny",
                                   "unverified", now, trace)
            return LoopResult("deny", True, trace, rec)

        # 3. GRADE SUFFICIENCY (ASM-2, SEC-13)
        suffices, required, evidenced = self.policy.grade_suffices(decision_class)
        if not suffices:
            trace.append(f"3 GRADE: class requires {required}, deployment evidences "
                         f"{evidenced} — deny/escalate (SEC-13)")
            rec = self._try_record(action, decision_class["id"], "POL-GRADE-INSUFFICIENT",
                                   "deny", chain_result.leaf_hash, now, trace,
                                   required=required, evidenced=evidenced)
            return LoopResult("deny", True, trace, rec)
        trace.append(f"2 VERIFY: chain OK ({chain_result.leaf_hash[:24]}…)")
        trace.append(f"3 GRADE: {required} ≤ evidenced {evidenced} — sufficient")

        # 4. EVALUATE bounds and escalation threshold (ENF-2, AUT-5)
        verdict, bound = self.policy.evaluate_bounds(decision_class, parameters)
        shadow = is_shadow(decision_class)
        rule = decision_class["id"]

        if verdict == "escalate":
            bundle = assemble_bundle(
                context={
                    "decision_class": decision_class["id"],
                    "matched_rule": f"escalation threshold on {bound['field']} "
                                    f"({bound.get('op')} {bound.get('bound')})",
                    "proposed_action": action,
                    "options": ["approve", "deny"],
                    "provenance": {"mandate_hash": chain_result.leaf_hash,
                                   "task_identity": subject},
                },
                bundle_id=f"bundle-{now.strftime('%Y%m%d%H%M%S')}",
                created=now.isoformat().replace("+00:00", "Z"),
            )
            trace.append(f"4 EVALUATE: threshold exceeded — escalate with bundle "
                         f"{bundle['bundle_hash'][:20]} (OVR-1)")
            rec = _record(self.store, action=action, decision_class=decision_class["id"],
                          rule=rule, decision="escalate", chain_hash=chain_result.leaf_hash,
                          task_identity=subject, now=now, required=required,
                          evidenced=evidenced, bundle=bundle)
            if approver is not None:
                ruling = approver(bundle)
                if ruling == "approve":
                    approval = _record(self.store, action=action,
                                       decision_class=decision_class["id"],
                                       rule=f"{rule}/approval", decision="approve",
                                       chain_hash=chain_result.leaf_hash,
                                       task_identity=subject, now=now,
                                       required=required, evidenced=evidenced,
                                       approver=getattr(approver, "__name__", "approver"))
                    trace.append("5 OVERSIGHT: approved on the bundle — proceed (OVR-4)")
                    return self._permit(action, decision_class, chain_result, now, subject,
                                        trace, required, evidenced, shadow,
                                        approval_record=approval, bundle=bundle)
                trace.append("5 OVERSIGHT: denied — stop")
                return LoopResult("deny", not shadow, trace, rec, bundle=bundle)
            return LoopResult("escalate", not shadow, trace, rec, bundle=bundle)

        if verdict == "deny":
            trace.append(f"4 EVALUATE: hard bound violated ({bound['field']}) — deny")
            rec = self._try_record(action, decision_class["id"], f"{rule}/bound",
                                   "deny", chain_result.leaf_hash, now, trace,
                                   required=required, evidenced=evidenced)
            return LoopResult("deny", not shadow, trace, rec)

        trace.append(f"4 EVALUATE: within bounds — permit ({'SHADOW' if shadow else 'enforced'})")
        return self._permit(action, decision_class, chain_result, now, subject,
                            trace, required, evidenced, shadow)

    def _permit(self, action, decision_class, chain_result, now, subject,
                trace, required, evidenced, shadow, approval_record=None, bundle=None):
        # 6. AUTHORISE/BROKER (ENF-5, SEC-3): credential after authorisation,
        # scoped to the class, single-use.
        credential = {
            "credential_id": f"cred-{now.strftime('%Y%m%d%H%M%S%f')}",
            "scope": decision_class["id"],
            "issued_after_authorisation": True,
            "single_use": True,
            "persisted": False,
        }
        trace.append("6 BROKER: single-use scoped credential issued post-authorisation")

        # 7. EXECUTE — only after the evidence is written (EVD-6 ordering).
        record = _record(self.store, action=action, decision_class=decision_class["id"],
                         rule=decision_class["id"], decision="permit",
                         chain_hash=chain_result.leaf_hash, task_identity=subject,
                         now=now, required=required, evidenced=evidenced,
                         approver=approval_record["approver"] if approval_record else None)
        outcome = self.executor(action, credential)
        trace.append(f"7 EXECUTE: {outcome}")

        # 8/9. EMIT: transparency anchoring (TG-3+) and the behavioural
        # verification tap happen out-of-band; the record is already sealed.
        return LoopResult("approve" if approval_record else "permit",
                          not shadow, trace, record, approval_record, bundle, credential)

    def _try_record(self, action, class_id, rule, decision, chain_hash, now, trace,
                    required=None, evidenced=None):
        """Best-effort record on early denials; a broken store must not mask
        the deny itself."""
        try:
            return _record(self.store, action=action, decision_class=class_id, rule=rule,
                           decision=decision, chain_hash=chain_hash,
                           task_identity=action.get("parameters", {}).get("subject", "unknown"),
                           now=now, required=required or "TG-0", evidenced=evidenced or "TG-0")
        except Exception as exc:  # EVD-6: the store is down; the action is dead
            trace.append(f"EVIDENCE: write failed ({exc}) — action did not happen")
            return None
