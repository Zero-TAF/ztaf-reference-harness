"""The ztaf-harness CLI: the visible front door of the framework.

    python -m ztaf_harness.cli demo   [--workdir DIR] [--seed HEX]
    python -m ztaf_harness.cli bootstrap --card CARD --profile PROFILE \
        --root-mandate MANDATE --key-seed HEX --kid KID [--out OUT]
    python -m ztaf_harness.cli audit-store --export EXPORT

The demo runs the full loop end to end: bootstrap an agent from an Agentic
Operations discovery card and profile, then evaluate three actions (permit,
escalation-with-approval, deny) and write the registry, the signed status
list, and the evidence export.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ztaf_evidence.store import EvidenceStore, EvidenceStore as _ES  # noqa: F401
from ztaf_mandate.keys import DictKeyProvider, generate_key, sign
from ztaf_mandate.mandate import body_of, mandate_hash, mint
from ztaf_mandate.canonical import digest
from ztaf_mandate.revocation import StatusChecker

from .ao import bootstrap, card_to_policy_fragment, load_discovery_card, load_profile
from .loop import DecisionPoint
from .policy import PolicyEngine

NOW = "2026-11-24T00:00:00Z"
ROOT_KID = "demo-operations-root"


def _parse_now(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def cmd_demo(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    seed = bytes.fromhex(args.seed) if args.seed else bytes.fromhex("de" * 32)
    now = _parse_now(NOW)
    examples = Path(__file__).resolve().parents[1] / "examples"

    # 1. The organisational root (operations principal -> payments desk).
    root_private, root_public = generate_key(seed)
    keys = DictKeyProvider({ROOT_KID: root_public})
    root = mint(root_private, {
        "zt_mandate_version": "0.1.0",
        "mandate_id": "ZT-MND-DEMO-ROOT",
        "mandate_version": 1,
        "issuer": "operations-director",
        "issuer_key_id": ROOT_KID,
        "subject": "payments-desk",
        "originator": "demo operations principal",
        "outcomes": ["operate the payments desk within policy"],
        "constraints": [
            {"type": "outcome-scope", "value": ["issue customer refunds within the payments policy"]},
            {"type": "resource-scope", "value": ["payments-api"]},
            {"type": "budget", "value": {"unit": "EUR", "amount": 5000}},
            {"type": "parameter-bound", "value": {"field": "amount", "op": "max", "bound": 500}},
        ],
        "escalation": {"threshold": "single refund above EUR 200", "channel": "oversight-desk"},
        "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"},
        "required_grade": "TG-2",
        "revocation": {"method": "status-list", "endpoint": "file:status-list.json"},
    })

    # 2. Bootstrap the agent from its Agentic Operations card and profile.
    card = load_discovery_card(examples / "card.json")
    profile = load_profile(examples / "profile.json")
    boot = bootstrap(card, profile, root_private, ROOT_KID, root, now)
    chain = [root, boot["mandate"]]
    subject = boot["registry_entry"]["subject"]

    # 3. Policy from the card (declared capabilities only), un-shadowed for
    # the demo; the grade register evidences TG-2 from the demo's own audit.
    classes, register = card_to_policy_fragment(card, default_shadow=False)
    policy = PolicyEngine({
        "zt_policy_version": "0.1.0",
        "decision_classes": classes,
        "grade_register": {k: "TG-2" for k in register},
        "deny_by_default": True,
        "agent_can_mutate_policy": False,
        "grade_sufficiency_enabled": True,
        "fail_closed_wiring": True,
    })

    # 4. Registry + signed status list (no revocations yet).
    registry = {
        "zt_registry_version": "0.1.0",
        "agents": {subject: boot["registry_entry"]},
        "mandates": {boot["registry_entry"]["mandate_id"]: {
            "mandate_hash": boot["registry_entry"]["mandate_hash"],
            "subject": subject, "status": "valid"}},
        "capabilities": {},
    }
    status_body = {"zt_status_version": "0.1.0", "updated": NOW,
                   "entries": {}, "issuer_key_id": ROOT_KID}
    status_list = {**status_body,
                   "issuer_signature": base64.b64encode(
                       sign(root_private, digest(status_body))).decode()}
    revocation = StatusChecker(status_list, root_public, now)

    # 5. The loop, over the demo actions.
    store = EvidenceStore()
    point = DecisionPoint(policy, keys, revocation, store)

    def oversight_demo(bundle: dict) -> str:
        return "approve"  # the demo approver; a real one rules in a UI, on the case

    oversight_demo.__name__ = "oversight-demo"
    actions = json.loads((examples / "actions.json").read_text())["actions"]
    print("Zero-TAF reference harness — demo run")
    print(f"  agent      : {subject} (bootstrapped from card {card['agent']['id']})")
    print(f"  chain      : {body_of(root)['mandate_id']} -> "
          f"{boot['registry_entry']['mandate_id']}")
    print(f"  classes    : {', '.join(sorted(policy.classes))}")
    print()
    for entry in actions:
        result = point.run(entry["action"], chain, now, subject, approver=oversight_demo)
        print(f"  {entry['name']}")
        for line in result.trace:
            print(f"    {line}")
        print(f"    verdict: {result.verdict} (enforced={result.enforced})")
        print()

    # 6. Persist the run.
    (workdir / "registry.json").write_text(json.dumps(registry, indent=2))
    (workdir / "status-list.json").write_text(json.dumps(status_list, indent=2))
    (workdir / "evidence-export.json").write_text(json.dumps(store.export(), indent=2))
    (workdir / "agent-mandate.json").write_text(json.dumps(boot["mandate"], indent=2))
    ok, reason = store.verify()
    print(f"  evidence   : {len(store.export()['records'])} records, chain verify "
          f"{'OK' if ok else 'FAILED: ' + str(reason)}")
    print(f"  written    : {workdir}/{{registry,status-list,evidence-export,agent-mandate}}.json")
    print("\nNext: ztaf-audit on a deployment bundle; ztaf-eval baseline/check on the export.")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    card = load_discovery_card(args.card)
    profile = load_profile(args.profile)
    root = json.loads(Path(args.root_mandate).read_text())
    private, _ = generate_key(bytes.fromhex(args.key_seed))
    boot = bootstrap(card, profile, private, args.kid, root, _parse_now(NOW))
    out = Path(args.out or "bootstrap.json")
    out.write_text(json.dumps(boot, indent=2))
    print(f"bootstrapped {boot['registry_entry']['subject']} -> {out}")
    return 0


def cmd_audit_store(args: argparse.Namespace) -> int:
    exported = json.loads(Path(args.export).read_text())
    ok, reason = EvidenceStore.verify_export(exported)
    head = exported.get("head", {})
    print(f"store : {head.get('record_count', '?')} records")
    print(f"chain : {'OK' if ok else 'FAILED — ' + str(reason)}")
    print(f"root  : {head.get('batch_root', '?')[:32]}…")
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ztaf-harness")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo", help="end-to-end demo: bootstrap + three decisions")
    d.add_argument("--workdir", default="ztaf-demo-run")
    d.add_argument("--seed", default=None, help="32-byte hex seed for the root key")
    d.set_defaults(func=cmd_demo)
    b = sub.add_parser("bootstrap", help="bootstrap an agent from card + profile + root mandate")
    b.add_argument("--card", required=True)
    b.add_argument("--profile", required=True)
    b.add_argument("--root-mandate", required=True)
    b.add_argument("--key-seed", required=True, help="32-byte hex seed of the issuer key")
    b.add_argument("--kid", required=True)
    b.add_argument("--out", default=None)
    b.set_defaults(func=cmd_bootstrap)
    a = sub.add_parser("audit-store", help="verify an evidence export's chain and head")
    a.add_argument("--export", required=True)
    a.set_defaults(func=cmd_audit_store)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
