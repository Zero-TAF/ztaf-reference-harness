"""Adapters for the Agentic Operations organisation's three concepts.

The `Agentic-Operation` GitHub organisation defines — README-level, as of
2026-11-24 — three concepts for agents operating under Agentic Operations:

- **agent-discovery-card**: "Machine-readable discovery cards ... describing
  what an agent is, can do and under which constraints."
- **agent-profile-management**: "identity, capability declarations and
  operational metadata."
- **agent-bootstrap-management**: "onboarding, initialization and alignment
  with the operating model."

Those repositories currently carry the *definitions*; this module is the
Zero-TAF **trust realisation** of them (per ADR-ZTAF-0006's pattern: AO owns
the concept, Zero-TAF owns the trust semantics). The reference card/profile
shapes below are our proposal for the machine-readable layer those
definitions call for; lodging them upstream is an owner-gated, outward-facing
action (ADR-ZTAF-0004 rule 3).

Mapping:

| Agentic Operations concept | Zero-TAF realisation |
|---|---|
| discovery card "can do" | declared capabilities → decision classes (CON-1, ZT-CC-9) |
| discovery card "under which constraints" | parameter bounds + escalation thresholds (MAN-3, AUT-5) |
| profile "identity" | the mandate subject binding (IDE-1, MAN-5 step 6) |
| bootstrap "onboarding" | chain-root mandate → agent mandate issuance + registry entry + grade-register entry (MAN-1..4, ASM-2) |
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ztaf_mandate.constraints import grade_rank
from ztaf_mandate.keys import KeyProvider
from ztaf_mandate.mandate import body_of, mandate_hash, mint

CARD_VERSION = "0.1.0"


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def load_discovery_card(path: str | Path) -> dict:
    """Load and structurally validate an agent discovery card.

    Reference card shape (proposed to the Agentic Operations definition)::

        { "zt_card_version": "0.1.0",
          "agent": {"id": ..., "name": ..., "purpose": ...},
          "capabilities": [{"tool": ..., "operations": [...],
                            "constraints": {"parameter_bounds": [...],
                                             "escalation_above": {...}}}],
          "constraints": {"validity": {...}, "budget": {...}} }
    """
    card = load_json(path)
    if card.get("zt_card_version") != CARD_VERSION:
        raise ValueError(f"card version must be {CARD_VERSION}")
    agent = card.get("agent") or {}
    if not agent.get("id"):
        raise ValueError("card agent.id is required")
    caps = card.get("capabilities") or []
    if not caps:
        raise ValueError("card declares no capabilities — an agent that can do "
                         "nothing needs no mandate (CON-1)")
    for cap in caps:
        if not cap.get("tool") or not cap.get("operations"):
            raise ValueError("each capability needs tool and operations")
    return card


def load_profile(path: str | Path) -> dict:
    """Load an agent profile (Agentic Operations: identity + metadata)."""
    profile = load_json(path)
    if not (profile.get("agent_profile") or {}).get("id"):
        raise ValueError("profile agent_profile.id is required")
    return profile


def profile_to_subject(profile: dict) -> str:
    """Profile identity → the mandate subject (MAN-5 step 6)."""
    return profile["agent_profile"]["id"]


def card_to_policy_fragment(card: dict, min_grade: str = "TG-2",
                             default_shadow: bool = True) -> tuple[list[dict], dict]:
    """Discovery card → declared-capability policy fragment (CON-1).

    Returns (decision_classes, grade_register_fragment). Classes land
    shadow-marked by default: a card is a claim until Stage 4 of adoption
    proves it (ztaf-adoption methodology).
    """
    classes: list[dict] = []
    register: dict[str, str] = {}
    for cap in card["capabilities"]:
        constraints = cap.get("constraints") or {}
        for operation in cap["operations"]:
            class_id = f"{card['agent']['id']}.{cap['tool']}.{operation}"
            classes.append({
                "id": class_id,
                "tool": cap["tool"],
                "operation": operation,
                "parameter_bounds": constraints.get("parameter_bounds", []),
                "escalation": constraints.get("escalation_above"),
                "min_grade": constraints.get("min_grade", min_grade),
                "shadow": constraints.get("shadow", default_shadow),
            })
            register[class_id] = constraints.get("min_grade", min_grade)
    return classes, register


def bootstrap(
    card: dict,
    profile: dict,
    issuer_private,
    issuer_kid: str,
    root_mandate: dict,
    now: datetime,
    validity: Optional[dict] = None,
) -> dict:
    """Bootstrap an agent under Agentic Operations onto a Zero-TAF chain.

    Onboarding (the AO bootstrap concept) becomes: issue the agent's mandate
    as an attenuation of the organisational root, scoped by the card's
    declared capabilities and constraints, bound to the profile identity,
    with a grade-register entry derived from the card. Returns the mandate,
    the grade-register fragment, and a registry-ready entry.
    """
    subject = profile_to_subject(profile)
    constraint_types: list[dict] = [
        {"type": "outcome-scope", "value": [card["agent"].get("purpose", subject)]}
    ]
    tools = sorted({cap["tool"] for cap in card["capabilities"]})
    constraint_types.append({"type": "resource-scope", "value": tools})
    bounds: list[dict] = []
    maxes: list[int] = []
    for cap in card["capabilities"]:
        constraints = cap.get("constraints") or {}
        bounds.extend(constraints.get("parameter_bounds", []))
        esc = constraints.get("escalation_above")
        if esc and esc.get("op") == "max":
            maxes.append(esc["bound"])
    for b in bounds:
        constraint_types.append({"type": "parameter-bound", "value": b})
    if card.get("constraints", {}).get("budget"):
        constraint_types.append({"type": "budget",
                                 "value": card["constraints"]["budget"]})

    root_body = body_of(root_mandate)
    classes, register = card_to_policy_fragment(card)
    required = max((c.get("min_grade", "TG-0") for c in classes),
                   key=grade_rank, default="TG-2")

    body = {
        "zt_mandate_version": "0.1.0",
        "mandate_id": f"ZT-MND-{card['agent']['id']}",
        "mandate_version": 1,
        "issuer": root_body["subject"],
        "issuer_key_id": issuer_kid,
        "subject": subject,
        "parent": {"mandate_id": root_body["mandate_id"],
                   "mandate_hash": mandate_hash(root_mandate)},
        "outcomes": [card["agent"].get("purpose", "operate within declared capabilities")],
        "constraints": constraint_types,
        "escalation": {"threshold": f"max parameter bound of "
                                    f"{min(maxes) if maxes else 'the declared bounds'}",
                       "channel": "oversight-desk"},
        "validity": validity or root_body["validity"],
        "required_grade": required,
        "revocation": root_body["revocation"],
    }
    mandate = mint(issuer_private, body)
    registry_entry = {
        "subject": subject,
        "card": {"zt_card_version": card["zt_card_version"], "agent_id": card["agent"]["id"]},
        "mandate_id": body["mandate_id"],
        "mandate_hash": mandate_hash(mandate),
        "required_grade": required,
        "bootstrap": {"root_mandate_id": root_body["mandate_id"], "at": now.isoformat()},
    }
    return {"mandate": mandate, "grade_register": register, "registry_entry": registry_entry}
