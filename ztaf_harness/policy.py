"""The policy engine and grade register (operator configuration, ENF-6).

The policy declares decision classes (AUT-1), their five-axis-driven
minimum grade (AUT-3), escalation thresholds, and shadow marking (ENF-8).
The grade register holds the evidenced grade per class (ASM-2); the
sufficiency check (SEC-13) compares them per action. This file is operator
configuration: the agent has no write path to it.
"""

from __future__ import annotations

from typing import Any, Optional

from ztaf_mandate.constraints import grade_rank

POLICY_VERSION = "0.1.0"


class PolicyError(Exception):
    pass


def validate_policy(policy: dict) -> None:
    if policy.get("zt_policy_version") != POLICY_VERSION:
        raise PolicyError(f"policy version must be {POLICY_VERSION}")
    if not policy.get("decision_classes"):
        raise PolicyError("policy declares no decision classes (AUT-1)")
    if not policy.get("deny_by_default", False):
        raise PolicyError("policy MUST be deny-by-default (SEC-10)")
    if policy.get("agent_can_mutate_policy", False):
        raise PolicyError("agent_can_mutate_policy MUST be false (ENF-6, CC-6)")
    if not policy.get("grade_sufficiency_enabled", False):
        raise PolicyError("grade_sufficiency_enabled MUST be true (SEC-13, CC-7)")
    if not policy.get("fail_closed_wiring", False):
        raise PolicyError("fail_closed_wiring MUST be true (ENF-3, CC-14)")
    register = policy.get("grade_register")
    if not isinstance(register, dict) or not register:
        raise PolicyError("grade_register must map decision classes to evidenced grades (ASM-2)")


class PolicyEngine:
    def __init__(self, policy: dict):
        validate_policy(policy)
        self.policy = policy
        self.classes = {c["id"]: c for c in policy["decision_classes"]}
        self.grade_register = policy["grade_register"]

    def resolve(self, tool: str, operation: str) -> Optional[dict]:
        """Step 1 of the runtime loop: resolve the decision class (AUT-1)."""
        for c in self.classes.values():
            if c.get("tool") == tool and c.get("operation") == operation:
                return c
        return None

    def grade_suffices(self, decision_class: dict) -> tuple[bool, str, str]:
        """Step 3: required minimum grade vs evidenced grade (ASM-2, SEC-13)."""
        required = decision_class.get("min_grade", "TG-0")
        evidenced = self.grade_register.get(decision_class["id"])
        if evidenced is None:
            return False, required, "unregistered"
        return grade_rank(evidenced) >= grade_rank(required), required, evidenced

    def evaluate_bounds(self, decision_class: dict, parameters: dict) -> tuple[str, Optional[dict]]:
        """Steps 4a/4b: escalation threshold first, then hard bounds.

        Returns ("escalate", bound) when the escalation threshold is
        exceeded, ("deny", bound) when a hard bound is violated, and
        ("permit", None) otherwise.
        """
        escalation = decision_class.get("escalation")
        if escalation and _violates(escalation, parameters):
            return "escalate", escalation
        for bound in decision_class.get("parameter_bounds", []):
            if _violates(bound, parameters):
                if escalation and bound.get("field") == escalation.get("field"):
                    return "escalate", bound
                return "deny", bound
        return "permit", None


def _violates(bound: dict, parameters: dict) -> bool:
    field, op, b = bound.get("field"), bound.get("op"), bound.get("bound")
    if field not in parameters:
        return False
    value = parameters[field]
    if op == "max":
        return value > b
    if op == "min":
        return value < b
    if op == "set":
        return value not in set(b)
    raise PolicyError(f"unknown bound op: {op}")


# Shadow marking is a property of a class (ENF-8, ZT-ARC-7).
def is_shadow(decision_class: dict) -> bool:
    return bool(decision_class.get("shadow", False))
