"""ztaf-reference-harness: the Zero-TAF reference decision point.

Reference only. The normative behaviour lives in ztaf-spec (trust clauses)
and ztaf-architecture (runtime loop, boundaries, topologies). This package
implements the loop over the ztaf-mandate and ztaf-evidence substrates and
adapts the Agentic Operations discovery-card, profile, and bootstrap
concepts.
"""

from .loop import DecisionPoint, LoopResult
from .policy import PolicyEngine, PolicyError, is_shadow

__version__ = "0.1.0"
