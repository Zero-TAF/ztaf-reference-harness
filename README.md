# ztaf-reference-harness

The reference decision-point for the Zero-Trust Agent Framework: the runtime loop as a runnable reference, with a demo CLI and adapters for the **Agentic Operations** programme's three concepts.

| Field | Value |
|---|---|
| Authority | Reference implementation — normative behaviour: [ztaf-spec](https://github.com/Zero-TAF/ztaf-spec) (trust clauses), [ztaf-architecture](https://github.com/Zero-TAF/ztaf-architecture) (runtime loop, boundaries) |
| Tier | T4 (realization) |
| Wave | W4 |
| Version | 0.1.0 |
| Status | Active |
| Licence | MIT |

## What this repository owns

- `ztaf_harness/policy.py` — the policy engine and grade register: decision classes (AUT-1), escalation thresholds (AUT-5), grade sufficiency (ASM-2/SEC-13), shadow marking (ENF-8); refuses agent-mutable configuration (ENF-6).
- `ztaf_harness/loop.py` — the decision-point loop: resolve → verify → grade → evaluate → escalate (with evidence bundle, OVR-1) → broker (single-use post-authorisation credentials, SEC-3) → execute → record (EVD-6 ordering: the evidence is written before execution) → emit. Fail-closed at every marked point.
- `ztaf_harness/ao.py` — **Agentic Operations adapters**: discovery card → declared-capability policy fragment (CON-1); profile → mandate subject binding; bootstrap → chain issuance + registry entry + grade-register entry. See the mapping table in the module docstring; the reference card/profile JSON shapes are our proposal for the machine-readable layer the [Agentic-Operation](https://github.com/Agentic-Operation) definitions call for (lodging upstream is owner-gated).
- `ztaf_harness/cli.py` — `ztaf-harness demo | bootstrap | audit-store`.
- `examples/` — a discovery card, a profile, and three actions (permit / escalation / deny).
- `tests/` — 10 tests: permit, escalation-with-approval (three records: case, ruling, enforced execution), deny paths, grade insufficiency (SEC-13), shadow mode, config-honesty rejection, AO adapters including a chain-verified bootstrap.

## What this repository does not own

- Normative clauses — [ztaf-spec](https://github.com/Zero-TAF/ztaf-spec). Reference conformance policy — `ztaf-conformance` (Wave 5).
- The mandate chain and the evidence store — substrates: [ztaf-mandate](https://github.com/Zero-TAF/ztaf-mandate), [ztaf-evidence](https://github.com/Zero-TAF/ztaf-evidence).
- Registries and revocation services — [ztaf-registry](https://github.com/Zero-TAF/ztaf-registry) (the demo writes registry-shaped files; the registry reference owns the semantics).
- Real side effects — the executor is a pure simulator; wiring a real brokered call is a deployment concern behind boundary B3.

## Running

```bash
pip install -r requirements.txt     # cryptography + the two substrate references
# or, from a flat checkout of the estate: the tests add sibling paths themselves
python -m unittest discover -s tests -v        # 10 tests
python -m ztaf_harness.cli demo                # the end-to-end demo
```

The demo bootstraps `refund-agent-42` from the example card and profile, runs three decisions (permit at €150; escalation at €350 ruled on the bundle; deny for an undeclared tool), and writes `registry.json`, `status-list.json`, `evidence-export.json`, and `agent-mandate.json` — the exact artifacts the Wave-5 tools consume:

```
python -m ztaf_conformance.cli audit --bundle <your bundle>   # ztaf-conformance
python -m ztaf_evaluation.cli check --store evidence-export.json --baseline baseline.json
```

**Reference only** — no real side effects, no network, no persistence beyond the demo's JSON files.
