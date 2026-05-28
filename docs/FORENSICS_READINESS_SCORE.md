# Forensics Readiness Score (FRS)

The Forensics Readiness Score (FRS) is a 5-level model for evaluating an organization's ability to perform DFIR on ephemeral CI/CD environments and AI/agentic systems.

## The five levels

### Level 1 — Reactive (Not Ready)

- Logs exist but are not centralized
- No tamper-evident logging
- Investigation requires manual log retrieval from individual systems
- No standard investigation playbooks
- **Typical investigation time:** Days to weeks

### Level 2 — Aware (Foundational)

- Centralized logging exists (SIEM or equivalent)
- Logs are searchable but not tamper-evident
- Some investigation playbooks exist (network, endpoint)
- No specialized playbooks for CI/CD or AI systems
- **Typical investigation time:** 1-3 days

### Level 3 — Prepared (Defined)

- Tamper-evident logging (append-only, signed)
- Specialized playbooks for CI/CD incidents
- Evidence retention policy documented and enforced
- Cross-team incident response coordination defined
- **Typical investigation time:** 4-24 hours

### Level 4 — Proactive (Measured)

- Continuous evidence integrity verification
- Specialized playbooks for AI/agentic system incidents (Five Forensic Questions framework integrated)
- Automated forensic data collection at incident detection
- Investigation metrics tracked (time-to-cause, time-to-remediation)
- **Typical investigation time:** 1-4 hours

### Level 5 — Adaptive (Optimizing)

- Forensic readiness designed into system architecture (not retrofitted)
- Cryptographic chain of custody for all evidence
- Real-time forensic timeline reconstruction
- Continuous improvement based on incident metrics
- **Typical investigation time:** Minutes to 1 hour

## Scoring methodology

Score each of these dimensions 1–5:

| Dimension | Description |
|---|---|
| Log centralization | Where are logs? How are they accessed? |
| Log integrity | Tamper-evidence? Signed? Append-only? |
| Playbook coverage | Which incident types have documented playbooks? |
| Evidence retention | Defined policy? Enforced? Retention period appropriate? |
| Automation | Manual collection vs. automated trigger? |
| Specialization | Generic playbooks vs. domain-specific (CI/CD, AI agents)? |

Overall FRS = average across the dimensions (rounded to nearest 0.5).

## Mapping to TDMM

The FRS dimension corresponds to TDMM Domain 8 (Operations & Incident Response). A typical regulated organization at TDMM 3.0 has FRS 2.5–3.0.

## How to improve FRS

| From | To | Typical intervention | Time investment |
|---|---|---|---|
| 1 → 2 | Reactive → Aware | Deploy SIEM; centralize logs | 2-3 months |
| 2 → 3 | Aware → Prepared | Add tamper-evidence; build CI/CD playbooks | 3-6 months |
| 3 → 4 | Prepared → Proactive | Add AI agent forensics; integrate Five Forensic Questions | 6-12 months |
| 4 → 5 | Proactive → Adaptive | Architect-in forensic readiness from day one in new systems | Ongoing |

## Why FRS matters

Most organizations invest heavily in incident DETECTION (SIEM rules, anomaly detection). They invest much less in incident INVESTIGATION readiness. The FRS framework surfaces this gap.

When a serious incident occurs (supply chain attack, AI agent misbehavior, insider threat), the difference between FRS 2 and FRS 4 is the difference between a 3-week investigation that produces incomplete answers and a 4-hour investigation that produces actionable remediation.
