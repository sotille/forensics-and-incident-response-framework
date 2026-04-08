# Agent Forensics Readiness Guide

## Table of Contents

- [Overview](#overview)
- [Why Readiness Must Be Pre-Incident](#why-readiness-must-be-pre-incident)
- [The Forensics Readiness Score (FRS)](#the-forensics-readiness-score)
- [Level 1 — No Agent Forensic Capability](#level-1-no-agent-forensic-capability)
- [Level 2 — Basic Audit Coverage](#level-2-basic-audit-coverage)
- [Level 3 — Structured Investigation Capability](#level-3-structured-investigation-capability)
- [Level 4 — Full Five Questions Capability](#level-4-full-five-questions-capability)
- [Level 5 — Continuous Assurance](#level-5-continuous-assurance)
- [Forensic Infrastructure Architecture](#forensic-infrastructure-architecture)
- [Context Window Capture](#context-window-capture)
- [Session Recording and Replay](#session-recording-and-replay)
- [Chain of Custody for AI Agent Evidence](#chain-of-custody-for-ai-agent-evidence)
- [Tabletop Exercises for Agent Forensics](#tabletop-exercises-for-agent-forensics)
- [Cost and Overhead Tradeoffs](#cost-and-overhead-tradeoffs)
- [Readiness Assessment Checklist](#readiness-assessment-checklist)

---

## Overview

Agent forensics readiness is the state of an organization's infrastructure, processes, and policies that determines whether an agent incident can be fully investigated after it occurs. Readiness is a pre-condition: the evidence required to answer the Five Forensic Questions must be collected at the time of the incident, not retroactively. An organization that discovers it needed context window logging after an incident cannot go back and collect that evidence.

This guide defines the five-level Forensics Readiness Score (FRS) for agentic systems, specifies the infrastructure requirements at each level, and provides implementation guidance for reaching Level 4 (Full Five Questions Capability) — the level at which an organization can reliably investigate agent incidents.

---

## Why Readiness Must Be Pre-Incident

The forensic challenge of agent incidents is that the most important evidence is ephemeral:

**Context window content is transient.** The system prompt, conversation history, and retrieved documents that shaped an agent's behavior during a session are typically not persisted by default. Once the session ends, the context window is gone unless it was explicitly captured.

**Non-determinism means reconstruction is unreliable.** Unlike a deterministic program, an agent given the same inputs may produce different outputs at a different time. Forensic reconstruction — running the same inputs through the same model — does not produce the original agent behavior. The original session record is the only reliable evidence.

**Model versions change.** The model that was running when the incident occurred may have been updated by the time the investigation begins. Behavioral comparison against the current model version does not reflect the incident-time behavior.

**Authorization policy evolves.** The tool authorization policy in effect at the time of the incident may differ from the current policy. Without version-controlled policies with commit-hash references in audit events, it is impossible to evaluate whether actions were policy-compliant at the time they occurred.

These constraints mean that forensic infrastructure must be deployed before agents are permitted to operate in consequential roles, not after an incident demonstrates its necessity.

---

## The Forensics Readiness Score

The Forensics Readiness Score (FRS) for agentic systems has five levels. The levels are cumulative: Level 3 requires that Level 1 and Level 2 are complete.

An organization operating AI agents in production should target at minimum Level 3 before agents are granted consequential permissions (those covered by approval gates). Level 4 is required before agents are permitted to operate with significant autonomy in production. Level 5 is appropriate for organizations that have reached AI Security Maturity Level 4 or 5 (see [ai-devsecops-framework/docs/maturity-model.md](../../../ai-devsecops-framework/docs/maturity-model.md)).

---

## Level 1 — No Agent Forensic Capability

**Definition:** Agents are operating without any forensic infrastructure. An incident cannot be investigated beyond what is visible in standard application logs and cloud audit trails.

**Characteristics:**
- No agent-specific audit trail
- System prompts not version-controlled
- No session boundary tracking
- Agent service account activity not distinguishable from human activity in cloud logs

**Risk:** An incident at this level cannot be fully investigated. The organization cannot determine what the agent was instructed to do, what data it accessed, or whether its actions were authorized.

**Remediation path:** Implement Level 2 before deploying agents in any production role.

---

## Level 2 — Basic Audit Coverage

**Definition:** Agent actions are logged in an identifiable, queryable form. The organization can determine what actions the agent took but may not be able to determine why.

**Requirements:**

- [ ] Agent tool calls are logged with session ID, agent role, tool name, and timestamp
- [ ] Agent service accounts are distinct from human accounts (no shared credentials)
- [ ] Session boundaries (start and end) are logged
- [ ] Human principal identity and task description are recorded at session start
- [ ] Logs are retained for at minimum 90 days

**What is answerable at Level 2:**
- Q1 (What did the agent do?): Yes, from tool call logs
- Q4 (What tools did it invoke?): Yes, if input parameters are included
- Q2, Q3, Q5: Partially or not at all

**Gap:** Tool call logs at Level 2 typically include the tool name and timestamp but may not include full input parameters or outputs. Context window content is not captured. Authorization policy version is not recorded in the audit trail.

---

## Level 3 — Structured Investigation Capability

**Definition:** The organization can answer all Five Forensic Questions for most agent incidents, with gaps in context window content and some cross-system correlation.

**Requirements (in addition to Level 2):**

- [ ] Tool call input parameters (full, not summarized) are logged
- [ ] Authorization policy is version-controlled in git; policy commit hash is recorded in session initiation event
- [ ] System prompts are version-controlled in git; system prompt commit hash is recorded in session initiation event
- [ ] Tool call authorization decisions (permitted and denied) are logged
- [ ] Human approval events (for approval-gated actions) are logged with approver identity and timestamp
- [ ] Audit trail is append-only and stored in a tamper-resistant location (separate from application infrastructure)
- [ ] Logs are retained for at minimum 12 months

**What is answerable at Level 3:**
- Q1: Yes (complete tool call sequence)
- Q2: Partially (system prompt and human task, but not context window content)
- Q3: Yes for resource access; partial for data content
- Q4: Yes (complete tool call sequence with parameters)
- Q5: Yes (authorization policy version and decision records)

---

## Level 4 — Full Five Questions Capability

**Definition:** The organization can answer all Five Forensic Questions completely for all agent incidents, including multi-agent chain incidents.

**Requirements (in addition to Level 3):**

- [ ] Context window content is captured at session start and at configurable intervals during long sessions
- [ ] Tool output content is logged (or hashed, with full content retrievable for high-severity incidents)
- [ ] Root session ID propagates through multi-agent chains; all subagent sessions are correlated to their root
- [ ] Session replay capability is implemented and tested: a completed session can be reconstructed from the audit trail for forensic review
- [ ] Canary tokens are deployed in sensitive resources and tool outputs; triggering a canary token generates an alert
- [ ] Agent incident response playbooks are documented and tested
- [ ] Forensic investigation procedures are documented and all responders have been trained

**What is answerable at Level 4:**
- Q1–Q5: All fully answerable for single-agent and multi-agent incidents

---

## Level 5 — Continuous Assurance

**Definition:** Forensic readiness is continuously verified through automated testing and periodic exercises. Forensic metrics are tracked and reported.

**Requirements (in addition to Level 4):**

- [ ] Monthly canary token triggering tests verify that alerts are generated and routed correctly
- [ ] Quarterly tabletop exercises validate that the Five Questions can be answered for simulated incident scenarios
- [ ] Annual forensic infrastructure review covers retention policy, storage capacity, and log coverage gaps
- [ ] Forensic readiness metrics reported to security leadership: mean time to answer each of the Five Questions, coverage gaps discovered in exercises
- [ ] Forensic infrastructure changes go through change management with rollback procedures
- [ ] Legal hold procedures tested annually (see [legal-hold-procedures.md](../legal-hold-procedures.md))

---

## Forensic Infrastructure Architecture

A Level 4 forensic infrastructure for agentic systems has four components:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Runtime Environment                     │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Agent Session │    │ Tool Execution│    │  Context Capture │   │
│  │  (LLM call)  │───▶│    Layer     │───▶│    Component     │   │
│  └──────────────┘    └──────────────┘    └────────┬─────────┘   │
│           │                  │                    │             │
└───────────┼──────────────────┼────────────────────┼─────────────┘
            │                  │                    │
            ▼                  ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│              Append-Only Agent Audit Store                       │
│  (separate infrastructure, no write access from agent runtime)   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Session events, tool calls, authorization decisions,    │    │
│  │  context snapshots, human approvals, canary triggers     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────┬───────────────────────────────────┘
                              │
            ┌─────────────────┼───────────────────┐
            ▼                 ▼                   ▼
   ┌─────────────────┐ ┌──────────────┐ ┌──────────────────────┐
   │  Investigation   │ │   Alerting   │ │   Long-Term Archive  │
   │  Query Interface │ │   (SIEM)     │ │   (Legal Hold)       │
   └─────────────────┘ └──────────────┘ └──────────────────────┘
```

### Append-Only Audit Store Implementation

The audit store must not be writable by the agent runtime. An agent that has been compromised must not be able to modify or delete its own audit records.

**AWS implementation:**
```yaml
# S3 bucket for agent audit trail — Object Lock enabled, WORM mode
aws s3api create-bucket \
  --bucket agent-audit-${ACCOUNT_ID} \
  --region us-east-1

aws s3api put-object-lock-configuration \
  --bucket agent-audit-${ACCOUNT_ID} \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 365
      }
    }
  }'

# Agent runtime role: PutObject only, no DeleteObject, no PutObjectLegalHold
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::agent-audit-${ACCOUNT_ID}/sessions/*"
    }
  ]
}
```

**Kubernetes implementation:**
```yaml
# Dedicated audit log namespace with restricted write policy
apiVersion: v1
kind: Namespace
metadata:
  name: agent-audit
---
# NetworkPolicy: only audit-writer service account can write to audit pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: audit-write-restriction
  namespace: agent-audit
spec:
  podSelector: {}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          audit-writer: "true"
```

---

## Context Window Capture

Context window capture records the full content that was available to the agent when it made each decision. This is the most operationally significant evidence gap at Level 2 and Level 3.

### What to Capture

At minimum, capture the following at session start and at each tool call that introduces new external content:

```json
{
  "capture_type": "context_snapshot",
  "session_id": "sess-7f3a9b2e-4c1d",
  "agent_role": "remediation-agent",
  "timestamp": "2024-10-15T14:32:01.523Z",
  "turn_number": 7,
  "trigger": "tool_result_received",
  "tool_that_produced_content": "github.issue.read",
  "context_hash": "sha256:a3b7c9d2e1f4a8b3...",
  "context_storage_ref": "s3://agent-audit/contexts/sess-7f3a9b2e/turn-7.json.gz",
  "tokens_in_context": 12847,
  "sensitive_content_detected": false
}
```

The full context content is stored separately (referenced by `context_storage_ref`) with appropriate data classification controls. The audit event records the hash for tamper detection and the reference for retrieval.

### Performance Impact

Full context window capture at every turn is expensive for large contexts. A pragmatic approach:

- Capture at session start (always)
- Capture after any tool result that introduces external content (PR descriptions, issue bodies, CVE data, file contents)
- Capture before any high-consequence tool call (merges, deployments, deletions)
- Store as compressed JSON with 90-day hot retention, 12-month archive

---

## Session Recording and Replay

Session replay reconstructs an agent session from the audit trail for forensic review. A complete replay includes:

1. The system prompt version active at the time
2. The human turn input (task description)
3. The tool calls made, in sequence, with their parameters
4. The tool results returned, in sequence
5. Any human approval events

Replay does not re-execute the agent (which would produce non-deterministic results). It reconstructs the *inputs* the agent received so investigators can trace how the agent's context evolved and identify where adversarial content entered the context window.

**Replay query construction:**

```bash
#!/bin/bash
# Reconstruct a session for forensic review
SESSION_ID="$1"
AUDIT_LOG="/var/log/agent-audit/$(date +%Y-%m-%d)-audit.json"

echo "=== Session Replay: ${SESSION_ID} ==="
echo ""

# 1. Session initiation
echo "--- Session Start ---"
jq -r '.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "session_start")
  | "Agent: \(.agent_role)\nHuman principal: \(.human_principal)\nTask: \(.task_description)\nPolicy version: \(.authorization_policy_version)"' \
  ${AUDIT_LOG}

echo ""
echo "--- Turn Sequence ---"

# 2. Ordered event sequence
jq -r '[.[] | select(.session_id == "'${SESSION_ID}'")] | sort_by(.timestamp)[]
  | if .event_type == "tool_call" then
      "[\(.timestamp)] TOOL CALL: \(.tool_name)\n  Input: \(.input_parameters | tostring)\n  Auth: \(.authorization_status)"
    elif .event_type == "tool_result" then
      "[\(.timestamp)] TOOL RESULT: \(.tool_name)\n  Content hash: \(.result_hash)"
    elif .event_type == "human_approval" then
      "[\(.timestamp)] HUMAN APPROVAL: \(.approved_action) by \(.approver)"
    elif .event_type == "tool_blocked" then
      "[\(.timestamp)] BLOCKED: \(.tool_name) — \(.block_reason)"
    else
      "[\(.timestamp)] \(.event_type)"
    end' \
  ${AUDIT_LOG}
```

---

## Chain of Custody for AI Agent Evidence

Agent forensics evidence must maintain an unbroken chain of custody if it will be used in legal proceedings, regulatory investigations, or internal disciplinary actions.

**Chain of custody requirements for agent evidence:**

| Requirement | Implementation |
|---|---|
| Evidence integrity at collection | Hash all evidence at collection time; record hash in chain of custody log |
| Immutable storage | WORM storage (S3 Object Lock, Azure Immutable Blob Storage) from point of collection |
| Access logging | Every access to evidence (read or copy) is logged with the accessor's identity |
| Transfer documentation | Any transfer of evidence to external parties (legal, regulators) uses signed transfer records |
| Retention compliance | Evidence is not destroyed before the retention period expires; legal hold overrides retention schedules |

**Evidence packaging for external transfer:**

```bash
# Package session evidence with integrity verification
SESSION_ID="sess-7f3a9b2e-4c1d"
PACKAGE_DIR="/tmp/evidence-${SESSION_ID}"
mkdir -p "${PACKAGE_DIR}"

# Collect all evidence files
jq '[.[] | select(.session_id == "'${SESSION_ID}'")] | sort_by(.timestamp)' \
  /var/log/agent-audit/*.json > "${PACKAGE_DIR}/audit-events.json"

# Retrieve system prompt version
git -C /path/to/prompts show ${POLICY_COMMIT}:prompts/${AGENT_ROLE}.txt \
  > "${PACKAGE_DIR}/system-prompt.txt"

# Generate evidence manifest with hashes
sha256sum "${PACKAGE_DIR}"/* > "${PACKAGE_DIR}/MANIFEST.sha256"

# Package and sign
tar czf "evidence-${SESSION_ID}.tar.gz" "${PACKAGE_DIR}"
sha256sum "evidence-${SESSION_ID}.tar.gz" > "evidence-${SESSION_ID}.tar.gz.sha256"

echo "Evidence package: evidence-${SESSION_ID}.tar.gz"
echo "Package hash: $(cat evidence-${SESSION_ID}.tar.gz.sha256)"
```

See [evidence-chain-of-custody.md](../evidence-chain-of-custody.md) for the full chain of custody procedures applicable to all forensic evidence types.

---

## Tabletop Exercises for Agent Forensics

Tabletop exercises test whether the forensic infrastructure works as designed and whether responders can execute the investigation procedures. Agent forensics exercises should be conducted at minimum quarterly at FRS Level 5, and annually at Level 4.

### Exercise Structure

**Scenario selection:** Choose one of the six agent incident types (AF-01 through AF-06) or a multi-type composite scenario. The scenario should specify: the agent involved, the session time range, the observable symptom (what triggered the investigation), and the underlying incident.

**Exercise objectives:** At the end of the exercise, participants must have answered all Five Forensic Questions for the scenario, identified any gaps encountered in the investigation, and produced a draft investigation report.

**Debrief questions:**
1. Were you able to answer all Five Forensic Questions? If not, which question could not be answered and why?
2. What evidence was missing that would have made the investigation faster or more complete?
3. Were the investigation playbooks accurate? Did any steps need to be modified?
4. How long did the investigation take? Is this within the expected time range for the incident type?

### Quarterly Exercise Scenario Template

```
Incident: [AF-0X type]
Observable symptom: [What was seen that triggered investigation]
Session ID (simulated): sess-tabletop-[date]-001
Agent role: [which agent type]
Time range: [24-hour window]

Injected evidence (pre-positioned in test log):
- [specific events and data the responders should find]

Expected Five Questions answers:
- Q1: [expected finding]
- Q2: [expected finding]
- Q3: [expected finding]
- Q4: [expected finding]
- Q5: [expected finding]
```

---

## Cost and Overhead Tradeoffs

Agent forensic infrastructure has measurable storage and compute overhead. The following guidance helps prioritize investment:

| Component | Cost Driver | Optimization |
|---|---|---|
| Full tool call logging with parameters | Storage volume proportional to parameter size | Log parameters in full for high-risk tools; log tool name + hash for low-risk tools |
| Context window capture | High storage for large context models | Capture at turn boundaries only; compress; archive after 30 days |
| Append-only audit store | WORM storage premium (15–25% vs. standard) | Unavoidable; treat as a security control cost, not an IT cost |
| Session replay capability | Compute for forensic queries | Build query interface on read replicas, not production audit store |
| Canary token infrastructure | Negligible | None required |

**Minimum viable forensic infrastructure cost estimate for a mid-size deployment (100 agent-hours/month):**

- Audit event storage: ~50 GB/month compressed, at standard cloud storage rates
- Context window storage: ~500 GB/month (uncompressed), ~150 GB compressed
- WORM storage premium: 20% overhead
- Total: approximately the cost of a single additional 1 TB storage tier per month

This is a small fraction of the cost of an uninvestigable agent incident.

---

## Readiness Assessment Checklist

Use this checklist to determine the current FRS level and identify the next steps to advance.

### Level 2 Checklist
- [ ] Agent tool calls logged with session ID, agent role, tool name, timestamp
- [ ] Agent service accounts are distinct and dedicated (no human/agent sharing)
- [ ] Session start and end events logged
- [ ] Human principal identity and task description recorded at session start
- [ ] Logs retained for 90+ days

### Level 3 Additional Requirements
- [ ] Tool call input parameters logged in full
- [ ] Authorization policy stored in version control; commit hash in session start event
- [ ] System prompt stored in version control; commit hash in session start event
- [ ] Authorization decisions (permitted and blocked) logged per tool call
- [ ] Human approval events logged with approver identity
- [ ] Audit trail is append-only, stored outside agent runtime environment
- [ ] Logs retained for 12+ months

### Level 4 Additional Requirements
- [ ] Context window captured at session start and on external content ingestion
- [ ] Tool output content logged or hashed with retrievable storage
- [ ] Root session ID propagates through multi-agent chains
- [ ] Session replay procedure documented and tested
- [ ] Canary tokens deployed in sensitive resources
- [ ] Agent incident response playbooks documented
- [ ] All incident responders trained on the Five Questions framework

### Level 5 Additional Requirements
- [ ] Monthly canary token alert tests
- [ ] Quarterly tabletop exercises with documented outcomes
- [ ] Annual forensic infrastructure review
- [ ] Forensic readiness metrics tracked and reported
- [ ] Legal hold procedures tested annually
