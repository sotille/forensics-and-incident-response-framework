# AI Agent Behavioral Baseline for Forensic Investigation

## Table of Contents

- [Purpose](#purpose)
- [Why Baseline Is Required for Agent Forensics](#why-baseline-is-required-for-agent-forensics)
- [Baseline Dimensions](#baseline-dimensions)
- [Tool Call Baselines](#tool-call-baselines)
- [Resource Consumption Baselines](#resource-consumption-baselines)
- [Network and Egress Baselines](#network-and-egress-baselines)
- [Session Duration and Scope Baselines](#session-duration-and-scope-baselines)
- [Authorization Pattern Baselines](#authorization-pattern-baselines)
- [Establishing Your Baseline](#establishing-your-baseline)
- [Anomaly Detection Thresholds](#anomaly-detection-thresholds)
- [Baseline Drift and Recalibration](#baseline-drift-and-recalibration)

---

## Purpose

This document defines the behavioral baseline patterns that investigators need to determine whether an AI agent's actions during an incident were within normal operating parameters or constituted anomalous, unauthorized, or adversarially influenced behavior.

A behavioral baseline is the forensic equivalent of a network traffic baseline in traditional IR: without it, analysts cannot distinguish an intrusion from normal operation. For AI agents, this problem is more acute because agent behavior varies legitimately based on instruction, context, and model non-determinism.

This document provides:
1. The dimensions of agent behavior that must be baselined before forensic comparison is possible
2. Reference baseline patterns for common DevSecOps AI agent types
3. Anomaly detection thresholds calibrated to distinguish signal from noise
4. Guidance on establishing and maintaining organization-specific baselines

---

## Why Baseline Is Required for Agent Forensics

Traditional IR assumes that attacker actions are distinguishable from normal operations because they involve fundamentally different techniques (lateral movement, privilege escalation, data staging). AI agent IR does not have this property:

- A legitimately functioning agent may call the same tools as an adversarially influenced agent
- The same tool call (`read_file`, `create_pr`, `run_tests`) appears in both legitimate and compromised sessions
- Model non-determinism means that no two legitimate sessions are identical even given the same instruction

The Five Forensic Questions framework (see `docs/agent-forensics/five-questions-framework.md`) answers *what* the agent did. The behavioral baseline answers *whether that was normal*. Both are required to reach an investigation conclusion.

**Without a baseline, investigators can only state:** "The agent called `delete_branch` 3 times during the session."
**With a baseline, investigators can state:** "The agent called `delete_branch` 3 times, which is 12× above the 99th percentile for this agent type over the past 90 days. This is anomalous."

---

## Baseline Dimensions

Establish baselines across six dimensions for each distinct agent type in your deployment:

1. **Tool call frequency** — How many tool calls per session; which tools are called how often
2. **Resource consumption** — Token consumption, wall-clock session duration, compute time
3. **Network and egress** — External endpoints contacted; data volume transmitted externally
4. **Session scope** — Repository scope, file system paths accessed, database tables queried
5. **Authorization patterns** — Ratio of authorized to unauthorized tool calls; approval gate hit rate
6. **Temporal patterns** — Time of day, day of week, session initiation triggers

Baseline each dimension separately by agent type (code review agent, vulnerability triage agent, remediation agent, etc.) and by invocation context (PR-triggered vs. scheduled vs. manual).

---

## Tool Call Baselines

### Reference Baselines by Agent Type

The following reference baselines are derived from observed production behavior in mature DevSecOps deployments. Calibrate against your organization's specific data before using for forensic comparison.

**Code Review Security Agent** (triggered by PR open/update events)

| Metric | Typical Range (P5–P95) | P99 | Anomaly Threshold |
|--------|----------------------|-----|-------------------|
| Total tool calls per session | 8–35 | 62 | > 100 |
| `read_file` calls | 5–28 | 54 | > 80 |
| `search_code` calls | 1–8 | 15 | > 25 |
| `post_comment` calls | 1–3 | 6 | > 10 |
| `create_issue` calls | 0–1 | 3 | > 5 |
| `write_file` / `delete_file` calls | 0 (should never occur) | 0 | > 0 — ALERT |
| External HTTP calls | 0 (to non-allowlisted domains) | 0 | > 0 — ALERT |

**Vulnerability Triage Agent** (triggered by scanner output events)

| Metric | Typical Range (P5–P95) | P99 | Anomaly Threshold |
|--------|----------------------|-----|-------------------|
| Total tool calls per session | 5–20 | 38 | > 60 |
| `query_database` / `query_tracker` calls | 2–12 | 22 | > 35 |
| `update_ticket` / `label_issue` calls | 1–8 | 15 | > 25 |
| `assign_ticket` calls | 0–4 | 8 | > 15 |
| `read_file` calls | 0–5 | 10 | > 18 |
| `run_code` / `execute_command` calls | 0 (should never occur) | 0 | > 0 — ALERT |

**Autonomous Remediation Agent** (triggered by approved work items)

| Metric | Typical Range (P5–P95) | P99 | Anomaly Threshold |
|--------|----------------------|-----|-------------------|
| Total tool calls per session | 15–80 | 140 | > 200 |
| `read_file` calls | 8–45 | 80 | > 120 |
| `write_file` calls | 2–20 | 40 | > 60 |
| `run_tests` calls | 2–8 | 15 | > 25 |
| `create_pr` calls | 1 (exactly — one PR per task) | 2 | > 3 — ALERT |
| `merge_pr` calls | 0 (human approval required) | 0 | > 0 — ALERT |
| `delete_file` calls | 0–2 | 4 | > 8 |
| Cross-repository file writes | 0 (should be scoped to target repo) | 0 | > 0 — ALERT |

### Tool Call Sequence Anomalies

Beyond frequency, certain tool call *sequences* are anomalous regardless of whether individual tool calls are within baseline:

| Anomalous Sequence | Why Anomalous |
|---|---|
| `read_file(secret_file)` → `external_http_request(external_domain)` | Data exfiltration pattern |
| `read_file(config)` → `write_file(config)` without any intermediate analysis step | Unauthorized configuration modification |
| `list_directory(/)` → `list_directory(/etc)` → `read_file(/etc/passwd)` | Privilege escalation probe |
| `run_code(code_string)` where `code_string` contains base64-encoded content | Obfuscation of injected payload |
| Any tool call with parameters containing `ignore previous instructions`, `system:`, or `<|im_start|>` | Direct prompt injection in tool parameters |
| Repeated `approve_action()` calls without intervening `request_approval()` | Authorization bypass attempt |

---

## Resource Consumption Baselines

Token consumption and session duration provide independent anomaly signals that are harder to suppress than tool call logs.

**Token consumption baselines (approximate; model-dependent):**

| Agent Type | Input Tokens (P5–P95) | Output Tokens (P5–P95) | Anomaly Threshold |
|---|---|---|---|
| Code review agent | 4,000–40,000 | 500–8,000 | Input > 100,000 OR Output > 20,000 |
| Vulnerability triage agent | 2,000–20,000 | 200–4,000 | Input > 60,000 OR Output > 12,000 |
| Autonomous remediation agent | 10,000–80,000 | 2,000–20,000 | Input > 200,000 OR Output > 60,000 |

**Session duration baselines:**

| Agent Type | Duration (P5–P95) | P99 | Anomaly Threshold |
|---|---|---|---|
| Code review agent | 30s–8min | 18min | > 30min |
| Vulnerability triage agent | 15s–4min | 10min | > 20min |
| Autonomous remediation agent | 2min–25min | 45min | > 90min |

**Anomalous resource patterns:**
- Session that consumes tokens but makes no tool calls (reasoning without acting — possible injection sinkhole)
- Session that terminates abruptly with zero output tokens after large input consumption (possible context window stuffing attack)
- Multiple sequential sessions initiated within seconds for the same agent (possible replay or amplification attack)

---

## Network and Egress Baselines

AI agents in DevSecOps pipelines should have predictable, allowlist-bound network behavior. Any egress outside the allowlist is anomalous regardless of volume.

**Standard allowlist for DevSecOps AI agents:**

| Endpoint Category | Examples | Notes |
|---|---|---|
| AI provider API | `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com` | Monitor for unusual models being called |
| Internal code repositories | `github.internal`, `gitlab.internal` | Scope to organization's repositories only |
| Internal ticket/issue systems | `jira.internal`, `linear.internal` | Scope to organization's projects only |
| Internal artifact registries | `registry.internal`, `artifactory.internal` | Read access only for most agents |
| Container/package registries | `registry.npmjs.org`, `pypi.org`, `hub.docker.com` | Read-only; monitor for unusual package name patterns (slopsquatting) |

**Network anomaly indicators:**

| Indicator | Threshold | Investigation Priority |
|---|---|---|
| Connection to domain not on allowlist | Any single occurrence | CRITICAL |
| DNS resolution of domain with >30 chars subdomain | Any occurrence | HIGH — potential DNS tunneling |
| Data upload volume to AI provider exceeding 3× session baseline | Any occurrence | HIGH — possible data exfiltration via context |
| Connection to allowlisted domain from unexpected agent role | Any occurrence | MEDIUM — possible privilege escalation |
| Repeated connection failures to allowlisted domain | >10 in 60s | LOW — possible misconfiguration or DoS |

---

## Session Duration and Scope Baselines

**Repository scope:** Each agent session should operate within a defined repository scope established at session initiation. Cross-repository access during a single session is anomalous unless explicitly authorized in the tool authorization policy.

**File system path baselines:**

| Agent Type | Expected Path Scope | Anomalous Paths |
|---|---|---|
| Code review agent | Repository root and subdirectories | `/etc/`, `/var/`, `/tmp/` (outside repo), `~/.ssh/`, `~/.aws/` |
| Vulnerability triage agent | Read-only access to issue tracker | Any local file system access |
| Remediation agent | Target repository only | Any path outside the assigned repository |

**Scope expansion pattern:** An agent that begins operating within its normal scope and progressively expands to new paths over the session is exhibiting scope expansion behavior, which is characteristic of adversarial context injection. Flag sessions where the set of unique paths accessed grows by more than 50% relative to the first quartile of the session.

---

## Temporal Pattern Baselines

Temporal patterns — when agents run and how that timing relates to normal operational cadence — constitute baseline dimension 6. They are the most frequently overlooked forensic signal and the hardest to suppress: an adversarially influenced agent cannot easily control when it was triggered or make an abnormal session look like it occurred at a normal time.

### Time-of-Day and Day-of-Week Baselines

Establish the expected invocation distribution for each agent type. Most DevSecOps agents are trigger-driven and should follow predictable timing:

| Agent Type | Expected Invocation Window | Anomaly Conditions |
|---|---|---|
| Code review agent | Mirrors commit/PR activity: weekday business hours (08:00–20:00 local TZ), occasional after-hours | Session initiated at 03:00–05:00 local with no correlated developer activity |
| Vulnerability triage agent | Triggered by scanner outputs: continuous, but scanner scheduling creates batch patterns | Single session initiating 3× normal session count in a 10-minute window |
| Autonomous remediation agent | Business hours or scheduled maintenance windows only | Session initiated outside the defined maintenance window without change ticket |
| Scheduled analysis agent | Fixed cron schedule (e.g., 02:00 UTC daily) | Session initiated at unexpected time; missing expected scheduled session |

**Recording temporal baselines:**

```python
from collections import defaultdict
import json
from pathlib import Path

sessions = [json.loads(line) for line in Path("agent-audit-30day.jsonl").read_text().splitlines()]

# Build hour-of-day and day-of-week distributions
hourly = defaultdict(int)
daily = defaultdict(int)

for s in sessions:
    from datetime import datetime
    ts = datetime.fromisoformat(s["session_start_timestamp"].replace("Z", "+00:00"))
    hourly[ts.hour] += 1
    daily[ts.weekday()] += 1  # 0=Monday, 6=Sunday

# Hours with < 2% of sessions are low-activity — invocations here warrant scrutiny
total = sum(hourly.values())
low_activity_hours = [h for h, count in hourly.items() if count / total < 0.02]
print(f"Low-activity hours (< 2% of sessions): {sorted(low_activity_hours)}")
```

**Anomaly thresholds:**
- A session initiated during a low-activity hour (< 2% of baseline sessions) warrants **MEDIUM** investigation
- A session initiated during an hour with zero baseline sessions warrants **HIGH** investigation
- Multiple sessions initiated within seconds of each other (burst triggering) with no correlated pipeline event warrants **HIGH** investigation

### Session Initiation Trigger Baseline

Each agent type should be triggered by a defined, auditable event. Record the trigger-to-session mapping in the baseline:

| Agent Type | Expected Trigger | Anomalous Trigger |
|---|---|---|
| Code review agent | GitHub PR `opened`/`synchronized` webhook | Direct API invocation; absence of webhook event in audit log |
| Vulnerability triage agent | CI pipeline scan completion event | Manual invocation without scan result ID in session metadata |
| Remediation agent | Approved work item creation with required fields | Session without a valid, unprocessed work item reference |

**Orphaned sessions** — sessions with no traceable trigger event — are a high-priority forensic indicator. An adversary who directly invokes an agent via its API bypasses the normal trigger chain, leaving no upstream event. Flag all sessions where the trigger source is absent from the audit record.

### Inter-Session Gap Analysis

For agents with scheduled or event-driven cadence, gaps in expected sessions are as informative as anomalous sessions:

- A scheduled agent that fails to run at its expected time may indicate availability compromise, environment tampering, or deliberate suppression of detection
- A burst of sessions following an abnormal gap may indicate event-driven replay or catch-up after an interruption — investigate the gap period first
- Systematic gaps during specific hours may indicate scheduled availability of an adversary or a compromised automation system

---

## Authorization Pattern Baselines

**Authorization approval rate baselines:**

| Agent Type | Expected Approval Rate (authorized/total calls) | Anomaly Threshold |
|---|---|---|
| Code review agent | 100% (all calls pre-authorized by policy) | Any UNAUTHORIZED or UNDETERMINED |
| Vulnerability triage agent | 100% | Any UNAUTHORIZED or UNDETERMINED |
| Remediation agent | 95–100% (approval gates for merges/deletes) | < 90% OR any self-approved consequential action |

**Authorization anomaly patterns:**

- **UNDETERMINED** status on any tool call: the tool was invoked but the authorization basis could not be determined from audit records. This indicates a logging gap or a tool call that bypassed the authorization layer.
- **Approval gate bypass:** a consequential action (file deletion, merge, external publish) was completed without a corresponding `request_approval` → `approval_granted` sequence in the audit trail.
- **Permission escalation:** the agent invoked a tool with parameters that exceed the scope of the authorization policy's resource limits (e.g., policy allows writes to `src/` but the agent wrote to `infra/terraform/`).

---

## Establishing Your Baseline

Baseline establishment requires a minimum of 30 days of production data across at least 100 agent sessions per agent type. The following procedure applies:

### Step 1: Define Agent Types

List all distinct agent types in your deployment. An agent type is defined by: the system prompt template version, the tool authorization policy version, and the invocation trigger. Agents that share all three are the same type; agents that differ on any are distinct types.

### Step 2: Instrument for Baseline Collection

Ensure the audit trail (see `docs/agent-audit-trail.md`) captures all required fields before starting data collection:
- `session_id` — unique per session
- `agent_type` — matches your type taxonomy
- `tool_name`, `tool_parameters` — per tool call
- `authorization_status` — AUTHORIZED/UNAUTHORIZED/UNDETERMINED per call
- `token_count_input`, `token_count_output` — at session level
- `session_start_timestamp`, `session_end_timestamp` — for duration calculation
- `network_egress_bytes` — per session if instrumented at the platform level

### Step 3: Collect 30-Day Sample

Run the agent in normal production operation for 30 days, logging all sessions. Exclude sessions manually flagged as anomalous during the collection period (they would skew the baseline). Aim for a minimum of 100 sessions per agent type; 500+ sessions provides a statistically robust baseline.

### Step 4: Calculate Statistical Baselines

```python
import json
import numpy as np
from pathlib import Path

sessions = [json.loads(line) for line in Path("agent-audit-30day.jsonl").read_text().splitlines()]

tool_calls_per_session = [s["tool_call_count"] for s in sessions]
token_input = [s["token_count_input"] for s in sessions]
session_duration = [s["session_duration_seconds"] for s in sessions]

for metric, values in [
    ("tool_calls_per_session", tool_calls_per_session),
    ("token_input", token_input),
    ("session_duration_s", session_duration)
]:
    print(f"{metric}: "
          f"P5={np.percentile(values, 5):.0f}, "
          f"P50={np.percentile(values, 50):.0f}, "
          f"P95={np.percentile(values, 95):.0f}, "
          f"P99={np.percentile(values, 99):.0f}")
```

Set your anomaly threshold at 2.5× the P99 value as a starting point. Adjust based on false positive rate in the first 30 days of monitoring.

### Step 5: Document and Version the Baseline

Store the baseline document in version control. The baseline document must include:
- Date range of collection data
- Number of sessions included
- Statistical values (P5, P50, P95, P99) per metric per agent type
- Anomaly thresholds derived from the data
- Known legitimate outlier events excluded from the data set (e.g., a bulk remediation sprint)

---

## Anomaly Detection Thresholds

The following anomaly categories require immediate investigation regardless of statistical threshold:

**CRITICAL — Investigate immediately (< 15 minutes):**
- Any tool call with `authorization_status: UNAUTHORIZED` in a production agent session
- Any network connection to a domain outside the allowlist
- Any file write to a path outside the agent's authorized scope
- `write_file` or `delete_file` calls by an agent type whose policy does not include write permissions
- A session that lasts 3× longer than the P99 duration baseline

**HIGH — Investigate within 2 hours:**
- Tool call count exceeding the P99 threshold by more than 50%
- Token consumption exceeding the anomaly threshold defined in the baseline
- Any `UNDETERMINED` authorization status
- Cross-repository access during a single session
- Prompt injection indicators in tool call parameters

**MEDIUM — Review within 24 hours:**
- Session duration between 2× and 3× the P99 baseline
- New file paths accessed that were not observed in the 30-day baseline
- Minor scope expansion (< 50% growth in unique paths accessed)

---

## Baseline Drift and Recalibration

Agent behavior legitimately changes when:
- The system prompt template is updated
- The tool authorization policy is updated
- The underlying model version changes
- A new feature is added that changes the agent's typical task scope

**When to recalibrate:**
- After any system prompt or policy version change — recalibrate within 30 days of the change
- Quarterly review of all baselines regardless of changes
- After any confirmed incident — exclude incident-period sessions, then re-verify baseline integrity

### Post-Incident Baseline Recalibration Procedure

After a confirmed incident involving an AI agent, the baseline for that agent must be recalibrated before it returns to production. The following procedure prevents incident-period anomalous behavior from contaminating the legitimate-behavior dataset.

**Step 1 — Determine the incident window.**

Establish the earliest possible start time and the confirmed end time of the incident. Use the audit trail, the circuit breaker event log, and the five-questions investigation output. When in doubt, extend the window rather than truncate it. Document the window as `[T_start, T_end]`.

**Step 2 — Quarantine incident-period sessions.**

Tag all sessions with `session_start` within the incident window as `INCIDENT_PERIOD_EXCLUDED`. These sessions must not be used in any baseline calculation. Archive them separately — they are evidence and must be preserved under the chain-of-custody policy.

```python
def quarantine_incident_sessions(
    sessions: list[dict],
    incident_start: datetime,
    incident_end: datetime
) -> tuple[list[dict], list[dict]]:
    """
    Partition sessions into clean and quarantined sets.
    Returns (clean_sessions, quarantined_sessions).
    """
    clean, quarantined = [], []
    for s in sessions:
        start = datetime.fromisoformat(s["session_start"])
        if incident_start <= start <= incident_end:
            s["baseline_status"] = "INCIDENT_PERIOD_EXCLUDED"
            quarantined.append(s)
        else:
            clean.append(s)
    return clean, quarantined
```

**Step 3 — Verify baseline integrity before recalculation.**

Before recalculating, verify that the remaining clean sessions do not themselves contain indicators of earlier undetected compromise. Check for:
- Sessions where the agent called tools outside its normal sequence pattern
- Sessions with anomalous authorization denial rates (significantly lower or higher than the baseline mean)
- Sessions where network egress occurred to destinations not in the approved allowlist

If anomalies are found in sessions outside the incident window, extend the incident window and return to Step 1.

**Step 4 — Collect a new calibration dataset.**

Recollect 30 days of verified clean sessions after the agent resumes operation with the patched system prompt and updated policy. Do not use pre-incident sessions as the sole basis for the new baseline — post-remediation behavior under the new controls may differ.

If 30 days of post-incident data is unavailable (e.g., the agent runs infrequently), use a minimum of 100 sessions or 14 days, whichever comes first, and flag the baseline as `PROVISIONAL` until the full 30-day threshold is met.

**Step 5 — Recalculate thresholds with conservatism bias.**

After a security incident, set initial anomaly thresholds 20% tighter than the statistical distribution suggests:

| Metric | Standard threshold | Post-incident threshold |
|---|---|---|
| Total tool calls per session | P99 + 50% | P99 + 20% |
| Session duration | P99 | P95 |
| Unique file paths per session | P99 | P90 |
| Network destinations per session | P99 | P95 |

Maintain the tighter thresholds for 90 days after the incident. After 90 days without further anomalies, revert to standard thresholds. Document the threshold schedule in the baseline version record.

**Step 6 — Update the baseline version record.**

Create a new baseline version entry that records:

```yaml
baseline_version: "3.1.0"
agent_id: "code-review-agent"
calibration_date: "2026-04-09"
system_prompt_version_hash: "sha256:a3f9..."
tool_policy_version: "2.4.0"
calibration_dataset:
  session_count: 847
  date_range: ["2026-03-01", "2026-03-31"]
  incident_exclusion_applied: true
  incident_window: ["2026-02-14T09:00Z", "2026-02-14T11:32Z"]
threshold_mode: "post_incident_conservative"
threshold_revert_date: "2026-07-09"
notes: "Recalibrated following AF-01 incident. Tighter thresholds active for 90 days."
```

**Step 7 — Validate the new baseline before production use.**

Before the agent resumes production operation, run one week of shadow monitoring: execute the agent in a staging environment, capture sessions, and verify that the new baseline produces fewer than 5% false-positive alerts on normal task traffic. If the false-positive rate exceeds 5%, review whether the post-incident threshold tightening is too aggressive for this agent's legitimate task profile and adjust upward by 10% increments.

**Version alignment:** Each baseline version must record the system prompt version hash and tool authorization policy version it was calibrated against. When investigating an incident, use the baseline version that was active at the time of the incident, not the current baseline.

---

---

## LLM Non-Determinism and Baseline Interpretation

LLM-based agents do not produce identical behavior given identical inputs. The same task, same system prompt, and same tool set can produce different tool call sequences across sessions due to model temperature, sampling parameters, and context window differences. This is a fundamental property of language model inference, not a deviation.

**What non-determinism means for forensic comparison:**

Non-determinism does not invalidate baseline comparison — it requires that baselines be statistical rather than deterministic. A baseline that says "the code review agent always calls `read_file` exactly 12 times" is methodologically incorrect; a baseline that says "the code review agent calls `read_file` between 5 and 28 times (P5–P95)" correctly accounts for variation.

The forensic question is not "did this session differ from any specific prior session?" but "does this session fall outside the statistical distribution of observed legitimate sessions?"

**Signals that are stable despite non-determinism:**

Some behavioral properties are invariant even in non-deterministic systems and are therefore more forensically reliable:

| Signal | Stability | Why |
|---|---|---|
| Hard-zero tool calls (`write_file` for code review agent) | Invariant | Policy-enforced; the agent cannot call this tool regardless of reasoning path |
| External domain connections | Invariant | Network allowlist is enforced at infrastructure level, not by agent reasoning |
| Authorization policy violations | Invariant | The tool execution layer rejects unauthorized calls regardless of agent reasoning |
| Session trigger source | Invariant | Determined by the event that initiated the session, not the LLM |
| Canary token presence | Invariant | Only appears if a specific data source influenced the output |

**Signals affected by non-determinism (use statistical thresholds):**

| Signal | Variability | Approach |
|---|---|---|
| Total tool call count | Moderate | Use P99 + 50% as anomaly threshold |
| Specific tool call frequency (read_file, search_code) | Moderate | Use P99 as investigation trigger |
| Session duration | High | Use P99 as investigation trigger; not a hard alert |
| Output token count | High | Use 2× P99 as investigation trigger |

**The non-determinism trap in forensic investigation:**

Investigators who lack a statistical baseline may incorrectly conclude that anomalous behavior was legitimate because "the agent could have reasoned its way there." The counter-argument: while any individual tool call may be plausibly legitimate in isolation, the *combination* and *sequence* of tool calls in a compromised session will deviate from the statistical distribution of thousands of legitimate sessions. Baseline analysis operates on the distribution, not on individual plausibility.

*Cross-references:* [agent-forensics/five-questions-framework.md](agent-forensics/five-questions-framework.md) — Investigation methodology that uses this baseline; [agent-forensics/readiness-guide.md](agent-forensics/readiness-guide.md) — Forensic readiness score requirements for baseline instrumentation; [ai-devsecops-framework/docs/agent-audit-trail.md](../../ai-devsecops-framework/docs/agent-audit-trail.md) — Audit trail schema required to collect baseline data; [best-practices.md](best-practices.md) — Evidence preservation procedures that protect baseline data integrity.
