# The Five Forensic Questions Framework for Agent Incidents

## Table of Contents

- [Overview](#overview)
- [Why Five Questions](#why-five-questions)
- [Question 1: What Did the Agent Do?](#question-1-what-did-the-agent-do)
- [Question 2: What Was It Instructed to Do?](#question-2-what-was-it-instructed-to-do)
- [Question 3: What Data Did It Access or Transmit?](#question-3-what-data-did-it-access-or-transmit)
- [Question 4: What Tools Did It Invoke and With What Parameters?](#question-4-what-tools-did-it-invoke-and-with-what-parameters)
- [Question 5: What Was the Authorization Basis for Each Action?](#question-5-what-was-the-authorization-basis-for-each-action)
- [Evidence Mapping by Question](#evidence-mapping-by-question)
- [Investigation Scope Determination](#investigation-scope-determination)
- [Gap Analysis: When You Cannot Answer a Question](#gap-analysis-when-you-cannot-answer-a-question)
- [The Five Questions as an Audit Readiness Checklist](#the-five-questions-as-an-audit-readiness-checklist)
- [Integration with Playbooks](#integration-with-playbooks)

---

## Overview

The Five Forensic Questions Framework structures agent incident investigations around five questions that must be answered to produce a complete, defensible investigation report. Every agent forensics investigation begins and ends with these five questions: they determine the scope of evidence collection, organize the analysis, and define what the final report must contain.

The framework applies to all agent incident types: unauthorized tool calls, confirmed prompt injection, unknown-provenance artifacts introduced by agents, permission escalation, multi-agent cascade compromise, and model supply chain tampering. The questions are consistent across incident types; the evidence sources differ.

The Five Forensic Questions are:

1. **What did the agent do?** — The factual record of agent actions
2. **What was it instructed to do?** — The legitimate task scope at session start
3. **What data did it access or transmit?** — The data plane impact of the session
4. **What tools did it invoke and with what parameters?** — The control plane record of the session
5. **What was the authorization basis for each action?** — The policy compliance evaluation

---

## Why Five Questions

Standard incident response produces a timeline: who did what, when, from where. For human actors, this is sufficient — identity, action, and authorization are independently verifiable artifacts (authentication logs, access control decisions, role assignments).

For AI agent incidents, the same three-part structure is insufficient:

**Identity is ambiguous.** A service account associated with an agent role may be shared across many sessions and agent instances. The agent that took an action may not be uniquely identifiable from the service account record alone.

**Action context determines meaning.** An agent that merged a pull request did so in response to its inputs — the system prompt, the conversation history, the external data in its context window. The same action (merge) is legitimate if authorized and malicious if the result of prompt injection. The action record alone does not distinguish these cases.

**Authorization has two layers.** Was the agent technically permitted to take the action (tool authorization policy)? And was the action within the legitimate scope of the session as established by the human principal? Both must be answered.

The Five Questions address these gaps by separating the factual record (Q1, Q3, Q4) from the intent record (Q2) and the authorization record (Q5). A complete investigation must answer all five.

---

## Question 1: What Did the Agent Do?

**Purpose:** Establish the complete factual record of agent actions — what happened, in what order, with what observable effects.

**Scope:** All actions taken by the agent during the session, including actions that succeeded, actions that failed (attempted but blocked), and system state changes caused by the agent's actions.

### Evidence Sources

| Evidence Source | What It Establishes |
|---|---|
| Agent audit trail (append-only log) | Tool calls made, inputs provided, outputs received, timestamps |
| Downstream system logs | What the tool calls actually did (e.g., GitHub API logs, AWS CloudTrail) |
| CI/CD pipeline logs | Pipeline steps triggered, approvals granted or skipped |
| Git commit and PR history | Code changes attributed to the agent's identity |
| Cloud resource change logs | Infrastructure modifications made using the agent's credentials |

### Evidence Collection Commands

```bash
# Retrieve all tool calls for a session from the agent audit log
jq '[.[] | select(.session_id == "'${SESSION_ID}'" and .event_type == "tool_call")]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# Retrieve GitHub API activity for the agent's service account
gh api /orgs/${ORG}/audit-log \
  --field phrase="actor:${AGENT_SERVICE_ACCOUNT}" \
  --field include=git \
  --field created="$(date -d '-24 hours' +%Y-%m-%dT%H:%M:%SZ)..$(date +%Y-%m-%dT%H:%M:%SZ)" \
  --paginate | jq '.[] | select(.session == "'${SESSION_ID}'")'

# Retrieve AWS CloudTrail events for the agent's role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=${AGENT_ROLE_ARN} \
  --start-time $(date -d '-24 hours' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds) \
  --output json | jq '.Events[]'
```

### What Q1 Cannot Establish Alone

Q1 establishes *what happened* but not *why it happened* or *whether it should have happened*. An agent that merged a PR, created commits, or deleted a branch appears the same in Q1 whether it was operating legitimately or was compromised. Q2 and Q5 are required to interpret Q1 findings.

---

## Question 2: What Was It Instructed to Do?

**Purpose:** Establish the legitimate task scope — what the human principal authorized the agent to do at session initialization.

**Scope:** The system prompt in effect at session start, the task provided by the human principal, and any subsequent instructions provided during the session.

### Why This Question Is Hard

The "instructions" given to an AI agent are composite. They include:

- The **system prompt** (what role and constraints the operator defined)
- The **human turn input** (the specific task the user requested)
- **Retrieved context** (documents, code, issues that the agent retrieved and added to its context window — any of which may contain adversarial content)
- **Tool outputs** fed back into the context (which are themselves derived from external, potentially untrusted sources)

An agent's behavior diverges from its legitimate instructions when adversarial content in any of these sources overrides the system prompt or human turn intent. Reconstructing the full context window is therefore essential to answering Q2 — not just the system prompt and human turn, but all context the agent actually processed.

### Evidence Sources

| Evidence Source | What It Establishes |
|---|---|
| System prompt version in version control | The operator-defined constraints and role |
| Session initiation event in audit log | Task description provided by human principal, timestamp, human identity |
| Context window capture (if recorded) | Full context window contents including retrieved documents |
| Tool output records | Content returned by each tool call that was fed back into context |
| Conversation transcript (if available) | Full turn-by-turn exchange between human and agent |

### Evidence Collection Commands

```bash
# Retrieve the system prompt version active at the time of the incident
POLICY_COMMIT=$(jq -r '.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "session_start") | .system_prompt_commit' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json)

git -C /path/to/system-prompts-repo show ${POLICY_COMMIT}:prompts/${AGENT_ROLE}.txt

# Retrieve the session initiation record (task description + human principal)
jq '.[] | select(.session_id == "'${SESSION_ID}'" and .event_type == "session_start")' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# Retrieve all tool outputs that were fed into context (potential injection sources)
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "tool_result")]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json
```

### Injection Indicators in Q2 Analysis

When comparing Q2 (what the agent was instructed to do) with Q1 (what the agent actually did), discrepancies indicate the agent deviated from legitimate instructions. Common patterns:

- Agent took actions outside the stated task scope (e.g., task was "analyze PR #123" but agent merged PR #456)
- Agent's actions align with instruction-like language found in tool outputs or retrieved documents
- Agent's actions occurred after a tool returned content containing imperative phrases ("you should", "please", "immediately")

---

## Question 3: What Data Did It Access or Transmit?

**Purpose:** Establish the data plane impact — what sensitive data the agent read, copied, summarized, or transmitted.

**Scope:** Files read, API responses received, content posted to external systems, content included in outputs returned to human principals.

### Why Data Impact Requires a Dedicated Question

Tool call records (Q4) establish *which tools were invoked*. Q3 establishes *what data moved through those tool calls*. These are distinct questions:

- An agent that read 200 source files via `file.read` tool calls (Q4 record) may have transmitted the contents of those files in a summary to an external system (Q3 impact)
- An agent that queried an internal vulnerability database (Q4 record) may have included the unredacted findings in a PR comment visible to external contributors (Q3 impact)

Data access scope determines regulatory notification obligations (GDPR, HIPAA, SOC 2), customer notification requirements, and the severity classification of the incident.

### Evidence Sources

| Evidence Source | What It Establishes |
|---|---|
| Tool input parameters in audit log | Which specific files/resources were accessed by name |
| Tool output content in audit log | What data was returned and available in the agent's context |
| Outbound API call records | What content the agent posted, commented, or transmitted externally |
| Agent output records (session transcript) | What the agent communicated back to the human principal |
| DLP and network egress logs | Whether data was transmitted outside the organization's boundary |

### Evidence Collection Commands

```bash
# Extract all file paths accessed during the session
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "tool_call"
  and (.tool_name | startswith("file.")))
  | .input_parameters.path]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# Extract all external API calls (potential data exfiltration)
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "tool_call"
  and .external == true)]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# Check for data transmitted in GitHub comments (visible externally)
gh api /repos/${OWNER}/${REPO}/issues/comments \
  --jq '.[] | select(.user.login == "'${AGENT_SERVICE_ACCOUNT}'"
    and .created_at >= "'${SESSION_START}'")'
```

---

## Question 4: What Tools Did It Invoke and With What Parameters?

**Purpose:** Establish the complete control plane record — every tool call, in sequence, with full input parameters and return values.

**Scope:** All tool invocations in the session, including failed calls (blocked by authorization policy), retried calls, and calls made by subagents spawned within the session.

### The Tool Call Chain as Forensic Evidence

The sequence of tool calls in an agent session is analogous to a process execution tree in a traditional forensic investigation. It shows:

- **Operational logic:** Did the agent follow a predictable, task-appropriate sequence of tool calls? Or does the sequence indicate deviation — unexpected pivots, unusual targets, escalating access patterns?
- **Injection indicators:** Did the sequence change after a tool returned content that contained instruction-like language?
- **Authorization violations:** Were any tool calls blocked by the authorization policy? Blocked calls are significant — they indicate the agent attempted an action outside its authorized scope, whether due to compromise or misconfiguration.

### Evidence Sources

| Evidence Source | What It Establishes |
|---|---|
| Agent audit trail, event_type=tool_call | Full tool call sequence: tool name, input parameters, timestamp |
| Agent audit trail, event_type=tool_blocked | Blocked tool calls: what was attempted and why it was blocked |
| Tool execution layer logs | Independent confirmation of tool calls, outside the agent's own records |
| Multi-agent chain records | Tool calls made by subagents, with parent session linkage |

### Evidence Collection Commands

```bash
# Full ordered tool call sequence for the session
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and (.event_type == "tool_call" or .event_type == "tool_blocked"))
  ] | sort_by(.timestamp)' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# Extract any blocked tool calls (authorization violations)
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "tool_blocked")]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# For multi-agent sessions: reconstruct the full tool call tree across all agents
jq '[.[] | select(.root_session_id == "'${ROOT_SESSION_ID}'"
  and .event_type == "tool_call")
  ] | group_by(.session_id) | map({agent: .[0].agent_role, calls: .})' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json
```

### Sequence Anomaly Indicators

| Pattern | Significance |
|---|---|
| High-consequence action (merge, deploy) immediately following an external data retrieval | Possible injection — external content may have triggered the action |
| Tool calls to resources outside the session's stated task scope | Scope creep or compromise-driven lateral access |
| Blocked call followed by alternative path to same target | Agent attempting to find an unblocked route to an unauthorized action |
| Unusual volume of read calls before a single write | Possible reconnaissance pattern |
| Tool call parameters containing content from external sources (verbatim) | Injection taint — external content influenced tool call parameters |

---

## Question 5: What Was the Authorization Basis for Each Action?

**Purpose:** Evaluate each agent action against the authorization policy in effect at the time — was each action within the agent's authorized scope?

**Scope:** The tool authorization policy version active during the session, the session scope established at initialization, and the human approval records for any approval-gated actions.

### Two-Layer Authorization Evaluation

Authorization evaluation for agent actions has two layers that must both be checked:

**Layer 1 — Tool authorization policy compliance:** Was the tool call permitted by the authorization policy in effect at the time? This is a binary determination: the policy either permitted or prohibited the call. Policy-prohibited calls that succeeded indicate an enforcement failure. Policy-permitted calls are not automatically legitimate — they still require Layer 2 evaluation.

**Layer 2 — Session scope compliance:** Was the tool call within the legitimate scope of the session as established by the human principal's task? An agent authorized by policy to create branches may not be legitimately authorized to create branches unrelated to its assigned task. This layer requires comparing the Q2 record (what the agent was instructed to do) against the Q4 record (what the agent actually did).

### Evidence Sources

| Evidence Source | What It Establishes |
|---|---|
| Tool authorization policy (version from Q2 record) | Which tools were policy-permitted at session time |
| Session initiation record (from Q2) | Task scope as defined by the human principal |
| Human approval records | Which actions were human-approved, by whom, at what time |
| Authorization decision events in audit log | Real-time policy evaluation results for each tool call |

### Evidence Collection Commands

```bash
# Retrieve the authorization policy version in effect during the session
POLICY_VERSION=$(jq -r '.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "session_start") | .authorization_policy_version' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json)

git -C /path/to/policies show ${POLICY_VERSION}:policies/agent-tool-authorization.yaml

# Retrieve all authorization decisions (permitted and blocked) for the session
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and (.event_type == "authorization_permitted"
    or .event_type == "authorization_denied"))]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json

# Retrieve human approval records for approval-gated actions
jq '[.[] | select(.session_id == "'${SESSION_ID}'"
  and .event_type == "human_approval")]' \
  /var/log/agent-audit/$(date +%Y-%m-%d)-audit.json
```

---

## Evidence Mapping by Question

| Question | Primary Evidence | Supporting Evidence | Common Gap |
|---|---|---|---|
| Q1: What did the agent do? | Agent audit trail | Downstream system logs, CloudTrail | Audit trail not tamper-protected; gaps in coverage |
| Q2: What was it instructed to do? | System prompt version, session initiation record | Context window capture, tool outputs | Context window not captured; system prompt not versioned |
| Q3: What data did it access/transmit? | Tool call input parameters, outbound API records | DLP logs, network egress | Tool outputs not logged; external post content not retained |
| Q4: What tools did it invoke? | Agent audit trail (tool_call events) | Tool execution layer independent logs | Subagent calls not correlated with root session |
| Q5: What was the authorization basis? | Policy version, authorization decisions | Human approval records | Policy not version-controlled; approval not recorded |

---

## Investigation Scope Determination

The Five Questions determine investigation scope through a process of gap analysis and expansion:

**Initial scope:** The session identified as the incident origin (session ID, time range, agent role).

**Scope expansion triggers:**

- Q1 reveals actions in systems outside the initial scope → expand to those systems
- Q2 reveals retrieved content from external sources → investigate those sources as potential injection vectors
- Q3 reveals data transmitted externally → determine what was transmitted and to whom
- Q4 reveals subagent sessions spawned during the parent session → expand to all child sessions
- Q5 reveals authorization policy violations → investigate whether the policy enforcement mechanism was bypassed or misconfigured

**Scope boundary:** Investigation scope is bounded by the root session ID. All agent activity traceable to the same root session (via `root_session_id` in the audit trail) is within scope.

---

## Gap Analysis: When You Cannot Answer a Question

If the available evidence does not permit answering one of the five questions, that gap must be documented as a finding — not papered over with assumptions.

| Question | Common Evidence Gap | Consequence | Remediation |
|---|---|---|---|
| Q1 | Agent audit trail missing or incomplete | Cannot establish what the agent did; investigation is inconclusive | Implement mandatory agent audit trail before allowing agents in production |
| Q2 | System prompt not versioned; context window not captured | Cannot distinguish legitimate behavior from injection-driven behavior | Version system prompts in git; implement context window logging |
| Q3 | Tool outputs not logged | Cannot establish data access scope; regulatory notification determination is uncertain | Log tool output hashes at minimum; log full output for high-risk tools |
| Q4 | Subagent calls not correlated to root session | Cannot reconstruct multi-agent tool call tree | Enforce root_session_id propagation across all agent tiers |
| Q5 | Authorization policy not version-controlled | Cannot verify what policy was in effect; authorization evaluation is uncertain | Store authorization policies in version control with commit-hash references |

---

## The Five Questions as an Audit Readiness Checklist

The Five Questions framework is both a reactive investigation tool and a proactive audit readiness checklist. An organization can determine whether it is prepared to investigate agent incidents by asking: *if an incident occurred today, could we answer all five questions?*

**Pre-incident readiness assessment:**

```
Q1 Readiness: Is an append-only agent audit trail in place? Are downstream system logs (CloudTrail, GitHub audit log) accessible and retained?

Q2 Readiness: Are system prompts version-controlled in git? Is the session initiation record (human principal identity, task description) captured in the audit trail? Is context window content logged or capturable?

Q3 Readiness: Are tool input parameters (including file paths, resource names, API targets) logged in the audit trail? Are outbound API calls from agent service accounts independently logged?

Q4 Readiness: Are tool call sequences logged with full input parameters? Is the tool execution layer logging independently of the agent runtime? Are subagent calls correlated to their root session?

Q5 Readiness: Are tool authorization policies stored in version control with commit hashes referenced in audit events? Are human approval events logged? Are authorization decision events (permitted and denied) recorded?
```

An organization that can answer "yes" to all of the above is forensically ready. One that cannot answer "yes" to any of Q1–Q5 should treat the unanswered questions as critical security gaps — not just compliance gaps — because an agent incident in that state cannot be fully investigated.

The Forensics Readiness Score (see [readiness-guide.md](readiness-guide.md)) provides a quantitative measure of this readiness across five levels.

---

## Integration with Playbooks

The Five Questions provide the investigative structure; the playbooks provide the step-by-step execution for specific incident types. Each playbook maps its investigation steps to the Five Questions:

| Playbook | Primary Q | Evidence Priority |
|---|---|---|
| AF-01: Unauthorized tool call | Q4, Q5 | Tool call sequence; authorization policy evaluation |
| AF-02: Confirmed prompt injection | Q2, Q4 | Context window content; tool call sequence change point |
| AF-03: Unknown provenance artifact | Q1, Q3 | Artifact creation record; data sourced to produce it |
| AF-04: Permission escalation | Q4, Q5 | Blocked-then-succeeded call sequences; policy gaps |
| AF-05: Multi-agent cascade | Q2, Q4 | Injection entry point; cross-agent tool call tree |
| AF-06: Model supply chain | Q1, Q2 | Model version active at incident time; behavior deviation evidence |

See [agent-forensics.md](../agent-forensics.md) for the complete investigation playbooks.
