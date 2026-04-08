# AF-02 — Multi-Agent Cascade Compromise Investigation

**Playbook ID:** AF-02  
**Domain:** Agent Forensics  
**Version:** 1.0 — 2026-04-08  
**Related playbooks:** AF-01 (Prompt Injection Unauthorized Action), PL-03 (AI Code Review Approval Chain)  
**Related framework docs:**  
- `forensics-and-incident-response-framework/docs/agent-forensics.md`  
- `forensics-and-incident-response-framework/docs/agent-forensics/five-questions-framework.md`  
- `ai-devsecops-framework/docs/multi-agent-architecture.md`  
- `ai-devsecops-framework/docs/blast-radius-containment.md`

---

## Purpose and Scope

This playbook governs forensic investigation of a **cascade compromise** in a multi-agent system: an incident in which a single injection or compromise point propagates adversarial influence through an agent chain, causing multiple downstream agents to take unauthorized actions.

A cascade compromise differs from a single-agent prompt injection (AF-01) in three ways:

1. **The initial injection may not directly cause the harmful action** — the orchestrator agent may behave normally while forwarding injected content to subagents that then act on it.
2. **Multiple agents and systems are affected** — blast radius assessment must span the entire agent chain.
3. **The injection source may appear legitimate** — each agent in the chain processes content from the preceding agent with that agent's authority attached, making the source of malicious instruction difficult to trace without complete audit trails.

**Trigger conditions:**

- Multiple AI agents produced anomalous behavior within a short time window (< 30 minutes between first and last unauthorized action)
- An orchestrator agent's output is confirmed to contain content derived from an external attacker-controlled source, and that output was consumed by one or more subagents
- Circuit breaker fired at multiple points in an agent pipeline within the same session
- Canary token from a sensitive data source appeared in the output of a subagent that should not have accessed that source
- Unauthorized actions were taken by agents with no direct connection to the injection source (indicating content relay through the chain)

**Out of scope:** Single-agent prompt injection incidents (use AF-01). Multi-agent incidents where each agent's compromise was independent (treat each with AF-01 separately and document the coincidence).

---

## Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| Incident Commander | Declares incident; coordinates cross-team response; owns executive communication |
| Agent Forensics Lead | Owns technical investigation; reconstructs the full cascade path |
| Platform / AI Infrastructure | Provides audit logs for all agents in the chain; preserves agent session state |
| Application Security | Assesses cumulative impact of all unauthorized actions across the chain |
| Data Privacy / Legal | Evaluates notification obligations given potentially broad data access |

---

## Critical Precondition: Suspend All Agents in the Suspected Chain

A cascade compromise requires suspending the entire agent chain before investigation — not just the agent where the anomalous action was first observed.

```bash
# Identify all agents in the chain from the orchestrator session ID
# Typically: one orchestrator + N subagents, each with their own pod/container/task

# Kubernetes — suspend all agent pods in the chain's namespace:
AGENT_NAMESPACE="<namespace>"
kubectl get pods -n $AGENT_NAMESPACE -l session-id=<orchestrator-session-id> -o name | \
  xargs -I{} kubectl label {} forensics.suspended=true -n $AGENT_NAMESPACE

# Cordon the nodes hosting these pods:
kubectl get pods -n $AGENT_NAMESPACE -l session-id=<orchestrator-session-id> \
  -o jsonpath='{.items[*].spec.nodeName}' | tr ' ' '\n' | sort -u | \
  xargs kubectl cordon

# Do NOT delete pods. Preserve memory state.

# AWS ECS — stop all tasks associated with the session:
aws ecs list-tasks --cluster <cluster> --family <agent-task-family> \
  --query 'taskArns' --output text | tr '\t' '\n' | \
  xargs -I{} aws ecs stop-task --cluster <cluster> --task {} \
  --reason "Security investigation AF-02 — cascade compromise"
```

Insert forensic event marker into each agent's audit log:
```json
{
  "event_type": "forensic_investigation_start",
  "playbook": "AF-02",
  "cascade_session_id": "<orchestrator-session-id>",
  "agent_role": "<orchestrator|subagent-1|subagent-2|...>",
  "timestamp": "<ISO-8601>"
}
```

---

## Phase 1 — Reconstruct the Cascade Path

### 1.1 Map the Agent Chain

Before applying the Five Questions, you must understand the architecture of the agent chain.

```
Reconstruct from audit logs and configuration:

Agent Chain Map:
  ┌─────────────────────────────────────────────────────────────────┐
  │ ORCHESTRATOR                                                     │
  │   Session ID: <id>                                              │
  │   Tool authorization policy: <policy-version>                   │
  │   Triggered by: <human user / automated scheduler / webhook>    │
  │   Task description: <verbatim from audit log>                   │
  └────────────────────────────┬────────────────────────────────────┘
                               │ delegated to
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
  │ SUBAGENT-1     │  │ SUBAGENT-2     │  │ SUBAGENT-N     │
  │ Role: <role>   │  │ Role: <role>   │  │ Role: <role>   │
  │ Tools: <list>  │  │ Tools: <list>  │  │ Tools: <list>  │
  └────────────────┘  └────────────────┘  └────────────────┘

For each agent:
  - Record: agent role, tool policy version, session start/end time
  - Confirm: did this agent share credentials with any other agent? (shared credentials amplify blast radius)
  - Confirm: did this agent have write access to any shared state that other agents could read?
```

### 1.2 Identify the Injection Entry Point

The entry point is the first agent in the chain that processed attacker-controlled content. It may not be the first agent that took an unauthorized action.

```
Procedure:

1. List all external data sources accessed by each agent (from tool call logs)
2. For each external data source, assess: could an adversary control this content?
   Untrusted sources in DevSecOps pipelines:
   - PR descriptions, titles, commit messages, code comments (controlled by PR authors)
   - CVE database descriptions (partially controlled; NVD entries have been manipulated)
   - Package registry metadata (controlled by package publishers)
   - External issue tracker content (controlled by issue reporters)
   - Webhook payloads from external services (may contain user-controlled content)
   - API responses from external/third-party services (partially controlled)

3. For each untrusted source accessed, check for injection content:
   - Pattern search (see AF-01 Section Q2 for detection commands)
   - Canary token presence check
   - Unicode anomaly check

4. Correlate: which agent processed the injection source first? Which tool call preceded
   the first anomalous action in the chain?

Entry point identified: Agent <role>, tool call <tool> at timestamp <T>
```

### 1.3 Trace Content Relay Through the Chain

Document how the injected content traveled from the entry point to each affected subagent.

```
For each agent-to-agent handoff in the chain, record:

  Handoff N: <source-agent> → <destination-agent>
  Mechanism: [direct tool call / shared queue / database / API response / shared file]
  Content transferred: [summary of what was sent; include verbatim if short]
  Did transferred content include attacker-controlled data? [Yes / No / Partial]
  If yes: identify the field or position within the transferred content that contained
          the injected material

The relay path explains how injection at the orchestrator level caused unauthorized actions
at subagent levels, even if each subagent had appropriate authorization controls in isolation.
```

---

## Phase 2 — Apply Five Questions to Each Agent in the Chain

Apply the Five Questions (from `five-questions-framework.md`) to each agent in the chain. Document separately for each agent role.

**Template for each agent:**

```
Agent Role: <orchestrator / subagent-1 / ...>
Session ID: <session-id>

Q1 — What did this agent do?
  [List all tool calls with timestamps; highlight unauthorized ones]

Q2 — What was this agent instructed to do?
  System prompt version: <SHA or version tag>
  User instruction received: <verbatim from audit log>
  Injection received from: <none / upstream agent output / external data>

Q3 — What data did this agent access or transmit?
  [Files, APIs, environment variables, secrets — classify each as AUTHORIZED / UNAUTHORIZED]

Q4 — What tools did this agent invoke, and with what parameters?
  [Full parameter list for unauthorized tool calls]

Q5 — What was the authorization basis?
  [Authorization table as per AF-01 Q5]
```

---

## Phase 3 — Blast Radius Assessment

### 3.1 Cumulative Impact Across the Chain

Because each subagent may have different tool authorizations and data access, the blast radius of a cascade is typically broader than any individual agent's scope.

```
Construct a cumulative impact table:

| Agent | Unauthorized Actions | Data Accessed | Systems Modified |
|-------|---------------------|---------------|-----------------|
| Orchestrator | [list] | [list] | [list] |
| Subagent-1 | [list] | [list] | [list] |
| Subagent-2 | [list] | [list] | [list] |
| TOTAL | [combined list] | [combined list] | [combined list] |

For each row:
  - Assess whether the unauthorized action from this agent created an input that
    triggered further unauthorized actions in another agent (cascade effect)
  - Estimate the total blast radius: sum of all resources modified, data accessed,
    and external actions taken across the entire chain
```

### 3.2 Shared Credential Assessment

A cascade compromise is particularly dangerous when agents share credentials or ambient authority.

```
For each credential or service account in use across the chain:

  Credential: <name or ARN>
  Agents using this credential: <list>
  Permissions attached: <list>
  Was this credential used to take any unauthorized action? [Yes / No]
  Action required: [Rotate immediately / Audit usage / No action needed]
```

If any shared credential was used in an unauthorized action, rotate it before proceeding to Phase 4.

---

## Phase 4 — Containment and Remediation

### 4.1 Remediate All Unauthorized Actions (Across the Full Chain)

Follow the per-action remediation procedure from AF-01 Section 3.1 for each UNAUTHORIZED entry in the Phase 2 Five Questions analysis.

Priority order:
1. Actions that modified authentication or authorization configuration
2. Actions that transmitted data externally
3. Actions that created or modified code, IaC, or configuration
4. Actions that created or deleted resources

### 4.2 Containment Controls for Multi-Agent Systems

Based on the cascade path identified in Phase 1, deploy the following controls:

| Control | Purpose | Implementation |
|---------|---------|----------------|
| Input validation at every agent boundary | Prevent injected content from propagating through the chain | Validate schema and check for injection patterns on every inter-agent message |
| Separate credentials per agent role | Limit blast radius when one agent is compromised | Each subagent uses a distinct, scoped service account |
| Canary tokens in sensitive data sources | Detect injection before it causes unauthorized action | Embed unique canary strings; alert if they appear in inter-agent messages |
| Circuit breakers with chain-scope awareness | Halt entire chain when anomaly detected at any point | Configure circuit breakers to suspend all downstream agents when triggered |
| Trust levels for inter-agent messages | Treat messages from orchestrator as semi-trusted, not fully trusted | Subagents must validate content from orchestrator, not implicitly execute instructions |

### 4.3 Tool Authorization Policy Update

For each authorization policy gap identified in Phase 2 Q5, update the policy:

```yaml
# Example: after cascade where subagent-1 unexpectedly invoked a write tool

agent_roles:
  subagent-1:
    tools:
      # BEFORE (policy gap): write_file was permitted with any path
      - name: write_file
        allowed_paths: ["*"]  # Too broad — allowed the unauthorized write

      # AFTER (corrected policy): restrict to specific output directory
      - name: write_file
        allowed_paths: ["/workspace/output/"]
        max_file_size_bytes: 1048576
        prohibited_extensions: [".sh", ".py", ".yaml", ".env"]
```

---

## Investigation Closure Requirements

- [ ] All agents in the chain analyzed with Five Questions
- [ ] Cascade path fully documented: entry point → relay path → affected agents
- [ ] Injection vector identified and source remediated
- [ ] All unauthorized actions across the chain reversed or documented as irrecoverable
- [ ] All shared credentials used in unauthorized actions rotated
- [ ] Tool authorization policies updated to close identified gaps
- [ ] Input validation deployed at all inter-agent boundaries
- [ ] Post-incident test: run a controlled injection test against the remediated pipeline to verify controls prevent the same cascade path
- [ ] Audit records sealed and preserved per `evidence-chain-of-custody.md`

---

## References

- `docs/agent-forensics/five-questions-framework.md` — Five Questions procedure
- `docs/agent-forensics.md` — Comprehensive agent forensics methodology
- `docs/agent-forensics/af-01-prompt-injection-unauthorized-action.md` — Single-agent injection (apply per agent in this cascade)
- `docs/evidence-chain-of-custody.md` — Evidence preservation requirements
- `ai-devsecops-framework/docs/multi-agent-architecture.md` — Multi-agent trust boundary design
- `ai-devsecops-framework/docs/blast-radius-containment.md` — Blast radius limits for multi-agent systems
- Glossary: cascade compromise, blast radius, circuit breaker, multi-agent system
