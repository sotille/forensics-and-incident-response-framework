# Pipeline Forensics: Investigation Playbooks and Procedures

This document expands the foundational pipeline forensics investigation procedures in [secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md](../../secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md). That document covers incident recognition, triage, evidence preservation, and investigation playbooks PL-01 through PL-06. This document adds:

- Forensic prerequisites gap analysis
- Two new playbook types covering AI/LLM pipeline manipulation and agentic unauthorized action (PL-07, PL-08)
- Post-compromise forensic report template
- Pipeline forensics metrics (MTTD, MTTC, MTTR)

**Read the upstream playbook first.** This document assumes familiarity with PL-01 through PL-06.

---

## Table of Contents

1. [Forensic Prerequisites Gap Analysis](#forensic-prerequisites-gap-analysis)
2. [PL-07: AI/LLM-Assisted Pipeline Manipulation](#pl-07-aillm-assisted-pipeline-manipulation)
3. [PL-08: Agentic Pipeline Unauthorized Action](#pl-08-agentic-pipeline-unauthorized-action)
4. [Post-Compromise Forensic Report Template](#post-compromise-forensic-report-template)
5. [Pipeline Forensics Metrics](#pipeline-forensics-metrics)

---

## Forensic Prerequisites Gap Analysis

Before an incident occurs, assess your pipeline forensics readiness against this gap analysis. Each item maps to a specific investigation step in the playbooks. Items marked **Critical** will cause investigation failure if absent.

### Evidence Sources

| Prerequisite | Required By | Gap Check | Remediation |
|---|---|---|---|
| CI audit log exported to tamper-evident store | All playbooks | Is the audit log shipped to S3 Object Lock or SIEM with WORM storage? If only available in the CI platform UI, it is not forensically protected. | See [architecture.md — CI/CD Audit Trail](architecture.md) |
| Pipeline run logs retained > 90 days | All playbooks | Does the CI platform auto-delete run logs before 90 days? GitHub Actions defaults to 90 days — configure explicitly. | Set retention policy explicitly; export logs to external store |
| Vault audit log active and shipped to SIEM | PL-03, PL-04 | Check `vault audit list`. If empty, Vault audit is not active. | `vault audit enable file file_path=/var/log/vault/audit.log` |
| Git repository reflog preserved | PL-01 | Is the repository mirrored to an external system that preserves the reflog? | Set up repository mirroring to a separate Git hosting system |
| Branch protection preventing force-push | PL-01 | Are force pushes disabled on the default branch in all production repositories? | GitHub: Settings → Branches → Branch protection rules → uncheck "Allow force pushes" |
| SLSA provenance for production artifacts | PL-02 | Does `cosign verify-attestation --type slsaprovenance` return a valid attestation for recent production images? | See [implementation.md Phase 2](implementation.md) |
| Cosign signatures on production artifacts | PL-02, PL-05 | Does `cosign verify` succeed for recent production images? | See [implementation.md Phase 2](implementation.md) |
| Network egress logging from CI runners | PL-03 | Are VPC Flow Logs enabled for the subnet containing CI runners? For GitHub Actions, is a network monitoring integration active? | Enable VPC Flow Logs; for GitHub-hosted runners, use network audit via OIDC token metadata |
| OIDC used instead of long-lived credentials | PL-03, PL-04 | Are any long-lived AWS/GCP/Azure credentials stored in CI platform secrets? | Replace with OIDC federation (see [devsecops-framework](../../devsecops-framework/docs/)) |
| Agent tool call logs active | PL-07, PL-08 | Are structured tool call logs shipped to tamper-evident store? | See [agent-forensics.md — Forensic Readiness](agent-forensics.md) |

### Critical Gap: No Artifact Signing

If Cosign signatures and SLSA provenance are absent, the investigation for artifact compromise (PL-02) cannot produce a definitive finding. Without a signed provenance attestation, you cannot:
- Prove which pipeline run produced a given artifact
- Verify that the artifact was not tampered with after the build
- Identify the source commit that was used as build input

In this state, any artifact produced during a potential compromise window must be treated as potentially compromised, regardless of registry access logs.

**Interim procedure** (if signing is not yet deployed): For each artifact produced during the compromise window, collect and hash the artifact, retrieve all registry push events for the artifact's repository, correlate with CI pipeline runs by timestamp, and treat the artifact as suspect if correlation is incomplete.

---

## PL-07: AI/LLM-Assisted Pipeline Manipulation

### Threat Model

This playbook addresses a class of attack that became operationally relevant as organizations began using AI/LLM-powered tools for code review, PR analysis, vulnerability triage, and automated code generation in their CI/CD pipelines. The attack surface is the AI model's context window: an attacker who can influence the content that an AI system reads can influence the AI system's outputs, which may in turn influence pipeline behavior.

**Attack vectors**:
- Malicious instructions embedded in PR descriptions, commit messages, or code review comments that are read by an AI PR review agent
- Malicious content in issue titles, JIRA descriptions, or Slack messages that are fetched by an AI triage agent with write access to pipeline configuration
- Prompt injection in dependency package names, README files, or SBOM content that is processed by an AI security analysis agent
- Malicious instructions embedded in test output that is summarized by an AI agent

**Indicators**:
- An AI agent performed an action (PR approval, pipeline trigger, label application, configuration change) that is inconsistent with the system prompt's authorization scope
- A pipeline was modified or triggered in a way that correlates with AI agent activity but not with human activity
- An AI agent's output contains instructions that are syntactically similar to prompt injection patterns (unusual formatting, overrides of previous instructions, role assumption commands)
- An AI-generated code suggestion introduced a security vulnerability that, on analysis, appears consistent with a backdoor or data exfiltration pattern

### Investigation Steps

```bash
# 1. Identify the AI agent session ID and time window from the suspicious action
# Look for the action in the CI platform audit log
gh api "/orgs/${ORG}/audit-log" \
  --field phrase="action:workflows actor:${AI_BOT_USER}" \
  --field created=">=${INCIDENT_START}" \
  | jq '.[] | {timestamp: .created_at, action: .action, repo: .repo, actor: .actor}'

# 2. Retrieve the tool call logs for the agent session
# (Assumes tool call logs are in SIEM — adjust query for your SIEM)
curl -s -H "Authorization: Bearer ${SIEM_TOKEN}" \
  "${SIEM_URL}/api/search" \
  --data "{
    \"index\": \"agent-tool-calls\",
    \"query\": {\"agent_id\": \"${AGENT_ID}\", \"session_id\": \"${SESSION_ID}\"},
    \"time_range\": {\"from\": \"${INCIDENT_START}\", \"to\": \"${INCIDENT_END}\"}
  }" \
  | jq '[.[] | {timestamp, tool_name, tool_input, authorization_decision}]' \
  > agent-tool-calls.json

# 3. Retrieve the system prompt hash that was in effect during the session
jq '.[] | select(.timestamp == (. | .timestamp | first)) | .system_prompt_hash' \
  agent-tool-calls.json

# 4. Retrieve the system prompt at that hash and review it
git log --all --oneline -- system-prompts/
git show ${SYSTEM_PROMPT_HASH:0:12}:system-prompts/${AGENT_NAME}.txt

# 5. Retrieve the full model input/output pairs for the session
# (These are in the restricted-access evidence store)
aws s3 cp \
  s3://${FORENSICS_BUCKET}/agent-sessions/${SESSION_ID}/turns.json \
  ./session-turns.json

# 6. Identify the external content that was injected into the agent's context
# Find which turns included content from external sources (PR description, issue, etc.)
jq '.[] | select(.content_source != "user" and .content_source != "system") | {
  turn: .turn,
  content_source: .content_source,
  content_source_ref: .content_source_ref,
  content_hash: .content_hash
}' session-turns.json

# 7. Retrieve the external content that may have contained the injection
# Example: retrieve the PR description that was read by the agent
gh api /repos/${ORG}/${REPO}/pulls/${PR_NUMBER} \
  | jq '{title, body, user: .user.login, created_at, updated_at}' \
  > pr-content-at-incident.json

# 8. Compare the agent's actual tool calls against what the system prompt authorizes
# Check whether the tool calls in agent-tool-calls.json are within scope
# of the system prompt's stated authorization boundary
echo "Authorized tools per system prompt:"
grep -E "you may use|you can use|authorized tools|available tools" \
  system-prompts/${AGENT_NAME}.txt

echo "Tools actually invoked during session:"
jq -r '.[].tool_name' agent-tool-calls.json | sort -u

# 9. Check if the anomalous action correlates with external content ingestion
# The injection typically causes the model to output a command or take an action
# immediately after the injected content is read
jq '[.[] | {turn, role, content_source, content_hash}] |
    group_by(.turn) | map(select(length > 1))' session-turns.json
```

**Indicators of Prompt Injection in Logs**:
- The model output for the turn immediately following external content ingestion contains unusual formatting, instructions, or commands
- The model invoked a tool that it had not invoked in any previous session for the same type of task
- The model's stated reasoning (if logged) references instructions that are not in the system prompt
- An `authorization_decision: DENY` event in the tool call log indicates the authorization policy caught an out-of-scope tool call — this should trigger immediate investigation even if the call was blocked

**Root Cause Identification**:
- Review the external content that was ingested in the turn preceding the anomalous tool call
- Compare the model's output reasoning against the system prompt's authorization scope
- Determine whether the injection was targeted (crafted specifically for the agent's capabilities) or opportunistic (generic injection attempt that happened to succeed)

**Containment**:
1. Suspend the agent from further operation until the investigation is complete
2. Revert any actions the agent took during the compromised session (PR approvals, pipeline triggers, label changes, configuration modifications)
3. Review all artifacts created or modified by the agent during the session window
4. Quarantine any downstream artifacts that may have been produced based on the compromised agent's actions

---

## PL-08: Agentic Pipeline Unauthorized Action

### Threat Model

This playbook addresses scenarios where an AI agent that is integrated into the pipeline executes actions that are outside its authorized scope — not because of prompt injection, but because of misconfigured tool permissions, policy gaps, or overly broad authorization boundaries. This is a configuration failure rather than an external attack, but the forensic investigation and remediation are similar.

**Indicators**:
- An agent created a PR, merged a PR, triggered a deployment, or modified infrastructure that it was not intended to have authority over
- An agent accessed a secret, environment variable, or configuration resource that is outside its documented authorization scope
- An agent escalated its own permissions — modified the tool authorization policy, modified its own system prompt, or added itself to a privileged group
- An agent performed an action on a production environment when its authorization scope was limited to non-production

### Investigation Steps

```bash
# 1. Enumerate all actions taken by the agent across all sessions in the incident window
jq -s 'flatten |
  map(select(.agent_id == "${AGENT_ID}")) |
  sort_by(.timestamp) |
  .[] | {timestamp, session_id, tool_name, tool_input, authorization_decision}' \
  /path/to/tool-call-logs/*.json \
  > all-agent-actions.json

# 2. Retrieve the tool authorization policy at the time of the unauthorized action
git show HEAD:policies/agent-tool-authorization.yaml

# 3. Verify the authorization policy version in the tool call log matches the current policy
POLICY_VERSION_IN_LOG=$(jq -r '.[] | select(.session_id == "${SESSION_ID}") | .authorization_policy_version | first' all-agent-actions.json)
git log --oneline -- policies/agent-tool-authorization.yaml | head -10

# 4. Compare what the agent did against what the policy authorizes
echo "=== POLICY: authorized tools for ${AGENT_ROLE} ==="
yq '.roles.${AGENT_ROLE}.allowed_tools[]' policies/agent-tool-authorization.yaml

echo "=== ACTUAL: tools invoked by agent ==="
jq -r '.[].tool_name' all-agent-actions.json | sort -u

# 5. Find the specific tool call that exceeded authorization
jq '.[] | select(.authorization_decision == "ALLOW" and (.tool_name | IN("${UNAUTHORIZED_TOOLS}")))' \
  all-agent-actions.json

# 6. Determine the full scope of what the agent did with the unauthorized tool
# Example: agent invoked github_merge_pr on a production repository
jq '.[] | select(.tool_name == "github_merge_pr")' all-agent-actions.json \
  | jq '{session_id, timestamp, pr_number: .tool_input.pull_request_number, repo: .tool_input.repository}'

# 7. Retrieve the PR that was merged and assess the code change
gh api /repos/${ORG}/${REPO}/pulls/${PR_NUMBER}/files \
  | jq '[.[] | {filename, additions, deletions, patch}]' \
  > unauthorized-merge-files.json

# 8. Assess downstream impact: was any artifact built from the unauthorized merge?
# Check CI runs triggered by the unauthorized merge commit
gh run list \
  --repo ${ORG}/${REPO} \
  --commit ${MERGE_COMMIT_SHA} \
  --json databaseId,status,conclusion,startedAt,name \
  > runs-from-unauthorized-merge.json

# 9. If an artifact was built, verify its status in production
# Was the artifact deployed? Was it deployed to production?
kubectl get pods -A -o json \
  | jq --arg sha "${MERGE_COMMIT_SHA}" \
  '.items[] | select(.spec.containers[].image | contains($sha)) | {
    namespace: .metadata.namespace,
    pod: .metadata.name,
    image: .spec.containers[].image
  }'
```

**Root Cause Categories**:

| Root Cause | Indicator | Remediation |
|---|---|---|
| Tool authorization policy too broad | Agent had legitimate authorization to use the tool on a different scope (e.g., staging) but no scope restriction prevented production use | Add scope constraints to tool authorization policy (repository allowlist, environment constraints) |
| Policy gap: tool was added without updating authorization policy | No policy entry for the tool; default-allow behavior | Review all agent tools against policy; add explicit DENY for sensitive tools; implement default-deny policy |
| System prompt authorized more than intended | System prompt language was ambiguous about scope | Rewrite system prompt with explicit scope statements; test against authorization policy evaluation |
| Policy evaluation bug | Tool call logs show `authorization_decision: ALLOW` for a call that should have been denied | Audit the authorization evaluation logic; treat all past tool calls since the bug was introduced as potentially unauthorized |
| Agent self-modified its authorization scope | Agent created or updated a policy file, modified a system prompt, or added itself to an IAM group | This is a critical finding — treat as a potential security incident, not just a misconfiguration |

---

## Post-Compromise Forensic Report Template

The following template is the minimum required content for a post-compromise report submitted to stakeholders after a pipeline forensics investigation.

```markdown
# Pipeline Compromise Investigation Report

**Incident ID**: INC-{YYYYMMDD}-{N}
**Classification**: [Confidential / Attorney-Client Privileged]
**Report Date**: {ISO8601}
**Report Author**: {Name, Title}
**Investigation Period**: {start} to {end}
**Playbook(s) Applied**: PL-{XX}

---

## Executive Summary

{2-3 sentence summary of what happened, when it was detected, and what action was taken.
Non-technical language. No speculation — only confirmed findings.}

---

## Confirmed Timeline

| Time (UTC) | Event | Evidence Source | Confidence |
|---|---|---|---|
| {timestamp} | {event description} | {log source + reference} | High / Medium / Low |

---

## Root Cause

**Confirmed root cause**: {1-2 sentences describing the specific control failure or attacker action that initiated the compromise}

**Contributing factors**:
- {factor 1}
- {factor 2}

---

## Blast Radius

**Systems confirmed affected**:
- {list with evidence reference for each}

**Systems confirmed not affected** (with evidence):
- {list with evidence reference for each}

**Systems where impact is undetermined**:
- {list with reason why determination was not possible}

---

## Artifacts

| Artifact | Digest | Status | Evidence |
|---|---|---|---|
| {image name} | {digest} | Compromised / Verified Clean / Undetermined | Cosign verify output / provenance ref |

---

## Credentials and Secrets

| Credential | Type | Confirmed Accessed | Rotated | Notes |
|---|---|---|---|---|
| {credential name} | API key / OIDC / service account | Yes / No / Unknown | Yes / Pending | |

---

## Actions Taken

**Containment**:
- {action 1 with timestamp}
- {action 2 with timestamp}

**Eradication**:
- {action 1 with timestamp}

**Recovery**:
- {action 1 with timestamp}

---

## Metrics

| Metric | Value |
|---|---|
| MTTD (detection time from initial compromise) | {duration} |
| MTTC (time from detection to containment) | {duration} |
| MTTR (time from detection to full recovery) | {duration} |

---

## Recommendations

| ID | Recommendation | Priority | Owner | Target Date |
|---|---|---|---|---|
| R-01 | {specific, actionable recommendation} | P1/P2/P3 | {team} | {date} |

---

## Evidence Inventory

All evidence collected during this investigation is stored at:
`s3://${FORENSICS_BUCKET}/incident-packages/INC-{ID}/`

Integrity verification:
```bash
aws s3 cp s3://${FORENSICS_BUCKET}/incident-packages/INC-{ID}/MANIFEST.sha256 .
sha256sum --check MANIFEST.sha256
```

Evidence retained until: {date, per retention schedule}

```

---

## Pipeline Forensics Metrics

These metrics measure the effectiveness of pipeline forensics capability. Measure each metric per incident type (PL-01, PL-02, etc.) to identify where detection or response gaps exist.

### MTTD — Mean Time to Detect

**Definition**: The time from the initial compromise event (as determined by investigation) to the time the incident was detected and an investigation was opened.

**Measurement**:
```
MTTD = detection_timestamp - initial_compromise_timestamp
```

The initial compromise timestamp is determined from the investigation timeline; the detection timestamp is the time the alert or report was received.

**Target benchmarks** (industry-informed):

| Incident Type | Good | Acceptable | Poor |
|---|---|---|---|
| PL-01: Malicious pipeline code injected | < 1 hour (SIEM rule fires on push to workflow file outside PR) | < 24 hours | > 24 hours |
| PL-02: Compromised build artifact | < 15 minutes (signature verification fails at deploy gate) | < 4 hours | > 4 hours |
| PL-03: Secret exfiltration from pipeline | < 30 minutes (anomalous network egress or secret access alert) | < 4 hours | > 4 hours |
| PL-07: AI/LLM-assisted manipulation | < 4 hours (tool call authorization anomaly alert) | < 24 hours | > 24 hours |
| PL-08: Agentic unauthorized action | Real-time (authorization policy evaluation alert on DENY or out-of-scope ALLOW) | < 1 hour | > 1 hour |

### MTTC — Mean Time to Contain

**Definition**: The time from detection to containment — when the attacker's ongoing access is stopped.

**Target**: P1 incidents — MTTC < 30 minutes. P2 incidents — MTTC < 4 hours.

### MTTR — Mean Time to Recover

**Definition**: The time from detection to full recovery — when services are restored with verified artifact integrity, rotated credentials, and hardened controls.

**Target**: P1 incidents — MTTR < 4 hours for containment; < 24 hours for full recovery. P2 — MTTR < 24 hours.

### Pipeline-Specific Leading Indicator Metrics

In addition to the lag indicators above, track these leading indicators that predict pipeline forensics capability:

| Metric | Measurement | Target |
|---|---|---|
| % production pipelines with Cosign signing | Count(signed pipelines) / Count(all production pipelines) | 100% |
| % production artifacts with verifiable SLSA provenance | Count(provenance verified) / Count(deployments in period) | 100% |
| CI audit log export gap rate | Count(export failures in period) / Count(expected exports) | 0% |
| Pipeline signature verification enforcement | Is the Kyverno/Gatekeeper policy in Enforce mode? | Yes |
| Agent tool call log coverage | % of agent tool calls that appear in tamper-evident log | 100% |
