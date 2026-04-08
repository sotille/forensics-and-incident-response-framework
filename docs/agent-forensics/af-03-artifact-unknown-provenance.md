# AF-03 — Agent-Generated Artifact of Unknown Provenance in Production

**Playbook ID:** AF-03  
**Domain:** Agent Forensics  
**Version:** 1.0 — 2026-04-08  
**Related playbooks:** AF-01 (Prompt Injection Unauthorized Action), AF-04 (Agent Permission Escalation), PL-02 (Compromised Build Artifact), PS-01 (AI Supply Chain Attack)  
**Related framework docs:**  
- `forensics-and-incident-response-framework/docs/agent-forensics.md`  
- `forensics-and-incident-response-framework/docs/agent-forensics/five-questions-framework.md`  
- `forensics-and-incident-response-framework/docs/supply-chain-forensics.md`  
- `ai-devsecops-framework/docs/agent-audit-trail.md`  
- `ai-devsecops-framework/docs/blast-radius-containment.md`  
- `secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md` (PL-02)

---

## Purpose and Scope

This playbook governs the forensic investigation of a software artifact found in a production or near-production environment that cannot be traced to a known, authorized agent session and approval chain. "Unknown provenance" means one or more of the following:

- The artifact lacks a valid Cosign signature from an authorized signing identity
- The SLSA provenance attestation is absent, invalid, or references an agent session with no human-authorized task initiation
- The artifact digest does not match any known build run in the CI audit log
- The artifact appeared in the registry or deployment environment without a corresponding pipeline execution record
- The agent session that produced the artifact processed external data sources that may have manipulated its behavior before artifact creation

**Trigger conditions for this playbook:**

- `cosign verify` fails for a production artifact or returns a signing identity outside the approved identity set
- `slsa-verifier verify-artifact` fails or references a session with anomalous build inputs
- Registry push event in audit log is not correlated with any authorized pipeline run
- AI agent session log shows a commit, push, or registry upload to a production-scoped target that was not in the agent's system prompt instructions
- Dependency-Track flags a new component with an unrecognized attestation identity
- A human reviewer identifies a code change or deployed configuration that no human authored and no pipeline build record explains

**Out of scope:** Artifacts produced by legitimate agent sessions where the authorization chain is intact but the artifact contains a security vulnerability. Use standard vulnerability management for those.

---

## Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| Incident Commander | Declares incident severity, owns stakeholder communication, authorizes production rollback |
| Agent Forensics Investigator | Leads technical investigation; owns Five Questions analysis |
| Platform / AI Infrastructure Team | Provides audit log access, CI/CD configuration, registry access logs |
| Application Security | Validates artifact integrity; assesses what was deployed and what it can affect |
| Release Engineering | Retrieves and validates production deployment records; executes rollback if required |
| Legal / Compliance | Assesses regulatory notification obligations if production data was accessible to the unauthorized artifact |

---

## Critical Precondition: Quarantine the Artifact Before Investigation

**BEFORE any other action:** Quarantine the artifact and prevent further propagation.

```bash
# Step 1: Mark the artifact suspect in the registry (do NOT delete — preserve for forensic analysis)
# If the artifact is a container image:
crane tag ${REGISTRY}/${REPO}:${TAG} ${REGISTRY}/${REPO}:forensic-hold-af03-$(date +%Y%m%d)

# Step 2: Block promotion to additional environments
# Add an OPA/Kyverno deny policy for the artifact digest
cat > /tmp/deny-artifact.yaml << EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-suspect-artifact-af03
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-suspect-digest
      match:
        any:
        - resources:
            kinds:
            - Pod
      validate:
        message: "Suspect artifact quarantined under AF-03 investigation — blocked from deployment"
        deny:
          conditions:
            any:
            - key: "{{request.object.spec.containers[].image}}"
              operator: Contains
              value: "${ARTIFACT_DIGEST}"
EOF
kubectl apply -f /tmp/deny-artifact.yaml

# Step 3: If artifact is already deployed to production, assess immediate risk
# (see Phase 3 — Blast Radius Assessment) before deciding on runtime removal
```

Seal the audit record with a forensic event marker:

```json
{
  "event_type": "forensic_investigation_start",
  "playbook": "AF-03",
  "artifact": {
    "type": "container_image|binary|package|iac_config",
    "digest": "<sha256:...>",
    "registry_path": "<registry/repo:tag>",
    "first_seen_in_production": "<ISO-8601>"
  },
  "investigator": "<name>",
  "timestamp": "<ISO-8601>",
  "trigger": "<describe what triggered this investigation>"
}
```

---

## Phase 1 — Answering the Five Forensic Questions

### Q1 — What did the agent do?

Reconstruct every action the suspected agent session took before and during artifact creation.

```bash
# Retrieve all tool calls from the suspected session
jq '[.[] | select(.session_id == "${SESSION_ID}") |
  {turn: .turn, tool: .tool_name, operation: .operation,
   params: .params, timestamp: .timestamp, outcome: .outcome}
] | sort_by(.turn)' agent-tool-calls.json

# Identify artifact-creation events: commits, registry pushes, file writes, deployments
jq '[.[] | select(.session_id == "${SESSION_ID}") |
  select(.tool_name | IN(
    "github.commit.write", "github.pr.write", "registry.push",
    "iac.apply", "deploy.trigger", "storage.write"
  ))]' agent-tool-calls.json

# For each identified artifact-creation event, record:
# - Tool + operation
# - Target repository / registry / environment
# - Commit SHA or artifact digest
# - Timestamp
# - Whether an approval gate was recorded as cleared
```

Expected output: Complete ordered list of artifact-creation actions with their targets, timestamps, and authorization gate records.

### Q2 — What was the agent instructed to do?

Determine what task the agent was legitimately authorized to perform and verify whether artifact creation was within that scope.

```bash
# Retrieve system prompt at session-start time
git show ${SYSTEM_PROMPT_COMMIT_HASH}:system-prompts/${AGENT_NAME}.txt > /tmp/system-prompt-at-incident.txt

# Retrieve the task instruction provided at session initiation
jq 'select(.event_type == "session_start" and .session_id == "${SESSION_ID}")' \
  agent-session-events.json

# Compare permitted tools with tools actually invoked
# The system prompt or tool authorization policy governs which artifact types the agent
# was permitted to create
git show ${POLICY_VERSION}:policies/agent-tool-authorization.yaml \
  | yq '.agents.${AGENT_ROLE}.tools'
```

**Authorization scope verification:**

| Question | Expected Source | Finding |
|----------|----------------|---------|
| Was artifact creation in the agent's permitted tool list? | Tool authorization policy at session time | |
| Was the target environment (registry, repo) in the permitted scope? | Policy constraints | |
| Was a human-approved task the origin of the session? | Session initiation audit record | |
| Did the system prompt authorize production-scoped artifact creation? | System prompt at session start | |

### Q3 — What data did the agent access or transmit before creating the artifact?

Identify every external data source the agent read during the session. Determine whether any source could have influenced the agent to produce an artifact it was not authorized to create.

```bash
# Reconstruct session turn-by-turn with external content sources
jq '[.[] | select(.session_id == "${SESSION_ID}") |
  select(.content_source != "system_prompt" and .content_source != "user_instruction") |
  {turn: .turn, source_type: .content_source, source_ref: .content_source_ref,
   content_length: (.content | length)}
] | sort_by(.turn)' session-turns.json

# Flag turns with high-risk external source types
jq '.[] | select(.content_source | IN(
  "github_pr_description", "github_issue", "github_commit_message",
  "code_comment", "sbom_metadata", "cve_description", "jira_ticket",
  "slack_message", "rag_corpus_result"
))' session-turns.json
```

For each high-risk content source, retrieve the actual content and inspect for injection patterns:

```bash
# For PR descriptions: retrieve the PR at the time of the session
gh api /repos/${ORG}/${REPO}/pulls/${PR_NUMBER} \
  --jq '{title: .title, body: .body, user: .user.login}'

# For commit messages: retrieve by SHA
git log --format='%H %s%n%b' ${COMMIT_SHA} -1
```

**Content anomaly indicators:**
- Text containing override phrases: "ignore previous instructions", "new task:", "your instructions have been updated"
- JSON-formatted tool call specifications embedded in data content
- Text directing the agent to push, deploy, or create artifacts in production
- Instructions claiming special authority (administrator override, emergency deployment, security team directive)

### Q4 — What tools did the agent invoke to produce the artifact?

Map the complete artifact creation pathway from source to registry.

```bash
# Reconstruct the build/push pathway
jq '[.[] | select(.session_id == "${SESSION_ID}") |
  select(.tool_name | test("commit|push|build|sign|tag|upload|deploy"))] |
  sort_by(.turn)' agent-tool-calls.json

# For each step, verify:
# 1. Was this tool invocation permitted by the authorization policy?
# 2. Was an approval gate cleared before this invocation?
# 3. Did the tool invocation use session-scoped credentials or standing credentials?

# Verify artifact signing identity used during the session
cosign verify \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${ARTIFACT_DIGEST} | jq '{identity: .[] | .optional.Issuer + "/" + .optional.Subject}'
```

### Q5 — What was the authorization basis for artifact creation?

Determine whether a human-initiated, approved task chain exists for this artifact.

```bash
# Trace from artifact back to human authorization
# Step 1: Get the agent session ID that produced the artifact from registry audit log
aws ecr describe-image-scan-findings --repository-name ${REPO} \
  --image-id imageDigest=${ARTIFACT_DIGEST}

# For GitHub Actions: correlate push event to workflow run
gh run list --repo ${ORG}/${REPO} --workflow ${WORKFLOW_FILE} \
  --created ">${WINDOW_START}" --created "<${WINDOW_END}" \
  --json databaseId,status,createdAt,headSha,triggeredBy

# For each workflow run: was it triggered by a human push, PR, or a bot?
# Bot-triggered runs require a human-authorized parent event
gh run view ${RUN_ID} --json triggeredBy,event,headBranch,headSha

# Step 2: Verify the task initiation chain
# Human approval → session start → artifact creation
# If any link is missing, the authorization basis is UNDETERMINED or UNAUTHORIZED
```

**Authorization determination:**

| Finding | Classification |
|---------|---------------|
| Signed artifact; valid SLSA provenance; human-authorized pipeline trigger; tool calls within policy | AUTHORIZED |
| Artifact lacks signature OR SLSA provenance missing OR trigger is automated with no human parent | UNAUTHORIZED — investigate further |
| Signing identity valid but session processed injected content before artifact creation | POTENTIALLY COMPROMISED — treat as unauthorized pending full Q3 analysis |
| No agent session log for the signing event | UNDETERMINED — missing forensic infrastructure |

---

## Phase 2 — Artifact Integrity Analysis

### 2.1 Static Integrity Verification

```bash
# Verify artifact signature and provenance
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/${ORG}/" \
  ${ARTIFACT_URI}

slsa-verifier verify-artifact ${ARTIFACT_PATH} \
  --provenance-path ${PROVENANCE_BUNDLE} \
  --source-uri "github.com/${ORG}/${REPO}" \
  --source-tag "${TAG}"

# If the artifact is a container image: scan for embedded indicators
trivy image --security-checks vuln,secret,config ${ARTIFACT_URI}
crane export ${ARTIFACT_URI} | tar -t | grep -E "\.(sh|py|ps1|exe|dll)$"

# Compute and record artifact digest for chain of custody
sha256sum ${ARTIFACT_PATH} > /tmp/af03-artifact-digest.txt
```

### 2.2 Behavioral Analysis (if artifact was deployed)

If the artifact reached a runtime environment, collect behavioral evidence before removing it.

```bash
# Collect syscall profile from a sandboxed run of the artifact (do NOT run in production)
# For container images: use Falco in a dedicated investigation namespace
kubectl create namespace forensic-investigation
kubectl run artifact-analysis \
  --image=${ARTIFACT_URI} \
  --namespace=forensic-investigation \
  --restart=Never \
  -- sleep 60

# Collect Falco events from the namespace
kubectl logs -n forensic-investigation -l app=falco --since=5m | \
  jq 'select(.k8s.ns.name == "forensic-investigation")'

# Record network connections attempted
kubectl exec -n forensic-investigation artifact-analysis -- \
  ss -tnp 2>/dev/null
```

---

## Phase 3 — Blast Radius Assessment

### 3.1 Assess Production Impact

| Question | Assessment |
|----------|------------|
| Is the artifact currently deployed to production? | |
| What systems, services, or data does it have access to? | |
| What external network destinations has it communicated with? | |
| What credentials, secrets, or environment variables was it exposed to at runtime? | |
| What data did it read, write, or transmit? | |
| How long has it been deployed? | |

### 3.2 Production Removal Decision

| Condition | Action |
|-----------|--------|
| Artifact deployment confirmed unauthorized AND artifact not yet in production | Block immediately; do not promote |
| Artifact in production AND behavioral evidence shows active malicious activity | Immediate removal with traffic cutover to known-good version |
| Artifact in production AND no behavioral anomalies confirmed | Controlled removal with documented rollback procedure; prioritize credential rotation |
| Artifact in production AND no prior known-good version | Freeze environment, conduct emergency review, consult legal before removal |

### 3.3 Credential and Secret Rotation

For every credential the artifact had access to during deployment:

```bash
# Identify credentials from the deployment environment spec
kubectl get pod ${POD_NAME} -o jsonpath='{.spec.containers[].env}' | jq '.[] | select(.valueFrom.secretKeyRef)'
kubectl get pod ${POD_NAME} -o jsonpath='{.spec.volumes}' | jq '.[] | select(.secret)'

# Rotate all identified credentials regardless of whether active use is confirmed
# Treat any credential that was in scope as potentially compromised
```

---

## Phase 4 — Containment and Remediation

### 4.1 Remove and Quarantine the Artifact

```bash
# Tag the artifact for forensic hold (do NOT delete yet — chain of custody requires it)
crane tag ${REGISTRY}/${REPO}:${TAG} ${REGISTRY}/${REPO}:af03-forensic-hold

# Remove from active use
# For Helm deployments:
helm rollback ${RELEASE} ${PRIOR_REVISION} --namespace ${NAMESPACE}

# For raw Kubernetes deployments:
kubectl set image deployment/${DEPLOYMENT} ${CONTAINER}=${KNOWN_GOOD_IMAGE}
```

### 4.2 Mandatory Control Improvements

Based on the investigation findings, implement the following before re-enabling the agent:

| Gap | Required Control | Reference |
|-----|-----------------|-----------|
| Artifact lacked Cosign signature | Enforce artifact signing in CI; add promotion gate requiring `cosign verify` | `secure-ci-cd-reference-architecture/docs/implementation.md` |
| SLSA provenance missing or invalid | Generate SLSA provenance at build time; block promotion without valid attestation | `secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md` |
| Agent used standing credentials to push | Replace with session-scoped OIDC credentials; set max_duration = task duration | `ai-devsecops-framework/docs/agent-authorization.md` |
| Agent processed injection-vector content before artifact creation | Add input sanitization and canary token; validate output schema before tool invocation | `ai-devsecops-framework/docs/prompt-injection-defense.md` |
| No human approval gate for production artifact push | Add approval gate for all production-scoped registry pushes | `ai-devsecops-framework/docs/blast-radius-containment.md` |
| Agent session log did not capture external content sources | Upgrade audit trail to capture content_source field per turn | `ai-devsecops-framework/docs/agent-audit-trail.md` |

---

## Investigation Closure Requirements

The investigation is closed when all of the following are documented:

- [ ] Q1–Q5 analysis complete with findings recorded for each question
- [ ] Artifact integrity determination: AUTHORIZED / UNAUTHORIZED / POTENTIALLY COMPROMISED / UNDETERMINED
- [ ] Artifact removed from all production environments or cleared as authorized
- [ ] All credentials in scope rotated
- [ ] Root cause documented: injection attack, misconfigured authorization policy, signing infrastructure gap, or other
- [ ] Mandatory control improvements implemented or tracked with owner and deadline
- [ ] Investigation timeline documented: when artifact appeared, when detected, when contained
- [ ] Post-incident report completed for: Technical audience (this document), Executive summary, Legal/Compliance (if personal data was accessible to the artifact)

---

## References

- [Five Forensic Questions Framework](five-questions-framework.md)
- [Agent Forensics Readiness Guide](readiness-guide.md)
- [supply-chain-forensics.md](../supply-chain-forensics.md) — SLSA provenance and Cosign verification procedures
- [ai-devsecops-framework/docs/agent-authorization.md](../../../../ai-devsecops-framework/docs/agent-authorization.md) — Tool authorization policy; session-scoped credentials
- [ai-devsecops-framework/docs/blast-radius-containment.md](../../../../ai-devsecops-framework/docs/blast-radius-containment.md) — Containment control specifications per agent role
- [secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md](../../../../secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md) — PL-02: Compromised Build Artifact
- [ai-devsecops-framework/docs/agent-audit-trail.md](../../../../ai-devsecops-framework/docs/agent-audit-trail.md) — Audit trail requirements; content_source field specification
