# The Forensics Framework

## Table of Contents

1. [IR Phases](#ir-phases)
2. [The Six Investigation Domains](#the-six-investigation-domains)
3. [Severity Classification System](#severity-classification-system)
4. [The Forensics Readiness Score](#the-forensics-readiness-score)
5. [Cross-Domain Incident Correlation](#cross-domain-incident-correlation)
6. [Investigation Workflow](#investigation-workflow)

---

## IR Phases

All incident response investigations in this framework follow an eight-phase lifecycle. The phases are sequential for any given investigation, but in practice an incident may cycle between phases — new evidence discovered in the Investigate phase may require returning to Contain.

| Phase | Objective | Key Actions | Output |
|---|---|---|---|
| **1. Detect** | Recognize that an incident may have occurred | Review alerts, anomaly signals, external reports; determine if signals warrant investigation | Incident ticket opened; initial severity assigned |
| **2. Triage** | Determine scope, severity, and urgency | Answer: Is this active or historical? What is the blast radius? What evidence exists? Who is on call? | Severity classification (P1/P2/P3); investigation team assembled |
| **3. Contain** | Stop ongoing harm without destroying evidence | Isolate compromised systems, disable compromised credentials, pause affected pipelines | Harm stopped; evidence preserved for investigation |
| **4. Preserve** | Collect and protect all forensic evidence | Export logs, snapshots, artifacts, git state, audit trails to tamper-evident storage before remediation | Evidence package in immutable storage; chain of custody initiated |
| **5. Investigate** | Determine what happened, when, how, and by whom | Root cause analysis, blast radius mapping, attacker timeline reconstruction, cross-domain correlation | Investigation report: timeline, root cause, blast radius, affected systems |
| **6. Eradicate** | Remove attacker access and persistence | Rotate compromised credentials, rebuild compromised systems, remove malicious artifacts | Verified clean environment; attacker access removed |
| **7. Recover** | Restore normal operations | Verify artifact integrity, re-enable pipelines, validate systems | Services restored; monitoring validated |
| **8. Learn** | Prevent recurrence and improve capability | Post-incident review, detection gap analysis, control improvement, runbook update | Post-incident report; action items tracked to completion |

### Critical Sequencing Rules

**Never remediate before preserving evidence.** The instinct to immediately rotate a compromised secret, delete a compromised container, or restore a modified pipeline definition is understandable but forensically destructive. The Preserve phase must complete before the Eradicate phase begins.

**Containment actions that destroy evidence require explicit approval.** Some containment actions — terminating a pod, deleting a CI runner, disabling a git branch — destroy evidence. Document the trade-off and obtain explicit approval from the investigation lead before taking any containment action that cannot be reversed.

**The investigation does not end at recovery.** The Learn phase is not optional. Post-incident reviews that produce documented, tracked action items are the mechanism through which forensics capability improves over time.

---

## The Six Investigation Domains

Every incident in a DevSecOps environment falls into one or more of these investigation domains. When an incident touches multiple domains simultaneously, follow the cross-domain correlation procedures in the [Cross-Domain Incident Correlation](#cross-domain-incident-correlation) section below.

### Domain 1: Pipeline Forensics

**Scope**: Compromise of CI/CD pipeline infrastructure — workflow definitions, build runners, pipeline triggers, CI service account credentials.

**High-value evidence sources**: CI platform audit log, workflow run logs, git history and reflog, Vault audit log for secret access, SLSA provenance attestations, OIDC token claims from CI runs.

**Canonical indicator**: An artifact was produced whose provenance cannot be verified, or a pipeline step executed that was not in the committed workflow definition.

**Investigation playbooks**: See [pipeline-forensics.md](pipeline-forensics.md) — PL-01 through PL-08.

### Domain 2: Cloud and Container Forensics

**Scope**: Compromise of cloud infrastructure — EC2 instances, Kubernetes pods, Lambda functions, cloud management plane (IAM, VPC, storage).

**High-value evidence sources**: CloudTrail (AWS) / GCP Audit Logs / Azure Activity Log, Kubernetes audit log, VPC Flow Logs, EBS snapshots, container filesystem exports.

**Canonical indicator**: Unexpected API calls to cloud management plane, unexpected outbound connections from a compute resource, an IAM role or service account performing actions outside its normal scope.

**Investigation playbooks**: See [cloud-forensics.md](cloud-forensics.md).

### Domain 3: Supply Chain Forensics

**Scope**: Compromise of software artifacts — malicious dependencies, tampered container images, corrupted registry contents, unauthorized artifact promotion.

**High-value evidence sources**: Cosign signatures, SLSA provenance, SBOM attestations, Rekor log, container registry audit logs, package manager audit logs.

**Canonical indicator**: An artifact in production whose signature cannot be verified, a dependency in an SBOM that matches a known-malicious package version, or a registry push event with no corresponding CI pipeline run.

**Investigation playbooks**: See [supply-chain-forensics.md](supply-chain-forensics.md).

### Domain 4: Identity and Credential Forensics

**Scope**: Compromise of human or machine identities — OIDC token abuse, service account credential theft, API key exfiltration, privilege escalation.

**High-value evidence sources**: CloudTrail AssumeRole events, Vault audit log, OIDC token claims, JWK set history, AWS IAM Access Advisor, authentication provider logs.

**Canonical indicator**: A principal accessed a resource from an unexpected IP address, at an unexpected time, or via an unexpected chain of assumed roles.

**Investigation steps (summary)**:

```bash
# Find all AssumeRole events by a compromised identity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=${COMPROMISED_IDENTITY} \
  --start-time ${INCIDENT_START} \
  --output json \
  | jq '.Events[] | select(.EventName == "AssumeRole") | {
    time: .EventTime,
    assumed_role: (.CloudTrailEvent | fromjson | .requestParameters.roleArn),
    source_ip: (.CloudTrailEvent | fromjson | .sourceIPAddress),
    user_agent: (.CloudTrailEvent | fromjson | .userAgent)
  }'

# Find all actions taken with the assumed role (lateral movement)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=${ASSUMED_ROLE_ARN} \
  --start-time ${INCIDENT_START} \
  --output json \
  | jq '.Events[] | {
    time: .EventTime,
    event: .EventName,
    source_ip: (.CloudTrailEvent | fromjson | .sourceIPAddress)
  }'
```

### Domain 5: Runtime Forensics

**Scope**: Compromise of running workloads — malware execution, unexpected process creation, filesystem modification, in-memory exploitation.

**High-value evidence sources**: Falco alerts, eBPF syscall telemetry, process trees, network connection state, container filesystem diff.

**Canonical indicator**: Falco alert for unexpected process in container, syscall pattern consistent with credential harvesting or lateral movement, filesystem modification in a read-only container.

**Investigation steps (summary)**:

```bash
# Capture container process tree before termination
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ps auxf > container-process-tree.txt

# Capture active network connections
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ss -tulpn > container-network-connections.txt

# Export container filesystem diff (files modified vs. base image)
CONTAINER_ID=$(docker ps --filter "name=${POD_NAME}" --format "{{.ID}}")
docker diff ${CONTAINER_ID} > container-filesystem-diff.txt

# For containerd (typical in Kubernetes)
crictl ps --name ${POD_NAME} -o json \
  | jq -r '.containers[0].id' \
  | xargs -I {} crictl inspect {} > container-inspect.json
```

### Domain 6: Agent and AI System Forensics

**Scope**: Compromise of or by AI agents operating in DevSecOps pipelines — unauthorized tool calls, prompt injection, permission escalation, artifact generation of unknown provenance.

**High-value evidence sources**: Tool call logs, system prompt version history, model input/output pairs, agent OIDC signing records.

**Canonical indicator**: An agent executed a tool call inconsistent with its system prompt's authorization scope, or an artifact created by an agent cannot be verified against the agent's signing identity.

**Investigation playbooks**: See [agent-forensics.md](agent-forensics.md) — AF-01 through AF-04.

---

## Severity Classification System

### Classification Criteria

| Severity | Criteria | Initial Response Time | Investigation Team |
|---|---|---|---|
| **P1 — Critical** | Confirmed compromise affecting production; confirmed secret exfiltration; pipeline used to deliver malicious artifact to production; active attacker with ongoing access | Immediate — 5 minutes to assemble core team | Security lead + on-call engineer + management notification |
| **P2 — High** | Compromise confirmed but contained to non-production; secret potentially exfiltrated (unconfirmed); artifact tampering detected before production deployment; significant supply chain anomaly | < 30 minutes | Security lead + on-call engineer |
| **P3 — Medium** | Suspicious signals requiring investigation; unconfirmed compromise; anomaly that may indicate precursor activity | < 4 hours | On-call security engineer |

### Severity Escalation Triggers

A P3 investigation must be escalated to P2 if any of the following are confirmed:
- The anomaly originated from an authenticated identity (not a misconfiguration or false positive)
- Any secret or credential was accessed outside its normal usage pattern
- Any artifact was produced or promoted without verifiable provenance

A P2 investigation must be escalated to P1 if any of the following are confirmed:
- Any compromise artifact reached a production environment
- Any secret with production access was accessed by an unauthorized principal
- An attacker still has active access to any system

### Notification Matrix

| Event | Notify Immediately |
|---|---|
| P1 declared | CISO, VP Engineering, Legal (if data breach possible), all on-call security |
| Production artifact integrity failure | Security lead, Platform lead, on-call SRE |
| Secret confirmed exfiltrated | CISO, Legal, affected system owners |
| Legal hold trigger condition met | Legal counsel, CISO, Engineering leadership |
| Law enforcement contact | Legal counsel only (before any other response) |

---

## The Forensics Readiness Score

The Forensics Readiness Score is a five-level maturity model for assessing an organization's capability to investigate security incidents in DevSecOps environments.

### Level 1: Ad Hoc

**Description**: No systematic forensics capability. When incidents occur, investigation depends on whatever logs happen to exist in accessible locations.

**Characteristics**:
- No defined evidence architecture; log retention is incidental
- CI/CD audit logs not exported outside the CI platform; often auto-deleted after 30–90 days
- No artifact signing or provenance; cannot verify artifact integrity post-incident
- No IR runbooks; investigation procedure invented per incident
- No tamper-evident storage; logs can be modified or deleted

**Typical investigation outcome**: Limited findings; cannot determine blast radius; attacker timeline incomplete or impossible to reconstruct.

**Risk**: Very High — most incidents result in incomplete investigation; recurrence likely because root cause is not fully understood.

---

### Level 2: Instrumented

**Description**: Basic logging is in place. Key evidence sources are enabled, but evidence is not systematically protected or correlated.

**Characteristics**:
- CloudTrail and cloud audit logs enabled
- CI platform audit logs enabled; not necessarily exported to external store
- Vault audit logging enabled
- No Object Lock or WORM protection on log storage
- No artifact signing or SLSA provenance
- Basic IR process documented but not tested

**Typical investigation outcome**: Can reconstruct cloud-level activity; CI-level activity partially visible; artifact integrity cannot be verified; blast radius assessment incomplete.

**Transition effort**: 2–4 weeks to move from Level 1 with dedicated implementation work.

---

### Level 3: Evidenced

**Description**: Evidence sources are systematically collected, tamper-protected, and retained. Artifact integrity infrastructure is deployed.

**Characteristics**:
- All required evidence sources from [architecture.md](architecture.md) enabled and exported
- Object Lock or WORM storage configured for log destinations
- Cosign artifact signing deployed for production builds
- SLSA provenance level 2+ attestations generated
- SBOM generated and signed for all production artifacts
- Kubernetes audit logs shipped to SIEM
- IR runbooks for major incident types documented and accessible

**Typical investigation outcome**: Complete timeline for most incident types; artifact integrity can be verified; blast radius can be determined for most compromise scenarios; root cause usually identifiable.

**Transition effort**: 1–3 months from Level 2.

---

### Level 4: Repeatable

**Description**: Forensics investigations follow documented procedures consistently. Evidence collection is automated. Investigation capability is tested periodically.

**Characteristics**:
- All Level 3 characteristics
- Automated evidence collection scripts deployed and tested
- Investigation runbooks cover all six domains with tested procedures
- Post-incident reviews produce action items that are tracked to completion
- Forensics exercises (tabletop or simulation) run at least annually
- Agent/AI forensics capability deployed if AI agents are in use
- Evidence retention schedules formalized and compliant with regulatory requirements

**Typical investigation outcome**: Investigations follow documented procedures; timelines are reconstructed reliably; post-incident reports meet regulatory and legal standards.

**Transition effort**: 3–6 months from Level 3.

---

### Level 5: Continuous

**Description**: Forensics capability is continuously improved. Evidence collection and anomaly detection are integrated into the development workflow.

**Characteristics**:
- All Level 4 characteristics
- Continuous evidence integrity monitoring (detect if logs are missing or gaps appear)
- Anomaly detection integrated with evidence sources (unusual secret access, unexpected artifact signatures)
- Forensics simulation exercises include agent/AI scenarios
- Investigation findings feed back into detection engineering (new alerts tuned from incident patterns)
- Legal and regulatory readiness maintained continuously; evidence packages can be generated on-demand
- MTTD, MTTC, and MTTR metrics tracked and improving quarter-over-quarter

**Typical investigation outcome**: Fast, complete investigations; near-real-time detection of anomalies; evidence packages meet legal hold standards.

**Transition effort**: 6–12 months from Level 4; requires sustained investment.

---

## Cross-Domain Incident Correlation

Most serious DevSecOps incidents span multiple investigation domains simultaneously. A sophisticated attacker who compromises a build pipeline will use that access to tamper with an artifact (supply chain domain), which gets deployed to production (cloud domain), where the attacker establishes persistence using stolen credentials (identity domain). Investigating any single domain in isolation will produce an incomplete picture.

### Example: Pipeline-to-Production Compromise Chain

This is the canonical cross-domain attack in DevSecOps:

```
[Domain 1: Pipeline]         [Domain 3: Supply Chain]    [Domain 2: Cloud]
Attacker compromises    →    Malicious artifact           Artifact deployed to
CI pipeline runner           pushed to registry           production EKS cluster
                             (signature forged or          (bypassing admission
                             bypassed)                     control)
                                                                  ↓
                                                         [Domain 4: Identity]
                                                         Artifact steals IMDS
                                                         credentials; attacker
                                                         assumes production IAM
                                                         role
```

**Investigation approach for cross-domain incidents**:

1. **Establish the timeline across all domains simultaneously.** Build a single master timeline with events from each domain's evidence sources. This reveals the attack sequence and identifies the initial point of compromise.

2. **Identify the "pivot point"** — the specific action where the attacker moved from one domain to another. In the example above, the pivot from Pipeline to Supply Chain is the moment the malicious artifact was pushed to the registry. The pivot from Supply Chain to Cloud is the deployment event.

3. **Each domain investigation is a peer**, not a subordinate. Assign investigation leads for each domain involved; they report to a cross-domain coordinator who owns the master timeline.

**Cross-domain timeline construction:**

```bash
# Merge evidence from multiple domains into a single timeline
# (assumes each domain produced a JSON evidence file with a 'timestamp' field)

jq -s '
  flatten |
  sort_by(.timestamp) |
  .[] | {
    timestamp,
    domain: (
      if .source | startswith("cloudtrail") then "cloud"
      elif .source | startswith("github") then "pipeline"
      elif .source | startswith("cosign") then "supply-chain"
      elif .source | startswith("vault") then "identity"
      else "unknown"
      end
    ),
    event: .event_name,
    actor: (.actor // .user // .identity),
    detail: .detail
  }
' \
  cloudtrail-events.json \
  github-audit-events.json \
  cosign-verification-results.json \
  vault-audit-events.json \
  > master-incident-timeline.json
```

4. **Determine blast radius across all domains.** Every system touched in any domain is potentially within the blast radius. The blast radius assessment must be complete before the Eradicate phase begins.

| Domain | Blast Radius Question | Evidence Source |
|---|---|---|
| Pipeline | Which artifacts were produced during the compromise window? Were any deployed? | CI run logs, registry push events, deployment records |
| Cloud | Which resources did the attacker access? What data was reachable? | CloudTrail, VPC Flow Logs |
| Supply Chain | Which versions of the artifact are malicious? Which environments consumed them? | Registry audit, SLSA provenance, deployment records |
| Identity | Which roles, accounts, or credentials were compromised? What was their access scope? | IAM policies, CloudTrail AssumeRole, Vault policies |
| Runtime | Which processes ran? Was data staged for exfiltration? | Falco, eBPF telemetry, container filesystem diff |
| Agent | Which tool calls did the agent make? What artifacts did it produce? | Tool call log, artifact signing records |

---

## Investigation Workflow

The following workflow integrates the IR phases, domain assignments, and severity system into a practical investigation process.

```
INCIDENT SIGNAL RECEIVED
         │
         ▼
  ┌─────────────┐
  │   TRIAGE    │  ← Assign initial severity (P1/P2/P3)
  │  (5–30 min) │    Identify which domains are involved
  └──────┬──────┘    Assemble investigation team
         │
         ▼
  ┌─────────────┐
  │   CONTAIN   │  ← Minimum viable containment only
  │             │    Document every containment action
  └──────┬──────┘    Get approval for any evidence-destroying action
         │
         ▼
  ┌─────────────┐
  │   PRESERVE  │  ← Export all relevant evidence sources
  │             │    Verify evidence integrity (hash everything)
  └──────┬──────┘    Open chain of custody record
         │
         ├──────────────────┬─────────────────┐
         ▼                  ▼                 ▼
  [Domain 1 Lead]    [Domain 2 Lead]   [Domain N Lead]
  Investigate per    Investigate per   Investigate per
  domain playbook    domain playbook   domain playbook
         │                  │                 │
         └──────────────────┴─────────────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │  CROSS-DOMAIN       │
                 │  TIMELINE MERGE     │
                 │  Blast radius map   │
                 │  Root cause ID      │
                 └──────────┬──────────┘
                            │
                            ▼
                     ┌────────────┐
                     │ ERADICATE  │
                     └─────┬──────┘
                           │
                           ▼
                     ┌────────────┐
                     │  RECOVER   │
                     └─────┬──────┘
                           │
                           ▼
                     ┌────────────┐
                     │   LEARN    │  ← Post-incident report
                     └────────────┘    Action items to tracking system
                                       Detection gap analysis
                                       Runbook update
```
