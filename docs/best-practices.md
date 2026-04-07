# Forensics Best Practices for DevSecOps

## Table of Contents

1. [Evidence-First Principle](#evidence-first-principle)
2. [Immutability as Design Principle](#immutability-as-design-principle)
3. [Defense in Depth for Logging](#defense-in-depth-for-logging)
4. [The Forensic Baseline](#the-forensic-baseline)
5. [Separation of Duties](#separation-of-duties)
6. [Communication Templates](#communication-templates)
7. [Common Mistakes and How to Avoid Them](#common-mistakes-and-how-to-avoid-them)

---

## Evidence-First Principle

The most consequential decision in any incident response is the sequencing of containment and evidence preservation. The instinct — to remediate immediately and minimize harm — is correct in intent but often destructive in practice. Remediation actions that occur before evidence is preserved frequently make root cause analysis impossible.

**The rule**: Containment actions that preserve attacker access are acceptable as long as they stop ongoing harm. Containment actions that destroy evidence require explicit approval from the investigation lead.

| Action | Evidence Impact | Sequencing |
|---|---|---|
| Disabling a CI pipeline | Low — run logs persist | Acceptable as first action |
| Rotating a compromised secret | Low — access logs persist | Acceptable after logs exported |
| Deleting a compromised CI runner | **High** — runner disk destroyed | Requires snapshot/export first |
| Terminating a compromised EC2 instance | **High** — disk destroyed, memory gone | Requires EBS snapshot first |
| Evicting/deleting a Kubernetes pod | **High** — container filesystem gone, memory gone | Requires export of filesystem diff, process tree, network state first |
| Merging a "fix" PR to a compromised repository | **Medium** — can obscure timeline in git history | Acceptable only after git log and reflog exported |
| Force-pushing to remove a malicious commit | **Critical** — destroys git history | Almost never acceptable; use branch deletion + git archival |
| Deleting or overwriting CI audit logs | **Critical** — destroys primary evidence | Never acceptable |

### The Evidence Preservation Checklist (run before any remediation)

```
For every compromised system, complete before remediation begins:

CLOUD COMPUTE (EC2, GCE, Azure VM):
[ ] EBS/persistent disk snapshot taken and hash recorded
[ ] CloudTrail events for the instance exported to evidence store
[ ] VPC Flow Logs for the instance's ENI exported
[ ] Instance metadata (tags, security groups, IAM role) exported
[ ] Memory dump attempted (if feasible — see cloud-forensics.md)

KUBERNETES POD:
[ ] kubectl get all -n ${NAMESPACE} -o yaml exported
[ ] kubectl describe pod ${POD} exported
[ ] Container process tree captured (ps auxf inside container)
[ ] Network connections captured (ss -tulpn inside container)
[ ] Container filesystem diff exported (docker diff or crictl)
[ ] Kubernetes audit log events for the pod exported from SIEM

CI/CD PIPELINE:
[ ] Full pipeline run log exported (all steps, all output)
[ ] Pipeline definition at incident SHA exported (git show SHA:path)
[ ] Git reflog exported from the repository
[ ] CI platform audit log events for the incident window exported
[ ] SLSA provenance attestation for any artifact produced exported

SECRETS / CREDENTIALS:
[ ] Vault audit log entries for the secret path exported
[ ] CloudTrail events for the secret ARN exported
[ ] All IAM role assumption chains involving the credential traced

ARTIFACT:
[ ] Artifact manifest and digest recorded
[ ] Cosign signature and Rekor entry extracted
[ ] SLSA provenance attestation extracted
[ ] SBOM extracted
[ ] Registry push audit event extracted
```

---

## Immutability as Design Principle

The forensic value of any evidence source is proportional to its tamper-evidence guarantee. Log data that can be modified or deleted by an attacker with write access to the log store is not forensic evidence — it is an assertion that the attacker might have modified.

Design for immutability at every layer:

**Level 1 — Platform-enforced immutability**: S3 Object Lock Compliance mode, Azure Immutable Storage with locked policy, GCS with locked retention policy. These are enforced by the cloud provider and cannot be overridden by any user in the account, including the root account.

**Level 2 — Cryptographic commitment**: CloudTrail log file validation (SHA-256 digest chain), Rekor append-only Merkle tree. These allow you to detect tampering even if platform-level protection fails.

**Level 3 — Separation of write and read principals**: The service account that writes logs must not have read or delete access. The service account that reads logs must not have write access. Neither should have delete access in Compliance mode (it is impossible, but make the intent explicit in IAM policy).

**Level 4 — Out-of-band copy**: Critical evidence sources (Vault audit log, CI audit log) should be shipped to a second destination in a separate account or separate cloud provider. An attacker who compromises the primary AWS account cannot reach a GCP Cloud Logging instance receiving the same events.

The cost of immutable log storage at current cloud pricing is trivial relative to the cost of a single incomplete investigation. At 10 GB/month of compressed logs across all sources, S3 at $0.023/GB-month with 7-year Object Lock is approximately $19/month for the entire retention period. There is no cost justification for not using Object Lock.

---

## Defense in Depth for Logging

No single log source should be the sole evidence of a critical event. For every high-value forensic event type, there should be at least two independent log sources that record it.

| Event Type | Primary Source | Secondary Source | Cross-Check Method |
|---|---|---|---|
| Secret accessed in production | Vault audit log | CloudTrail Secrets Manager events | Compare access times and accessor identity |
| Artifact pushed to registry | Registry audit log (ECR CloudTrail) | SLSA provenance (build invocation ID) | Verify push timestamp matches pipeline run |
| Kubernetes API exec to production pod | Kubernetes audit log | Falco alert | Falco k8s_audit rule for exec events |
| CI pipeline definition modified | Git commit history | CI platform audit log | Git commit SHA in CI event should match |
| IAM role assumed | CloudTrail AssumeRole | Application logs (if app initiates assume) | Source IP should match expected service |
| Agent tool invocation | Agent tool call log | Application-level log (target system) | Tool call record should have corresponding target system event |

When investigating, always attempt to corroborate an event in both sources. A Vault audit entry showing a secret was read but no corresponding CloudTrail Secrets Manager event (if using Secrets Manager) warrants investigation of why the sources diverge. A CI audit log showing a pipeline ran but no SLSA provenance for the resulting artifact warrants immediate artifact quarantine.

---

## The Forensic Baseline

A forensic baseline is a documented record of normal behavior for every system, credential, and artifact flow in your environment. Without a baseline, it is impossible to distinguish anomalous behavior from normal behavior during an investigation.

**What to baseline**:

| Category | Baseline Questions | How to Establish |
|---|---|---|
| CI pipeline runs | What time of day do builds run? What secrets does each pipeline access? What is the normal build duration? What is the normal artifact digest frequency? | Mine CI audit logs over 30-day period; document in runbook |
| Secret access patterns | Which services access which secrets? From which IPs? At what time of day? What is the normal access frequency? | Mine Vault/Secrets Manager audit logs; establish normal ranges |
| Kubernetes API activity | Which service accounts make which API calls? How often? What is normal exec activity (should be near-zero in production)? | Mine k8s audit logs; alert on exec events that exceed baseline |
| Registry push patterns | Which pipelines push to which repositories? How often? At what times? What is the normal image layer size? | Mine registry audit logs |
| Network flows | What external IPs do production services communicate with? What is normal outbound bytes/hour? | Mine VPC Flow Logs; establish normal destination CIDRs |
| Agent tool calls | Which tools does each agent invoke? How often? What is the normal sequence of tool calls for the agent's primary task? | Mine agent tool call logs over 30 days after deployment |

The baseline should be documented in the runbooks for each domain and updated quarterly. An investigation that cannot compare observed behavior against a baseline will produce inconclusive results.

---

## Separation of Duties

**The person who owns a compromised system must not lead the investigation of that system's compromise.**

This is not a reflection on the system owner's honesty — it is a structural control that protects the investigation's integrity and protects the system owner. An investigation led by the system owner creates conflicts of interest in evidence interpretation, creates pressure to minimize blast radius assessments, and creates legal exposure if the owner's conduct is itself under scrutiny.

| Role | May Not Also Be |
|---|---|
| Investigation Lead | Owner of any system under investigation |
| Evidence Custodian | Investigation Lead; must be a neutral party |
| Forensic Analyst | System owner for any system they are analyzing |
| Legal Hold Custodian | Investigation Lead; must report to Legal directly |

For small security teams where this strict separation is impractical, use the following compensating control: all investigation decisions must be documented in writing with a second-team-member acknowledgment before execution. This creates a contemporaneous record that prevents retroactive rationalization.

---

## Communication Templates

### P1 Internal Alert (Engineering Slack / Teams)

```
[INCIDENT ALERT - P1]
Incident ID: INC-{YYYYMMDD}-{N}
Time detected: {ISO8601}
Summary: {1-2 sentence plain-language description of what happened}

Status: ACTIVE INVESTIGATION
- [X] Containment: IN PROGRESS / COMPLETE
- [ ] Evidence preserved
- [ ] Blast radius determined

Current assessment:
- Systems potentially affected: {list}
- Secrets potentially compromised: {yes/no/unknown}
- Production artifact integrity: {verified / unverified / compromised}

Investigation lead: {name}
Next update: In 30 minutes or when status changes

DO NOT:
- Modify any affected repository or pipeline until cleared by investigation lead
- Rotate any credentials until evidence has been preserved
- Discuss publicly (Slack is logged; use the designated incident channel only)
```

### P1 Management Notification (Email)

```
Subject: Security Incident Notification — INC-{ID} [{severity}]

This message confirms a security incident is under active investigation.

Incident: {brief description — no technical detail in subject line}
Detected: {date and time}
Current status: Containment in progress / Contained / Under investigation

What is known: {2-3 sentences on what has been confirmed}
What is unknown: {2-3 sentences on what is still being investigated}
Potential impact: {brief description of scope if compromise confirmed}

Current actions:
- Investigation team assembled
- Evidence preservation in progress
- [other specific actions]

Next update: {time} or immediately if status escalates

Contact: {investigation lead name and secure contact method}

Note: This communication is confidential and may be subject to legal privilege. Do not forward without authorization from Legal.
```

### Post-Incident External Communication (if customer-facing data is involved)

```
Subject: Security Notification

We are writing to inform you of a security incident that may have affected {describe scope without unnecessary alarm}.

What happened: {Plain-language description of the incident}
When it happened: {Date range}
What data was affected: {Specific data types; do not overstate scope}
What we have done: {Actions taken to contain and remediate}
What you should do: {Specific, actionable steps — only if there are any}

We take the security of your data seriously. We have [describe remediation and prevention measures].

If you have questions, contact {security@yourcompany.com}.
```

---

## Common Mistakes and How to Avoid Them

### Mistake 1: Log Rotation Destroying Evidence

**What happens**: An engineer notices that the Vault audit log is consuming disk space and increases the rotation frequency. The rotation schedule means logs older than 7 days are deleted. When an incident is discovered 10 days later, the Vault audit evidence covering the initial compromise is gone.

**How to avoid**: Ship all audit logs to an external store immediately on generation. Never rely on local log rotation schedules as the retention mechanism. The local log file is a buffer; the SIEM and Object Lock bucket are the evidence record.

### Mistake 2: Ephemeral Runner Evidence Lost

**What happens**: A GitHub Actions runner is compromised and runs a malicious step that exfiltrates secrets. The job completes (or fails), the runner terminates, and the disk is destroyed. The investigation has only the step-level logs that were captured before the pipeline was halted — which may not include the malicious step's output if it was designed to avoid logging.

**How to avoid**: Configure GitHub Actions with debug logging enabled for production-critical pipelines (`ACTIONS_STEP_DEBUG: true`). For self-hosted runners, configure the runner to export its disk image to S3 on job completion before the instance terminates. Use Falco on Kubernetes runners to capture runtime behavior independent of the job log.

### Mistake 3: Git History Rewritten

**What happens**: A developer (or attacker) force-pushes to rewrite the git history that contained evidence of the compromise. The malicious commit is no longer in the history. The pipeline definition shows no evidence of tampering.

**How to avoid**: Enable branch protection rules that prevent force pushes to default branches. Configure GitHub to export audit log events for `git.push_force` actions. Mirror repositories to a separate system where force-push audit events are captured. Preserve the `git reflog` before any remediation that involves touching the repository.

```bash
# Export git reflog before any repository remediation
git reflog --all --date=iso > git-reflog-$(date +%Y%m%d%H%M%S).txt
git log --all --oneline --graph --decorate > git-history-$(date +%Y%m%d%H%M%S).txt
```

### Mistake 4: Investigating with the Compromised Identity

**What happens**: An investigator uses the compromised CI service account credentials to query logs and verify artifact signatures. Because the account may still have attacker access or because the account's actions now mix with attacker actions in the audit trail, the investigation contaminates its own evidence.

**How to avoid**: Create a separate forensics investigator IAM role that is used exclusively for incident investigation. This role has read-only access to logs and artifacts and is never used for operational work. Its actions in the audit trail are clearly identifiable as investigation actions, not operational or attacker actions.

### Mistake 5: Premature Scope Narrowing

**What happens**: An investigation team determines that a pipeline was compromised and focuses entirely on the pipeline domain. They find the compromised workflow file, patch it, and close the incident. Two weeks later, they discover that the compromised pipeline also accessed a database credential — the attacker has had production database access for three weeks.

**How to avoid**: In every incident, explicitly ask: "What access did the compromised principal have?" Map all permissions of every compromised identity before declaring the blast radius complete. Use the cross-domain correlation procedures in [framework.md](framework.md) to ensure all relevant domains are investigated.

### Mistake 6: Single-Source Evidence for Critical Findings

**What happens**: An investigation concludes that no data exfiltration occurred because CloudTrail shows no unusual network-level API calls. VPC Flow Logs were not enabled. The conclusion is published. The actual exfiltration, which occurred at the container level to an IP address outside the VPC (not captured in CloudTrail), is never discovered.

**How to avoid**: Apply defense in depth for logging (see above). For any finding of "no exfiltration," verify the finding against at least two independent sources (CloudTrail + VPC Flow Logs at minimum; Falco network events + VPC Flow Logs for container workloads).

### Mistake 7: Treating Artifact Deletion as Remediation

**What happens**: After discovering a malicious container image in the registry, the team deletes it from the registry. The Rekor entry for the Cosign signature of that image remains — it is permanent and publicly queryable. The deletion also destroys the SBOM attestation, making it impossible to determine which downstream services consumed the image.

**How to avoid**: Never delete artifacts from the registry as an incident response action without first preserving the manifest digest, Cosign signature, SLSA provenance, and SBOM attestation. The artifact itself is forensic evidence. Quarantine it (move to an isolated repository, remove promotion) rather than deleting it.

### Mistake 8: Closing an Incident Without Verified Eradication

**What happens**: A compromised service account's access key is rotated. The incident is closed. The attacker had also created a secondary access key that was not in the standard key rotation procedure — they maintain access for another month.

**How to avoid**: Eradication must include a complete audit of all persistence mechanisms, not just the one that was initially identified. For credential compromise, list all access keys, sessions, and federated identities for the affected account. For pipeline compromise, review all pipeline integrations, OAuth apps, and webhook registrations for the affected repository. Use the blast radius framework in [framework.md](framework.md) to ensure all persistence mechanisms are identified before closing.
