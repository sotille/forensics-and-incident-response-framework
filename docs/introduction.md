# Introduction: Why Forensics Is Different in DevSecOps

## Table of Contents

1. [The Core Problem](#the-core-problem)
2. [Five Ways DevSecOps Changes Forensics](#five-ways-devsecops-changes-forensics)
3. [The Six Investigation Domains](#the-six-investigation-domains)
4. [Forensics Prerequisites](#forensics-prerequisites)
5. [When to Use This Framework](#when-to-use-this-framework)
6. [Scope and Boundaries](#scope-and-boundaries)

---

## The Core Problem

Traditional digital forensics operates on a set of assumptions that do not hold in modern DevSecOps environments. A forensics investigator responding to a Windows server compromise can image the disk, analyze the registry, recover deleted files from slack space, and extract memory. The evidence persists because the infrastructure persists.

In cloud-native DevSecOps environments, the infrastructure does not persist:

- A GitHub Actions runner that processed a malicious build step exists for 2–8 minutes. When the job completes, the virtual machine is terminated and its disk is gone.
- A Kubernetes pod that exfiltrated a secret may have been evicted and garbage-collected before the alert fires.
- An AWS Lambda function has no persistent filesystem at all — only the execution log, and only if you configured CloudWatch with the right retention policy.
- A supply chain attack may have occurred three dependency versions ago; the malicious package version has been yanked from the registry, and you must reconstruct what happened from SBOM snapshots and provenance records.

This framework exists because these environments require a fundamentally different approach: evidence must be collected continuously and automatically, because by the time you know you need it, it is already gone. Forensics readiness in DevSecOps is not something you activate in response to an incident; it is infrastructure you build in advance.

---

## Five Ways DevSecOps Changes Forensics

### 1. Ephemeral Environments Destroy Evidence Automatically

In cloud-native infrastructure, evidence destruction is a feature, not an anomaly. Ephemeral CI runners, spot instances, and serverless functions are designed to be disposable. There is no disk image to acquire because there is no persistent disk.

This forces a shift from post-incident evidence collection to continuous evidence export. Every audit event, every build log, every secret access record must be streamed to a tamper-evident, append-only store the moment it is generated. Waiting until an incident to start collecting evidence is too late.

**Implication for this framework**: The [Evidence Architecture](architecture.md) document is the foundation. Every other document depends on it. If you have not built evidence infrastructure, the investigation playbooks will fail at Step 1.

### 2. Infrastructure as Code Makes the Git History the Crime Scene

In traditional environments, the attacker modified a running system. In IaC-driven environments, the attacker modifies a repository. The compromise is a commit — a changed workflow file, an updated Terraform module, a modified Dockerfile. The git history is the primary forensic artifact.

This cuts both ways: git is a forensic goldmine (every change is hashed, authored, and timestamped), but git history can be rewritten. Force pushes and history rewrites that destroy evidence are a documented attacker technique. Forensic investigation must preserve git state before any remediation that could trigger history modification.

**Implication**: The first action in any pipeline compromise investigation is to export the git history, branch refs, and reflog before the repository is modified.

### 3. Immutability Is a Forensic Advantage — If You Use It

Immutable OCI image digests, Cosign signatures, SLSA provenance attestations, and Rekor transparency log entries are cryptographic evidence of what was built, when, by which pipeline, from which source commit. These controls exist for supply chain security, but they are equally powerful as forensic instruments.

An artifact with a valid Cosign signature carries a certificate containing the OIDC issuer, the workflow reference, the repository, and the commit SHA. An artifact with a SLSA provenance attestation records the build invocation ID, the builder identity, and the source materials digest. These are better forensic records than most traditional audit logs.

**Implication**: Artifact signing and SLSA provenance must be treated as forensic infrastructure, not just supply chain controls. Retrofitting them after an incident is too late to help with that incident.

### 4. The Pipeline Is the Target

The 2020 SolarWinds attack did not compromise production systems directly — it compromised the build pipeline that delivered software to those systems. The XZ Utils backdoor was inserted through a sustained social engineering campaign targeting the project's CI process. Compromising the pipeline is more valuable to an attacker than compromising a single runtime host: it gives the attacker access to every environment that consumes the pipeline's output.

The CI/CD pipeline is therefore a high-value forensic target. Pipeline forensics is not just about investigating pipelines that have been compromised — it is about using pipeline artifacts (build logs, provenance, signatures) as evidence in investigations that originate elsewhere.

**Implication**: Pipeline forensics is the highest-priority investigation domain. See [docs/pipeline-forensics.md](pipeline-forensics.md) for the full investigation procedure set.

### 5. AI Agent Systems Create New Forensic Challenges

When AI agents operate within DevSecOps pipelines — triaging vulnerabilities, reviewing PRs, triggering deployments, managing secrets — they introduce forensic questions that have no precedent in traditional IR:

- Was the agent acting within its authorized scope when it executed this tool call?
- Was the agent's context manipulated via prompt injection (a malicious string in a git commit message, a PR description, an issue title, or SBOM content that altered the agent's behavior)?
- Who is accountable for an action — the agent, the human who configured the agent's system prompt, or the human who approved the workflow that invoked the agent?
- Can the agent's outputs be authenticated as originating from the agent (not modified in transit) and as being the result of authorized inputs (not a hallucinated or injected command)?

These questions require new evidence sources (tool call logs, system prompt version history, input/output pair recording) and new investigation techniques that are covered in [docs/agent-forensics.md](agent-forensics.md).

---

## The Six Investigation Domains

This framework organizes forensic investigation around six domains that reflect the attack surfaces present in a DevSecOps environment. Real incidents rarely stay within a single domain — a pipeline compromise often leads to a supply chain artifact being deployed to a cloud workload. The framework's cross-domain correlation procedures address this explicitly in [docs/framework.md](framework.md).

| Domain | Scope | Primary Evidence Sources | Key Playbook |
|--------|-------|--------------------------|--------------|
| **Pipeline Forensics** | CI/CD workflow compromise, malicious pipeline steps, unauthorized triggers | CI audit logs, workflow run logs, SLSA provenance, Vault audit | [pipeline-forensics.md](pipeline-forensics.md) |
| **Cloud and Container Forensics** | EC2, EKS, Lambda, and container runtime compromise | CloudTrail, VPC Flow Logs, Kubernetes audit logs, container filesystem snapshots | [cloud-forensics.md](cloud-forensics.md) |
| **Supply Chain Forensics** | Dependency compromise, artifact tampering, registry manipulation | SBOM, SLSA provenance, Cosign signatures, Rekor log, registry audit | [supply-chain-forensics.md](supply-chain-forensics.md) |
| **Identity and Credential Forensics** | OIDC token abuse, service account compromise, secret exfiltration | CloudTrail AssumeRole events, Vault audit, OIDC token claims, JWK set history | (see [framework.md](framework.md)) |
| **Runtime Forensics** | Host and container runtime compromise, malware, lateral movement | Falco alerts, eBPF telemetry, process trees, network connections | (see [framework.md](framework.md)) |
| **Agent and AI System Forensics** | Unauthorized tool calls, prompt injection, agent permission escalation | Tool call logs, system prompt version history, model I/O pairs, agent signing records | [agent-forensics.md](agent-forensics.md) |

---

## Forensics Prerequisites

The investigation playbooks in this framework assume a minimum evidence infrastructure. Without these capabilities, investigation procedures will produce incomplete or no findings.

### Required Prerequisites (must have before incidents occur)

| Prerequisite | Why Required | Implementation Guidance |
|---|---|---|
| CI/CD audit logs exported to tamper-evident store | Without these, you cannot determine what pipeline steps ran, who triggered them, or what secrets were accessed | [architecture.md — CI/CD Audit Trail](architecture.md) |
| Cloud provider audit logging enabled (CloudTrail, GCP Audit Logs, Azure Monitor) | Cloud-level actions (IAM changes, secret access, compute operations) are invisible without these | [architecture.md — Immutable Log Storage](architecture.md) |
| S3 Object Lock (or equivalent) on log buckets | Without WORM protection, an attacker with write access to the log bucket can destroy evidence | [architecture.md — Immutable Log Storage](architecture.md) |
| SLSA provenance attestations for production artifacts | Without provenance, you cannot reconstruct build lineage or verify which commit produced a suspect artifact | [supply-chain-forensics.md](supply-chain-forensics.md) |
| Cosign artifact signatures | Without signatures, you cannot verify artifact integrity or establish who signed what, when | [supply-chain-forensics.md](supply-chain-forensics.md) |
| Secret access logging (Vault audit, Secrets Manager CloudTrail) | Without these, you cannot determine which secrets were accessed during a compromise window | [architecture.md — CI/CD Audit Trail](architecture.md) |

### Strongly Recommended (significantly improves investigation quality)

| Recommendation | Impact if Absent |
|---|---|
| Kubernetes audit logs shipped to SIEM | Container-level actions invisible; cannot reconstruct pod compromise sequence |
| VPC Flow Logs for all production VPCs | Cannot determine whether data exfiltration occurred or reconstruct lateral movement |
| SBOM generated for every artifact build | Cannot perform forensic SBOM diff or determine which deployments contained a compromised dependency |
| Git repository mirroring or backup with reflog preservation | Force-push attacks that rewrite history destroy evidence if mirroring is absent |
| Agent tool call logging (if AI agents are in use) | Agent forensics investigations are impossible without tool call records |

If your environment does not yet meet the required prerequisites, start with [docs/implementation.md](implementation.md) Phase 1 before using the investigation playbooks.

---

## When to Use This Framework

### Use this framework when:

- You are building forensics and incident response capability for a DevSecOps environment from scratch
- An incident has occurred and you need structured investigation procedures
- You are assessing your forensics readiness and want a maturity model to evaluate against
- You are meeting a regulatory requirement for incident response capability (SOC 2 CC7, ISO 27001 A.16, NIST CSF RS.AN)
- You are designing or reviewing evidence architecture for a new platform
- You are responsible for AI agent systems in DevSecOps and need to understand the forensic requirements they create

### Relationship to Other Techstream Documents

This framework intentionally expands beyond existing Techstream content:

- [secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md](../secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md) covers pipeline forensics for the six foundational compromise types (PL-01 through PL-06). This framework's [docs/pipeline-forensics.md](pipeline-forensics.md) adds the forensic prerequisites gap analysis, two new AI/agent playbooks (PL-07, PL-08), post-compromise report templates, and pipeline-specific metrics.
- [software-supply-chain-security-framework/docs/incident-response-playbook.md](../software-supply-chain-security-framework/docs/incident-response-playbook.md) covers supply chain IR response. This framework's [docs/supply-chain-forensics.md](supply-chain-forensics.md) extends that with the forensic use of SBOM and SLSA provenance as chain-of-custody instruments.
- [cloud-security-devsecops/docs/incident-response-playbooks.md](../cloud-security-devsecops/docs/incident-response-playbooks.md) covers cloud IR. This framework's [docs/cloud-forensics.md](cloud-forensics.md) provides the technical forensic procedures for evidence collection from ephemeral cloud and container environments.

---

## Scope and Boundaries

### In Scope

- Evidence architecture design for DevSecOps environments
- Investigation procedures for the six domains listed above
- Evidence collection, preservation, and chain of custody
- Legal hold procedures for digital evidence
- AI and agent system forensics
- Post-incident reporting and metrics

### Out of Scope

- Physical security incidents and physical evidence handling
- Endpoint forensics for developer workstations (beyond their cloud credentials)
- Network forensics below the VPC/cloud layer (BGP hijacking, physical network taps)
- Malware reverse engineering (referenced as a technique; detailed RE procedures are out of scope)
- Penetration testing and red team procedures

### Framework Versioning

This framework documents procedures current as of the release date. Cloud provider APIs, CLI tools, and forensics tooling change frequently. Commands in this framework should be validated against current tool versions before use in incident response. If you find an outdated command, see [CONTRIBUTING.md](../CONTRIBUTING.md) for how to submit a correction.
