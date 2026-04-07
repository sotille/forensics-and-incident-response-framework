# Forensics and Incident Response: 18-Month Maturity Roadmap

## Table of Contents

- [Roadmap Overview](#roadmap-overview)
- [Forensics Readiness Score — 5 Levels](#forensics-readiness-score--5-levels)
- [18-Month Roadmap by Quarter](#18-month-roadmap-by-quarter)
- [KPIs per Phase](#kpis-per-phase)
- [Tooling Adoption Sequence](#tooling-adoption-sequence)
- [Organizational Readiness](#organizational-readiness)

---

## Roadmap Overview

This roadmap provides a structured path from minimal forensics capability (Level 1: Ad Hoc) to a continuously improving forensics and incident response program (Level 5: Continuous). It follows the same phasing model as the [DevSecOps Framework Roadmap](../../devsecops-framework/docs/roadmap.md) and is designed to be run in parallel with, not after, the parent DevSecOps implementation.

### Guiding Principles

- **Evidence infrastructure first**: You cannot investigate what you did not record. The first quarter focuses entirely on evidence collection before any investigation capability is built.
- **Sequencing is not optional**: Each phase builds on the previous one. Artifact forensics (Q2) requires evidence infrastructure (Q1). Agent forensics (Q4) requires artifact forensics (Q2) and SIEM integration (Q3).
- **Measure from day one**: Establish baseline metrics at the start of Q1. Improvement cannot be demonstrated without a baseline.
- **Test before you need it**: Every runbook must be exercised in a simulated incident before it is used in a real one. A runbook that has never been tested should be labeled "DRAFT — not production-ready."

### Key Stakeholders

| Stakeholder | Role in Roadmap |
|---|---|
| CISO / Security Leadership | Executive sponsor; legal hold escalation authority; board reporting |
| VP Engineering | Co-sponsor; ensures engineering teams prioritize evidence infrastructure work |
| Platform Engineers | CI/CD audit log integration; evidence bucket configuration; Kubernetes audit policy |
| Security Engineers | Investigation runbooks; SIEM correlation rules; forensics tooling deployment |
| Legal Counsel | Legal hold procedures; regulatory evidence requirements; GDPR conflict resolution |
| Cloud Engineers | CloudTrail configuration; VPC Flow Logs; Object Lock bucket setup |
| DevSecOps Lead | Overall program coordination; maturity assessment; roadmap tracking |

---

## Forensics Readiness Score — 5 Levels

Detailed level descriptions are in [framework.md — Forensics Readiness Score](framework.md). The roadmap below targets progression through each level.

| Level | Name | Roadmap Target |
|---|---|---|
| 1 | Ad Hoc | Baseline state (most organizations) |
| 2 | Instrumented | End of Q1 |
| 3 | Evidenced | End of Q2 |
| 4 | Repeatable | End of Q4 |
| 5 | Continuous | End of Q6 |

---

## 18-Month Roadmap by Quarter

### Q1 (Months 1–3): Evidence Infrastructure

**Theme**: Enable all required evidence sources; configure tamper-evident storage; document the evidence inventory.

**Target Forensics Readiness Level**: Level 2 (Instrumented)

**Milestone 1.1: Cloud Audit Logging** (Month 1)
- Enable CloudTrail in all regions with multi-region trail
- Enable CloudTrail log file validation
- Enable VPC Flow Logs for all production VPCs
- Enable cloud provider audit logs (GCP Audit Logs or Azure Monitor if applicable)
- Create Object Lock bucket in Compliance mode for log storage

**Deliverables**:
- CloudTrail delivering to Object Lock bucket across all regions
- VPC Flow Logs shipping to Object Lock bucket for all production VPCs
- Log delivery verified (no gaps, no delivery errors)

---

**Milestone 1.2: CI/CD and Secrets Audit Logging** (Month 1–2)
- Configure GitHub/GitLab organization audit log export to Object Lock bucket
- Enable Vault audit logging (file + syslog)
- Configure Vault audit log to ship to SIEM
- Enable AWS Secrets Manager CloudTrail data events
- Document all secrets and their access policies

**Deliverables**:
- CI platform audit logs flowing to SIEM and Object Lock bucket
- Vault audit log active and confirmed shipping
- Secrets access audit trail verified

---

**Milestone 1.3: Kubernetes Audit Logging** (Month 2)
- Deploy audit policy to all production Kubernetes clusters
- Configure Fluent Bit or Fluentd to ship audit logs to SIEM
- Validate audit log capture for pod exec, secret access, and RBAC changes
- Verify EKS CloudWatch Logs enabled if using managed EKS

**Deliverables**:
- Kubernetes audit logs in SIEM with < 5-minute delivery latency
- Pod exec events confirmed captured in audit trail
- Retention policy confirmed (minimum 1 year)

---

**Milestone 1.4: Evidence Inventory and Gap Assessment** (Month 3)
- Document all evidence sources: what is collected, where stored, retention, tamper-evidence
- Identify evidence gaps (evidence sources not yet enabled)
- Prioritize gap remediation for Q2
- Establish evidence infrastructure ownership (who is responsible for each source)
- Baseline current Forensics Readiness Score

**Deliverables**:
- Evidence inventory document (see [architecture.md](architecture.md) for template)
- Forensics readiness gap analysis
- Evidence source ownership matrix
- Baseline Forensics Readiness Score: Level 2

**Q1 KPIs**:
- Evidence sources enabled: all required sources from [architecture.md](architecture.md)
- Tamper-evident storage: 100% of log destinations
- Evidence delivery gap: 0 sources with delivery interruptions > 1 hour
- Evidence inventory: documented and reviewed by security and platform leads

---

### Q2 (Months 4–6): Artifact Forensics

**Theme**: Deploy artifact signing, SLSA provenance, and SBOM generation. Build the artifact chain of custody that enables supply chain forensics investigations.

**Target Forensics Readiness Level**: Level 3 (Evidenced)

**Milestone 2.1: Cosign Signing Rollout** (Month 4)
- Deploy Cosign keyless signing to all production CI pipelines
- Verify Rekor entries created for all production image builds
- Document signing identity patterns (expected OIDC subject regexps per pipeline)

**Deliverables**:
- 100% of production container image builds produce Cosign signature
- Signing identity registry documented (which workflow produces which OIDC subject)
- Rekor log entry retrieval tested for a representative sample of images

---

**Milestone 2.2: SLSA Provenance Generation** (Month 4–5)
- Integrate slsa-github-generator (or equivalent) into all production build pipelines
- Target SLSA Level 2 as minimum; Level 3 for highest-criticality services
- Validate provenance attestation retrieval for all production images
- Document provenance verification commands for each pipeline type

**Deliverables**:
- SLSA provenance attestation generated for all production artifacts
- Provenance verification runbook drafted and reviewed
- At least one investigation exercise using provenance to reconstruct build lineage

---

**Milestone 2.3: SBOM Generation and Attestation** (Month 5–6)
- Integrate syft into all container image build pipelines
- Attach SBOM as signed Cosign attestation on each image build
- Configure SBOM storage with artifact versioning (SBOM retained with each image version)
- Test SBOM retrieval and query (find all images using a given dependency)

**Deliverables**:
- 100% of production container image builds produce signed SBOM
- SBOM query runbook: "which production images contain [dependency]@[version]?"
- SBOM retrieval verified from a forensics investigation context (read-only role)

---

**Milestone 2.4: Signature Verification Enforcement** (Month 6)
- Deploy Kyverno or OPA Gatekeeper policy requiring Cosign signature on production deployments
- Test enforcement: verify an unsigned image is blocked from production
- Configure policy to alert (not block) for staging; block for production
- Document exception process (how to allow an emergency deployment that cannot be signed)

**Deliverables**:
- Signature verification enforced at production deployment gate
- At least one blocked deployment confirmed (policy is enforcing, not just auditing)
- Exception process documented and approved

**Q2 KPIs**:
- % production builds with Cosign signature: 100%
- % production builds with SLSA provenance attestation: 100%
- % production builds with signed SBOM: 100%
- Unsigned deployments to production blocked by policy: yes (confirmed)
- Forensics Readiness Score: Level 3

---

### Q3 (Months 7–9): SIEM Integration and Detection

**Theme**: Integrate evidence sources into SIEM with cross-source correlation rules; deploy anomaly alerting; develop and test investigation runbooks.

**Target Forensics Readiness Level**: Low Level 4 (Repeatable — initial runbooks)

**Milestone 3.1: SIEM Integration** (Month 7)
- Connect all evidence sources (cloud audit, k8s audit, CI audit, Vault, VPC Flow Logs) to SIEM
- Validate data quality: correct parsing, timestamps, field extraction
- Configure retention in SIEM (minimum 1 year hot; 3 years cold/archive)
- Test cross-source querying (can you correlate a Vault access event with a CloudTrail event by timestamp and IP?)

**Deliverables**:
- All evidence sources indexed in SIEM
- Cross-source correlation query confirmed working
- SIEM retention policy confirmed and documented

---

**Milestone 3.2: Priority Correlation Rules** (Month 7–8)
- Deploy rules for the five highest-priority incident types (see [best-practices.md](best-practices.md) for rule examples)
- Tune rules against historical data to reduce false positive rate
- Configure alert-to-ticket automation (no manual ticket creation for automated alerts)
- Validate each rule fires correctly against a synthetic test event

**Deliverables**:
- Minimum 5 production correlation rules active
- Alert-to-ticket integration operational
- Each rule validated against test event

---

**Milestone 3.3: Investigation Runbooks** (Month 8–9)
- Write investigation runbooks for each of the six investigation domains
- Include environment-specific values (actual bucket names, cluster names, SIEM queries)
- Conduct tabletop exercise for each P1 scenario type
- Publish runbooks to incident response system (Jira, PagerDuty runbook, or internal wiki)

**Deliverables**:
- Six domain runbooks written and reviewed
- Two tabletop exercises completed
- Runbooks published and accessible to all on-call security engineers

---

**Milestone 3.4: MTTD and MTTR Baseline** (Month 9)
- Define MTTD (mean time to detect) measurement methodology for each alert type
- Measure MTTD for all correlation rule-triggered alerts over the past 30 days
- Measure MTTR (mean time to recover) for all closed incidents in the past quarter
- Publish baseline metrics

**Deliverables**:
- MTTD baseline established per alert type
- MTTR baseline established per severity level
- Metrics dashboard accessible to security and engineering leadership

**Q3 KPIs**:
- % evidence sources indexed in SIEM: 100%
- Active correlation rules: ≥ 5
- Alert-to-ticket automation: operational
- Domain runbooks: 6 (one per domain)
- Tabletop exercises completed: ≥ 2
- MTTD baseline established: yes
- Forensics Readiness Score: Level 4 (initial)

---

### Q4 (Months 10–12): Agent and AI Forensics

**Theme**: If AI agents are deployed in DevSecOps workflows, build the forensic infrastructure required to investigate agent incidents. Run a live forensics exercise.

**Target Forensics Readiness Level**: Level 4 (Repeatable — complete)

**Milestone 4.1: Agent Forensics Assessment** (Month 10)
- Inventory all AI agents operating in the DevSecOps environment
- For each agent: document the tools it can invoke, its authorization scope, and the system prompt
- Assess current tool call logging: is it structured? is it shipped to tamper-evident storage?
- Identify gaps against the agent forensics requirements in [agent-forensics.md](agent-forensics.md)

**Deliverables**:
- Agent inventory with tool permissions documented
- Agent forensics gap assessment
- Prioritized remediation plan for gaps

---

**Milestone 4.2: Agent Audit Infrastructure** (Month 10–11)
*Only applicable if AI agents are deployed.*

- Deploy structured tool call logging for all agents
- Implement system prompt versioning in version control
- Configure tool call logs to ship to tamper-evident SIEM
- Test tool call log retrieval for a past agent session

**Deliverables**:
- Tool call logging operational for all agents
- System prompts versioned and hash-referenced in logs
- Tool call log retrieval confirmed from investigation role

---

**Milestone 4.3: Agent Investigation Playbooks** (Month 11)
- Write investigation runbooks for AF-01 through AF-04 (see [agent-forensics.md](agent-forensics.md))
- Customize with actual agent IDs, tool names, and authorization policies
- Conduct tabletop exercise for AF-02 (suspected prompt injection)

**Deliverables**:
- Agent investigation playbooks written and reviewed
- Tabletop exercise for prompt injection scenario completed

---

**Milestone 4.4: Live Forensics Exercise** (Month 12)
- Design a simulated P2 incident that spans at least two domains
- Execute the investigation using the runbooks
- Measure time from simulation start to complete investigation report
- Document gaps found during the exercise and create remediation action items

**Deliverables**:
- Live forensics exercise completed
- Exercise report with gap analysis
- Action items tracked in security backlog
- Forensics Readiness Score: Level 4 (complete)

**Q4 KPIs**:
- Agent forensics gap assessment completed: yes
- Agent tool call logging deployed: yes (if agents in use)
- Agent playbooks: 4
- Live forensics exercise: 1
- Exercise completion time vs. target: documented
- Forensics Readiness Score: Level 4

---

### Q5 (Months 13–15): Regulatory Readiness

**Theme**: Ensure forensic capability meets regulatory evidence requirements; implement evidence packaging; complete legal hold procedures.

**Milestone 5.1: Regulatory Evidence Requirements Analysis** (Month 13)
- Identify applicable regulatory frameworks (SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR)
- For each framework, identify specific evidence retention and incident response requirements
- Map requirements to current forensics capability
- Identify compliance gaps

**Deliverables**:
- Regulatory requirements matrix
- Compliance gap analysis

---

**Milestone 5.2: Evidence Packaging** (Month 13–14)
- Implement evidence packaging script (see [implementation.md](implementation.md) Phase 4)
- Define evidence package format and hashing procedure
- Test evidence package against a historical incident
- Review package format with legal counsel

**Deliverables**:
- Evidence packaging script tested and operational
- Evidence package format approved by legal counsel

---

**Milestone 5.3: Legal Hold Procedures** (Month 14–15)
- Complete [legal-hold-procedures.md](legal-hold-procedures.md) with organization-specific values
- Identify legal hold custodians per evidence type
- Train legal hold custodians on procedures
- Test legal hold activation procedure in a tabletop exercise

**Deliverables**:
- Legal hold procedures document complete and reviewed by legal counsel
- Legal hold custodians identified and trained
- Legal hold tabletop exercise completed

**Q5 KPIs**:
- Regulatory requirements matrix: complete
- Evidence packaging: operational
- Legal hold procedures: reviewed by legal counsel
- Legal hold tabletop: completed

---

### Q6 (Months 16–18): Continuous Evidence and Simulation

**Theme**: Implement continuous evidence integrity monitoring; run forensics simulation exercises; establish continuous improvement cycle.

**Milestone 6.1: Continuous Evidence Monitoring** (Month 16)
- Deploy evidence gap detection (alert if evidence delivery interrupted for > 2 hours)
- Monitor evidence source health (SIEM ingestion rate, parser error rate)
- Implement weekly evidence integrity check (verify Object Lock configuration intact)
- Alert on unexpected changes to evidence infrastructure (bucket policy changes, SIEM forwarding disabled)

**Deliverables**:
- Evidence gap detection operational
- Evidence health dashboard available to security team
- Weekly integrity check automated

---

**Milestone 6.2: Forensics Simulation Exercises** (Month 16–17)
- Design and run two advanced simulation exercises:
  - Supply chain compromise spanning pipeline → artifact → cloud deployment
  - Agent-assisted attack: prompt injection causing unauthorized tool call
- Measure MTTD, MTTC (mean time to contain), and MTTR for each simulation
- Compare against baseline from Q3

**Deliverables**:
- Two simulation exercises completed
- MTTD/MTTC/MTTR compared against Q3 baseline
- Improvement trends documented

---

**Milestone 6.3: Continuous Improvement Cycle** (Month 17–18)
- Establish quarterly forensics review process (review all incidents, update runbooks, assess new threats)
- Integrate forensics capability assessment into annual security review
- Publish quarterly forensics KPI report to security leadership
- Assess Forensics Readiness Score against Level 5 criteria

**Deliverables**:
- Quarterly forensics review process documented and operational
- Q6 forensics KPI report published
- Forensics Readiness Score: Level 5 (if criteria met)

**Q6 KPIs**:
- Evidence gap detection: operational
- Simulation exercises: 2
- MTTD improvement vs. Q3 baseline: positive trend
- MTTC improvement vs. Q3 baseline: positive trend
- MTTR improvement vs. Q3 baseline: positive trend
- Forensics Readiness Score: Level 5

---

## KPIs per Phase

| KPI | Q1 Target | Q2 Target | Q3 Target | Q4 Target | Q5 Target | Q6 Target |
|---|---|---|---|---|---|---|
| Evidence sources enabled | All required | All required + artifact signing | + SIEM integration | + agent logging | + regulatory packaging | Continuous monitoring |
| Tamper-evident storage | 100% | 100% | 100% | 100% | 100% | 100% |
| Artifacts with Cosign signature | — | 100% | 100% | 100% | 100% | 100% |
| Artifacts with SLSA provenance | — | 100% | 100% | 100% | 100% | 100% |
| Active SIEM correlation rules | — | — | ≥ 5 | ≥ 10 | ≥ 10 | Continuously tuned |
| Investigation runbooks | — | — | 6 | 10 (+ agent) | Reviewed | Quarterly updated |
| Exercises completed | — | — | 2 (tabletop) | 1 (live fire) | 1 (legal hold) | 2 (simulation) |
| MTTD baseline | — | — | Established | Baseline | Improving | Improving |
| Forensics Readiness Score | Level 2 | Level 3 | Low Level 4 | Level 4 | Level 4 | Level 5 |

---

## Tooling Adoption Sequence

| Tool | Phase | Purpose |
|---|---|---|
| AWS CloudTrail / GCP Audit Logs / Azure Monitor | Q1 | Cloud audit logging |
| S3 Object Lock / Azure Immutable Storage | Q1 | Tamper-evident log storage |
| Fluent Bit / Fluentd | Q1 | Kubernetes audit log shipping |
| SIEM (Splunk / Elastic / OpenSearch / Panther) | Q1 | Log aggregation and investigation interface |
| Cosign | Q2 | Artifact signing |
| slsa-github-generator | Q2 | SLSA provenance |
| syft | Q2 | SBOM generation |
| grype | Q2 | SBOM vulnerability query (forensic SBOM analysis) |
| Kyverno / OPA Gatekeeper | Q2 | Signature enforcement at admission |
| rekor-cli | Q2 | Rekor log querying |
| Falco | Q3 | Runtime anomaly detection; Kubernetes audit enrichment |
| Hubble (Cilium) | Q3 | Kubernetes network observability |
| Agent logging framework | Q4 | Tool call log collection |
| GPG (forensic signing) | Q5 | Evidence package signing |

---

## Organizational Readiness

### Required Roles

The following roles must be clearly assigned before beginning the roadmap. These can be individuals, teams, or shared responsibilities — but ownership must be explicit.

| Responsibility | Owner |
|---|---|
| Evidence infrastructure (log buckets, Object Lock, shipping config) | Cloud/Platform Engineering |
| SIEM administration and correlation rules | Security Engineering |
| Artifact signing pipeline integration | Platform/DevSecOps Engineering |
| Investigation runbook ownership | Security Engineering |
| Legal hold authority | Legal Counsel + CISO |
| Evidence chain of custody | Security Engineering (custodian) + Legal (reviewer) |
| Forensics exercise design and execution | Security Engineering |
| Agent forensics (if applicable) | AI/ML Platform Team + Security Engineering |

### Training Requirements

| Role | Training Required Before |
|---|---|
| All security engineers | Q3 (investigation runbooks go live) |
| Platform engineers | Q1 (evidence infrastructure deployment) |
| On-call SREs | Q3 (runbooks accessible to on-call rotation) |
| Legal hold custodians | Q5 (legal hold procedures finalized) |
| Management notification recipients | Q1 (P1 communication template published) |
