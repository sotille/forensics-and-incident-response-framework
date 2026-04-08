# Forensics and Incident Response Framework for DevSecOps

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](CHANGELOG.md)
[![Documentation](https://img.shields.io/badge/docs-comprehensive-brightgreen.svg)](docs/)
[![Maintained](https://img.shields.io/badge/Maintained-yes-green.svg)](CHANGELOG.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

DevSecOps organizations invest heavily in prevention — scanners, gates, signing, and hardening. But when those controls are bypassed or fail, the ability to investigate what happened, preserve evidence, and understand blast radius is often absent. Ephemeral CI runners terminate after a build. Containers are deleted after a pod restart. Lambda functions leave behind only structured logs if you remembered to enable them. The "scene of the crime" is a git commit hash, an OCI image digest, or an OIDC token that expired 15 minutes ago.

This framework provides the structured procedures, evidence architecture, and investigation playbooks required to conduct a complete forensic investigation across the six domains that matter most in DevSecOps: CI/CD pipelines, cloud workloads and containers, software supply chain artifacts, identity and credentials, runtime systems, and AI agent operations. It covers both the infrastructure you must build before an incident and the procedures you execute after one.

---

## Overview

The framework addresses the central tension in modern DevSecOps forensics: the same properties that make cloud-native infrastructure secure by design — immutability, ephemerality, automation, least privilege — also destroy forensic evidence unless you deliberately architect for preservation. A compromised GitHub Actions runner is gone the moment the job finishes. An EKS pod that processed a malicious artifact is evicted. A Lambda function that exfiltrated credentials has no persistent disk at all.

The approach taken here is evidence-first architecture: define the evidence you will need in a future investigation before you build the systems that will be investigated. This framework covers what to log, where to store it immutably, how to correlate across domains, and how to execute structured investigations when incidents occur.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Documentation](#documentation)
3. [Repository Structure](#repository-structure)
4. [Who Should Use This Framework](#who-should-use-this-framework)
5. [Contributing](#contributing)
6. [License](#license)
7. [Learning Resources](#learning-resources)

---

## Quick Start

### Prerequisites

Before using the investigation playbooks in this framework, your environment must have:

- **Tamper-evident log storage**: CI/CD audit logs, cloud provider audit logs (CloudTrail, GCP Audit Logs, Azure Monitor), and Kubernetes audit logs shipped to an append-only, WORM-protected store (S3 Object Lock, Azure Immutable Blob, Splunk with forwarder-only access)
- **Artifact signing and provenance**: Cosign signatures and SLSA provenance attestations generated for all production artifacts
- **SBOM generation**: Software Bill of Materials generated at build time and stored with each artifact version
- **Secret audit logging**: HashiCorp Vault audit logging enabled and exported; AWS Secrets Manager CloudTrail events enabled
- **Network logging**: VPC Flow Logs enabled for all production VPCs; Kubernetes network policy logging where applicable

If these prerequisites are not in place, start with [docs/implementation.md](docs/implementation.md) Phase 1 before attempting to use the investigation playbooks.

### Recommended Reading Order

If you are new to this framework, read in this order:

1. [docs/introduction.md](docs/introduction.md) — Why forensics is different in DevSecOps
2. [docs/architecture.md](docs/architecture.md) — What infrastructure you need to investigate effectively
3. [docs/framework.md](docs/framework.md) — The forensics framework and investigation model
4. [docs/implementation.md](docs/implementation.md) — How to build forensics capability incrementally
5. Domain playbooks as relevant to your environment

If you are responding to an active incident, go directly to the relevant domain playbook:

- Pipeline compromise → [docs/pipeline-forensics.md](docs/pipeline-forensics.md)
- Cloud/container compromise → [docs/cloud-forensics.md](docs/cloud-forensics.md)
- Supply chain compromise → [docs/supply-chain-forensics.md](docs/supply-chain-forensics.md)
- Agent/AI system incident → [docs/agent-forensics.md](docs/agent-forensics.md)

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/introduction.md](docs/introduction.md) | Why forensics is fundamentally different in DevSecOps environments |
| [docs/architecture.md](docs/architecture.md) | Evidence architecture: what to log, where, and how to protect it |
| [docs/framework.md](docs/framework.md) | The core forensics framework: IR phases, investigation domains, severity model |
| [docs/implementation.md](docs/implementation.md) | Phased implementation plan (0–30 days through 180+ days) |
| [docs/best-practices.md](docs/best-practices.md) | Evidence handling, common mistakes, communication templates |
| [docs/roadmap.md](docs/roadmap.md) | 18-month maturity roadmap |
| [docs/pipeline-forensics.md](docs/pipeline-forensics.md) | Pipeline forensics playbooks including AI/agent pipeline threats (PL-07, PL-08) |
| [docs/cloud-forensics.md](docs/cloud-forensics.md) | Cloud and container forensics: EC2, EKS, Lambda, containers |
| [docs/supply-chain-forensics.md](docs/supply-chain-forensics.md) | Supply chain forensics using SBOM, SLSA provenance, Cosign, and Rekor |
| [docs/agent-forensics.md](docs/agent-forensics.md) | AI agent forensics: tool call reconstruction, prompt injection detection, agent chain of custody |
| [docs/evidence-chain-of-custody.md](docs/evidence-chain-of-custody.md) | Evidence collection, packaging, hashing, and legal chain of custody |
| [docs/legal-hold-procedures.md](docs/legal-hold-procedures.md) | Legal hold triggers, implementation, GDPR considerations, escalation matrix |

---

## Repository Structure

```
forensics-and-incident-response-framework/
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── docs/
    ├── introduction.md
    ├── architecture.md
    ├── framework.md
    ├── implementation.md
    ├── best-practices.md
    ├── roadmap.md
    ├── pipeline-forensics.md
    ├── cloud-forensics.md
    ├── supply-chain-forensics.md
    ├── agent-forensics.md
    ├── evidence-chain-of-custody.md
    └── legal-hold-procedures.md
```

---

## Who Should Use This Framework

| Role | Primary Use |
|------|-------------|
| **Security Engineers** | Build evidence architecture; develop investigation runbooks; execute incident investigations |
| **Platform/SRE Engineers** | Configure tamper-evident logging; implement artifact signing and provenance; integrate forensics tooling into platform |
| **DevSecOps Leads** | Program-level forensics maturity planning; roadmap prioritization; team readiness assessment |
| **CISOs and Security Managers** | Understand forensics capability gaps; evaluate legal and regulatory readiness; commission forensics exercises |
| **Incident Responders** | Domain-specific investigation playbooks; evidence collection procedures; blast radius assessment |
| **Legal and Compliance Teams** | Legal hold procedures; evidence packaging standards; regulatory evidence requirements |

This framework is most directly applicable to organizations operating in cloud-native environments with CI/CD pipelines, container workloads, and supply chain artifact management. Organizations using AI agents in DevSecOps workflows will find [docs/agent-forensics.md](docs/agent-forensics.md) to be new territory not covered by other frameworks.

---

## Ecosystem Cross-References

This framework exists within the broader Techstream DevSecOps ecosystem:

- **[secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md](../secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md)** — The foundational pipeline forensics playbook; [docs/pipeline-forensics.md](docs/pipeline-forensics.md) expands beyond it with AI/agent threat classes
- **[software-supply-chain-security-framework/docs/incident-response-playbook.md](../software-supply-chain-security-framework/docs/incident-response-playbook.md)** — Supply chain IR; consolidated and extended in [docs/supply-chain-forensics.md](docs/supply-chain-forensics.md)
- **[cloud-security-devsecops/docs/incident-response-playbooks.md](../cloud-security-devsecops/docs/incident-response-playbooks.md)** — Cloud IR; consolidated and extended in [docs/cloud-forensics.md](docs/cloud-forensics.md)
- **[devsecops-framework/docs/](../devsecops-framework/docs/)** — Parent DevSecOps framework
- **[techstream-docs/](../techstream-docs/)** — Central documentation index

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this framework.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

---

## Learning Resources

- **[techstream-learn/book-3-cloud-security](../techstream-learn/book-3-cloud-security/)** — Cloud security engineering fundamentals: logging architecture, evidence collection, and cloud-native forensics labs
- **[techstream-learn/book-5-ai-agentic-security](../techstream-learn/book-5-ai-agentic-security/)** — AI and agentic systems security companion labs, including:
  - [Ch 14 — The Agent Forensics Problem](../techstream-learn/book-5-ai-agentic-security/ch14-forensics-problem/) — Evidence gap analysis for uninstrumented agent deployments
  - [Ch 15 — The Five Forensic Questions Framework](../techstream-learn/book-5-ai-agentic-security/ch15-five-forensic-questions/) — Structured investigation using the Five Questions against simulated incident evidence
  - [Ch 16 — Agent Forensics Investigation Playbooks](../techstream-learn/book-5-ai-agentic-security/ch16-forensics-playbooks/) — Executing AF-01 and AF-02 playbooks on realistic evidence sets
  - [Ch 17 — Agent Forensics Readiness](../techstream-learn/book-5-ai-agentic-security/ch17-forensics-readiness/) — Forensic readiness assessment and tabletop exercise design
  - [Ch 04 — Agent Forensics: Session Reconstruction](../techstream-learn/book-5-ai-agentic-security/ch04-agent-forensics/) — Reconstruct sessions, detect injection, verify provenance (Lab 04)
- **[techstream-books/VOLUMES.md](../techstream-books/VOLUMES.md)** — Full index of Techstream technical volumes; this framework is a primary source for Volume 3 (Cloud-Native Security) and Volume 5 (AI and Agentic Systems Security)
- **[www.techstream.app](https://www.techstream.app)** — Techstream platform and additional resources
