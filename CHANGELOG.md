# Changelog

All notable changes to this framework are documented here.
Format: [version] — [date] — [summary of changes]

## [Unreleased]

- [2026-04-08] Expanded docs/ai-behavioral-baseline.md — added Post-Incident Baseline Recalibration Procedure (7-step process): incident window determination, session quarantine with Python implementation, baseline integrity verification before recalculation, post-incident calibration dataset collection (minimum 100 sessions or 14 days flagged PROVISIONAL), conservative threshold adjustment (20% tighter for 90 days post-incident with per-metric table), baseline version record schema with incident exclusion metadata, and staging validation requirement (< 5% false-positive rate before production return); closes the gap where the section mentioned recalibration after incidents but provided no operational procedure

- [2026-04-08] Created docs/agent-forensics/af-06-model-supply-chain-tampering.md — AF-06: Model supply chain tampering detected post-deployment investigation playbook; contamination window determination (last known-good model digest to suspension); Five Questions applied across all sessions in the window; layer-hash comparison for weight poisoning detection using safetensors/PyTorch; ModelScan integration for deserialization attack detection; registry push forensics (who pushed the tampered model and when); behavioral analysis procedure in isolated sandbox; blast radius assessment for all actions taken with tampered model; mandatory controls: immutable model tags, digest verification at load time, SafeTensors migration, Cosign model signing; behavioral baseline invalidation and recalibration requirements; cross-referenced with AF-03, AF-05, PS-01, ai-devsecops-framework/docs/model-supply-chain.md
- [2026-04-08] Created docs/agent-forensics/af-04-agent-permission-escalation.md — AF-04: Agent escalated its own permissions investigation playbook; covers IAM policy modification, Kubernetes RBAC changes, tool authorization policy git commits, and system prompt modification by agent identity; reversion procedure before investigation (CloudTrail and RBAC rollback commands); Five Questions for permission escalation; escalation trigger classification (injection-facilitated, system prompt ambiguity, explicit user instruction, model behavior anomaly); scope-of-escalation assessment (permission delta computation, actions taken with escalated permissions); policy hardening: self_modification_prohibited enforcement, prohibited_tools list for iam/rbac/policy/settings, CODEOWNERS for policy files, branch protection; system prompt hardening with prohibited and required phrasing templates
- [2026-04-08] Created docs/agent-forensics/af-03-artifact-unknown-provenance.md — AF-03: Agent-generated artifact of unknown provenance in production investigation playbook; covers artifacts lacking valid Cosign signature, missing/invalid SLSA provenance, digest mismatch, or registry push not correlated with authorized pipeline run; Kyverno policy for artifact quarantine without deletion; Five Questions with authorization determination matrix (AUTHORIZED/UNAUTHORIZED/POTENTIALLY COMPROMISED/UNDETERMINED); static integrity verification (cosign verify, slsa-verifier, crane export); behavioral analysis procedure in forensic namespace; blast radius assessment; credential rotation procedure; mandatory control improvements (session-scoped OIDC credentials, approval gates for production registry push, audit trail content_source field); cross-referenced with AF-01, AF-04, PL-02, PS-01, ai-devsecops-framework/docs/blast-radius-containment.md

- [2026-04-08] Expanded docs/ai-behavioral-baseline.md — two major additions: (1) Temporal Pattern Baselines section covering time-of-day and day-of-week distribution baselines, session initiation trigger baseline, orphaned session detection, inter-session gap analysis, and Python implementation for recording temporal distributions; (2) LLM Non-Determinism and Baseline Interpretation section explaining the statistical vs. deterministic baseline distinction, invariant signals (policy-enforced zero calls, allowlist-blocked network, authorization violations), non-determinism-affected signals with appropriate thresholds, and the non-determinism trap in forensic investigation — addressing gap where dimension 6 (temporal patterns) was listed in baseline dimensions but had no corresponding documentation section

- [2026-04-08] Created docs/playbooks/pl-02-slopsquatting-supply-chain.md — PL-02: Slopsquatting and AI-hallucinated package supply chain attack investigation playbook; covers four investigation phases (triage, containment, forensic analysis, post-incident); includes package origin determination procedure, deployment scope assessment, static and behavioral malicious package analysis, Five Supply Chain Forensic Questions, mandatory notification checklist, indicators of compromise reference, and evidence chain of custody requirements; cross-referenced with PL-01, PS-01, and ai-devsecops-framework threat-intelligence.md
- [2026-04-08] Created docs/playbooks/pl-03-ai-code-review-approval-chain.md — PL-03: Compromised AI code review approval chain investigation playbook; covers PR audit record collection (GitHub App audit log, AI reviewer session log, system prompt version), blast radius assessment, AI reviewer behavior analysis including failure mode classification (direct injection, indirect injection, context window saturation, capability gap, jailbreak, config bypass), historical pattern review, containment and mandatory control improvements (input sanitization, canary token, output schema validation), and investigation report requirements for technical, executive, and legal audiences
- [2026-04-08] Created docs/agent-forensics/af-01-prompt-injection-unauthorized-action.md — AF-01: Prompt injection unauthorized agent action investigation playbook; complete Five Questions procedure for single-agent injection incidents; evidence preservation for ephemeral session state; Q2 injection content detection with Unicode anomaly scanning; injection vector classification taxonomy (6 classes); attribution confidence levels (Confirmed/Probable/Suspected/Unknown); per-action-type remediation procedure; injection source remediation by vector class; mandatory control improvements table
- [2026-04-08] Created docs/agent-forensics/af-02-multi-agent-cascade-compromise.md — AF-02: Multi-agent cascade compromise investigation playbook; full chain suspension procedure (Kubernetes and ECS); cascade path reconstruction (agent chain map, injection entry point identification, content relay tracing); Five Questions applied per agent; cumulative blast radius assessment across the chain; shared credential assessment and rotation; post-containment control improvements (per-agent credentials, input validation at every boundary, chain-scope circuit breakers, inter-agent trust levels); post-incident controlled injection test requirement

- [2026-04-08] Created docs/ai-behavioral-baseline.md — forensic behavioral baseline for AI agents: six baseline dimensions (tool call frequency, resource consumption, network egress, session scope, authorization patterns, temporal patterns), reference baselines by agent type (code review agent, vulnerability triage agent, autonomous remediation agent) with P5–P95 and P99 statistical values, anomaly detection thresholds and severity classification (CRITICAL/HIGH/MEDIUM), tool call sequence anomaly patterns including prompt injection indicators in parameters, network allowlist reference and egress anomaly indicators, Python baseline calibration script, baseline drift and recalibration guidance, and version alignment requirements for forensic investigation

- [2026-04-07] Created docs/playbooks/ directory with docs/playbooks/ai-supply-chain.md — Playbook PS-01: AI-assisted supply chain attack investigation covering trigger conditions, evidence preservation procedures with chain-of-custody requirements, six investigation steps (package lineage, registry forensics, content analysis, AI interaction reconstruction, blast radius assessment, model supply chain integrity), attribution/escalation matrix for opportunistic vs. targeted attacks, containment action tables, and structured evidence report template
- [2026-04-07] Created docs/agent-forensics/five-questions-framework.md — dedicated deep-dive document for the Five Forensic Questions framework: question-by-question evidence sources, evidence collection commands, evidence mapping table, investigation scope determination algorithm, gap analysis guidance, and audit readiness checklist; integrates with investigation playbooks in agent-forensics.md
- [2026-04-07] Created docs/agent-forensics/readiness-guide.md — Agent Forensics Readiness Guide with five-level Forensics Readiness Score (FRS), level-by-level requirements and checklists, forensic infrastructure architecture (append-only audit store on AWS and Kubernetes), context window capture strategy and implementation, session recording and replay procedure, chain of custody for AI agent evidence, tabletop exercise structure, and cost/overhead tradeoffs
- [2026-04-07] Integrated into techstream-docs ecosystem index — added to Framework Repository Index table and Mermaid ecosystem map as cross-cutting layer node (FIRF) with edges from secure-ci-cd, supply-chain, cloud-security, and ai-devsecops frameworks
- [2026-04-07] Added to techstream-docs framework-selection-guide: decision tree path for forensics investigation, prerequisites in "When NOT to Use" table, and scope boundaries
- [2026-04-07] Added "Multi-domain compromise requiring forensic investigation" incident type and Detection/Forensics domain lead to cross-framework-incident-response.md
- [2026-04-07] Agent forensics terms (Agent forensics) added to techstream-books master glossary


---

## [1.0.0] — 2026-05-17

### Added — Governance and Documentation

- `SECURITY.md` — security reporting policy and supported versions
- `CITATION.cff` — academic and industry citation metadata (CFF v1.2.0)
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `README.md` "Related Publications" section linking the TechStream article series

### Federal-standards alignment (this release)

- Continued alignment with Executive Order 14028 (Improving the Nation's Cybersecurity)
- Continued alignment with Executive Order 14306 (June 2025)
- Continued alignment with NIST SP 800-218 (SSDF) v1.1
- Acknowledgment of NIST SP 1800-44 (NCCoE DevSecOps Practices) preliminary draft, March 2026

### Related publications referenced in this release

  - "Why Your AI Agent Is the Next SolarWinds" (Medium, May 2026)

### Changed

- Documentation cross-references updated to reflect the public TechStream framework portfolio at https://github.com/sotille

## [1.0.0] — 2024-01-15

- Initial public release
- Core framework document covering 8-phase IR lifecycle and 6 investigation domains
- Evidence architecture document with tamper-evident storage configuration
- Phased implementation guide (0–30, 30–90, 90–180, 180+ days)
- Pipeline forensics playbooks PL-01 through PL-08, including AI/LLM pipeline manipulation (PL-07) and agentic unauthorized action (PL-08)
- Cloud and container forensics document covering EC2, EKS, Lambda, and container runtime
- Supply chain forensics document covering SBOM, SLSA provenance, Cosign, and Rekor
- Agent forensics document covering tool call reconstruction, prompt injection forensics, and agent chain of custody (playbooks AF-01 through AF-04)
- Evidence chain of custody procedures including packaging, hashing, and immutable storage
- Legal hold procedures including GDPR conflict resolution and escalation matrix
- 18-month forensics maturity roadmap aligned to 5-level Forensics Readiness Score
- Best practices document with communication templates and common mistake catalog
