# Changelog

All notable changes to this framework are documented here.
Format: [version] — [date] — [summary of changes]

## [Unreleased]

- [2026-04-07] Integrated into techstream-docs ecosystem index — added to Framework Repository Index table and Mermaid ecosystem map as cross-cutting layer node (FIRF) with edges from secure-ci-cd, supply-chain, cloud-security, and ai-devsecops frameworks
- [2026-04-07] Added to techstream-docs framework-selection-guide: decision tree path for forensics investigation, prerequisites in "When NOT to Use" table, and scope boundaries
- [2026-04-07] Added "Multi-domain compromise requiring forensic investigation" incident type and Detection/Forensics domain lead to cross-framework-incident-response.md
- [2026-04-07] Agent forensics terms (Agent forensics) added to techstream-books master glossary

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
