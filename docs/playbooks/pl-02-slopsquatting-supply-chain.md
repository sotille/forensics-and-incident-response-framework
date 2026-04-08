# PL-02 — Slopsquatting and AI-Hallucinated Package Supply Chain Attack

**Playbook ID:** PL-02  
**Domain:** Software Supply Chain Forensics  
**Version:** 1.0 — 2026-04-08  
**Related playbooks:** PL-01 (Unauthorized Pipeline Agent Action), `ai-supply-chain.md` (PS-01), AF-01 (Prompt Injection)  
**Related framework docs:**  
- `software-supply-chain-security-framework/docs/sbom-guide.md`  
- `ai-devsecops-framework/docs/threat-intelligence.md`  
- `forensics-and-incident-response-framework/docs/supply-chain-forensics.md`

---

## Purpose and Scope

This playbook governs the forensic investigation and containment response when a slopsquatting attack or AI-hallucinated package dependency is confirmed or suspected in a software delivery pipeline.

**Slopsquatting** is a supply chain attack that exploits AI coding assistants' tendency to hallucinate package names that do not exist in the target registry. An attacker registers the hallucinated package name with malicious code, which is installed when a developer follows the AI suggestion without independent verification.

**Trigger conditions for this playbook:**

- SCA scanner flags a dependency not present in the organization's approved package allowlist
- A package was installed whose name does not appear in any historical version of the project's lockfile or manifest
- An AI coding assistant suggestion is identified as the origin of a newly introduced dependency
- Security team receives a tip (internal or external) about a hallucinated package name being registered with malicious content
- Anomalous network traffic from a build agent to an unexpected external endpoint (potential payload delivery or exfiltration)

**Out of scope:** Dependency confusion attacks originating from attacker-published packages without AI-hallucination involvement (see supply-chain-forensics.md for the broader supply chain attack taxonomy).

---

## Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| Incident Commander | Declares incident, coordinates response, owns stakeholder communication |
| Supply Chain Forensics Lead | Leads technical investigation; owns evidence chain of custody |
| Platform/Build Engineering | Provides access to build logs, runner environments, artifact registries |
| Application Security | Validates scope of deployed artifacts; assesses blast radius |
| Legal / Privacy | Advises on notification obligations if customer data is potentially affected |

---

## Phase 1 — Initial Triage (Target: < 2 hours from trigger)

### 1.1 Confirm the Package Origin

Determine whether the suspicious dependency was introduced by an AI assistant suggestion or through another path.

**Evidence to collect:**

```
Collect the following and preserve as evidence artifacts:

1. Git blame on the manifest file (requirements.txt, package.json, go.mod, pom.xml, etc.)
   $ git log --follow -p -- <manifest-file> | grep -A5 -B5 "<package-name>"

2. PR description, commit message, and review thread for the commit that introduced the dependency
   - Check if any AI assistant suggestion comment appears in the PR
   - Check if Copilot, Cursor, or similar tool metadata appears in the PR source

3. Developer interview (if internal actor): Ask which tools were active when the code was written

4. AI assistant log export (if organization manages the tool): Extract session log for the developer
   and timeframe corresponding to the commit timestamp ± 2 hours

5. Package registry lookup:
   $ pip show <package-name>     # Python
   $ npm info <package-name>     # Node.js
   $ go list -m <module-path>    # Go
   Record: package creation date, publisher identity, total download count, version history
```

**Decision — Proceed to Phase 2 if ANY of the following:**
- Package was registered within 30 days of the commit that introduced it
- Package publisher is unknown or has no prior publication history in this registry
- Package metadata (description, homepage, author) is missing or copied from a legitimate similar package
- Package was introduced in a commit that also contains AI assistant metadata

### 1.2 Assess Deployment Scope

Before containment, determine where the malicious package may have been deployed.

```
Evidence collection:

1. Artifact registry query — identify all container images and packages built since the
   malicious dependency was introduced:
   $ crane ls <registry>/<image> | xargs -I{} crane manifest <registry>/<image>:{} | \
     jq '.layers[].digest'

2. Deployment records — query CI/CD system for all deployments since the dependency was introduced:
   - GitHub Actions: Use the Deployments API
   - GitLab: Check deployment tracking in Environments
   - Jenkins: Build history with artifact fingerprints

3. Running environment scan — check all production, staging, and dev environments:
   $ trivy image --scanners vuln <image>:<tag> 2>/dev/null | grep <package-name>

4. SBOM comparison — if SBOMs are generated at build time, compare:
   - SBOM from before the malicious commit (baseline)
   - SBOM from builds after the malicious commit
   Record all artifact digests affected.
```

**Evidence artifact:** Create `pl02-scope-inventory-<date>.json` with:
- List of all affected build IDs
- List of all affected container image digests
- List of all environments where affected artifacts were deployed
- Timestamp range of potential exposure

---

## Phase 2 — Containment (Target: < 4 hours from Phase 1 completion)

### 2.1 Remove the Malicious Dependency

```
Containment actions (in order):

1. Immediately block the package in the organization's private registry proxy:
   - Artifactory: Add to blocked list in the virtual repository configuration
   - Nexus: Add a route rule blocking the package name
   - AWS CodeArtifact: Use package group block policy

2. Open an emergency PR removing the malicious dependency from the manifest:
   - Remove from: requirements.txt / package.json / go.mod / Cargo.toml / pom.xml
   - Remove from: lockfile (requirements.lock / package-lock.json / go.sum)
   - Assign to security team for review; do not wait for normal review cycle

3. Block the pipeline from building with the current manifest until the PR is merged:
   - If using branch protection: add a temporary blocking status check
   - If using CI gates: add a temporary policy rule blocking the package name

4. Preserve evidence before removing:
   $ pip download <package-name>==<version> --no-deps -d ./evidence/
   $ sha256sum ./evidence/<package-name>-<version>.tar.gz > ./evidence/pl02-package-hash.txt
   # Upload to immutable evidence store before taking any other action on the package
```

### 2.2 Isolate Affected Environments

For each environment confirmed in the Phase 1 scope inventory:

```
If environment is PRODUCTION:
  - Do NOT terminate running processes (preserve forensic state)
  - Take a process-level snapshot:
      $ lsof -p <pid> > evidence/pl02-open-files-<pid>.txt
      $ ss -tulnp > evidence/pl02-network-connections.txt
  - Block outbound network traffic from the affected service at the network layer
    (security group rule / firewall policy / network policy)
  - Begin controlled replacement: deploy a known-clean image in parallel; 
    route a subset of traffic to verify before full cutover

If environment is STAGING or DEV:
  - Terminate affected runners/containers immediately
  - Rebuild from a known-clean image (pre-malicious-dependency commit)
  - Preserve build runner disk image for forensic analysis if runner is persistent
```

---

## Phase 3 — Forensic Investigation (Target: complete within 48 hours)

### 3.1 Analyze the Malicious Package

Perform static and behavioral analysis of the preserved package artifact.

```
Static analysis:
  $ python -m zipfile -l ./evidence/<package-name>-<version>.tar.gz
  # Inspect all Python files for:
  # - setup.py install_requires hooks that execute code on installation
  # - __init__.py that executes on import
  # - Any base64-encoded or obfuscated strings

For Node.js packages:
  $ npx arethetypeswrong ./evidence/<package>.tgz   # type safety check
  # Inspect package.json "install" and "postinstall" scripts

For binary or compiled packages:
  $ strings ./evidence/<package-binary> | grep -E "(http|ftp|curl|wget|powershell|exec)"
  $ objdump -d ./evidence/<package-binary> > evidence/pl02-disasm.txt
```

**Key behavioral indicators to document:**

| Indicator | Present? | Evidence Reference |
|-----------|----------|-------------------|
| Network connection on import/install | | |
| File system write outside package directory | | |
| Environment variable enumeration | | |
| Credential file access (`~/.aws`, `~/.ssh`, `.env`) | | |
| Process spawning | | |
| Data encoding / base64 content | | |

### 3.2 Determine Data Exposure

Answer the five supply chain forensic questions:

**Q1 — What did the package execute?**
```
From process snapshot and system logs:
  $ journalctl --since "<install-time>" --until "<containment-time>" -u <service> | \
    grep -E "(import|require|install)" > evidence/pl02-execution-log.txt

Check auditd (if deployed):
  $ ausearch -ts <install-time> -te <containment-time> -k <service-key> > evidence/pl02-audit.txt
```

**Q2 — What data sources were accessible?**
From the scope inventory: list all environment variables, mounted secrets, cloud metadata endpoints, and credential files accessible to the process that loaded the malicious package.

**Q3 — Was any data exfiltrated?**
```
Network flow analysis (requires pre-existing flow logging):
  - CloudWatch VPC Flow Logs (AWS): filter by source=<container-IP>, protocol=TCP, dst_port=443
  - Azure NSG Flow Logs: similar filter
  - On-premise: tcpdump replay from packet capture if available

DNS query logs:
  $ dig +short TXT <package-publisher-domain>   # check for DNS exfiltration indicators
  $ journalctl -u systemd-resolved | grep -i <package-name>
```

**Q4 — What artifacts were produced by affected builds?**
From the Phase 1 scope inventory: enumerate all container images, deployment packages, and published artifacts.

**Q5 — What is the authorization status of each action taken by the malicious package?**
For each confirmed action (network call, file access, credential read):
- Mark: AUTHORIZED (within expected package behavior) / UNAUTHORIZED / UNDETERMINED

---

## Phase 4 — Post-Containment Actions

### 4.1 Mandatory Notification Checklist

| Audience | Condition | Timing |
|----------|-----------|--------|
| Engineering leadership | Always | Within 24 hours of confirmation |
| Legal / Privacy | Any personal data potentially accessed | Within 24 hours |
| Affected customers | Customer data confirmed or suspected exposed | Per applicable regulation (GDPR: 72 hours; CCPA: 45 days; etc.) |
| Cloud provider (AWS/Azure/GCP) | Production credential exposure confirmed | Immediately; rotate credentials first |
| Package registry (npm/PyPI/etc.) | Malicious package confirmed | Immediately |
| CISA / national CERT | Critical infrastructure or widespread impact | Per organizational policy |

### 4.2 Remediation Requirements

Before resuming normal operations:

- [ ] All affected artifact digests removed from production and staging
- [ ] Malicious dependency blocked in all registry proxies
- [ ] Clean rebuild of all affected services verified with SBOM diff
- [ ] All credentials that were accessible to the malicious package rotated
- [ ] AI tool usage policy updated to require independent package verification before importing AI-suggested dependencies
- [ ] SCA allowlist policy enforced in pipeline (block packages not in approved list)
- [ ] Dependency confusion detection enabled in SCA tool (Snyk, Grype, or equivalent)

### 4.3 CHANGELOG Entry

Update `forensics-and-incident-response-framework/CHANGELOG.md` with a new entry for each time this playbook is executed, including: incident date, packages affected, environments compromised, and duration from detection to containment.

---

## Indicators of Compromise Reference

Common slopsquatting indicators to configure in SCA and registry monitoring:

- Package name is a plausible variation of a well-known package (`colourama` vs `colorama`)
- Package was registered within 30 days and has fewer than 100 total downloads
- Package description exactly copies a legitimate package description
- Package publisher email domain was registered within 6 months
- `setup.py` or `pyproject.toml` contains `subprocess.run()` or `os.system()` calls
- Package `__init__.py` makes outbound HTTP requests

---

## Evidence Chain of Custody

All evidence collected during this playbook must follow the procedures in `docs/evidence-chain-of-custody.md`:

1. Hash all files on collection: `sha256sum <file> > <file>.sha256`
2. Upload to write-once evidence store (S3 Object Lock, Immutable Azure Blob, etc.)
3. Record collector name, timestamp, and collection method for each artifact
4. Do not execute or decompress evidence in the investigation environment — use an isolated analysis VM
5. Maintain the custody log in `legal-hold-procedures.md` format if legal proceedings are anticipated

---

## References

- `docs/supply-chain-forensics.md` — Broader supply chain forensics methodology
- `docs/agent-forensics.md` — If the malicious package was introduced by an AI agent (not a human developer)
- `docs/playbooks/ai-supply-chain.md` (PS-01) — AI-assisted supply chain attack investigation (model artifacts, hallucinated packages, broader AI pipeline compromise)
- `ai-devsecops-framework/docs/threat-intelligence.md` — Slopsquatting detection and AI-Assisted Attack Taxonomy
- `software-supply-chain-security-framework/docs/sbom-guide.md` — SBOM-based dependency tracking
- OWASP LLM Top 10 — LLM04: Model Denial of Service, LLM09: Overreliance
