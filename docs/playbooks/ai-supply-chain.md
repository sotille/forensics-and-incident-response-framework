# Playbook PS-01 — AI-Assisted Supply Chain Attack Investigation

> Part of the [Forensics and Incident Response Framework](../../framework.md)

---

## Playbook Metadata

| Field | Value |
|-------|-------|
| Playbook ID | PS-01 |
| Category | Pipeline / Supply Chain |
| Variant | AI-Assisted Attack |
| Severity baseline | HIGH (escalate to CRITICAL if production artifact confirmed affected) |
| Response SLA | Initial triage: 2 hours; Phase 1 evidence preservation: 4 hours; Phase 2 investigation complete: 48 hours |
| Primary owner | Security Incident Response Team |
| Secondary owner | Platform / DevSecOps team |
| License | Apache 2.0 |

---

## Scope

This playbook covers investigations triggered by potential AI-assisted supply chain attacks in the software delivery pipeline. It applies to the following incident types:

- **Slopsquatting**: A package installed by a developer or CI pipeline was suggested by an AI coding assistant; the package name matches an AI hallucination pattern; the package may be malicious.
- **Hallucinated package exploitation**: A hallucinated dependency was registered and installed before detection controls identified it.
- **AI-generated malicious artifact introduction**: A commit, PR, or configuration change introduced by an AI agent or acting on AI suggestion contains malicious or unauthorized code.
- **Model supply chain compromise discovered during pipeline execution**: A model artifact loaded by a CI/CD pipeline component produces anomalous outputs, fails a digest verification check, or is flagged by a model scanner.
- **AI-powered dependency update agent introduces unknown package**: An autonomous dependency update agent (e.g., Dependabot-equivalent with AI enhancement) introduces a package not previously in the approved registry.

**Out of scope for this playbook:**
- General software supply chain incidents not involving AI components (use `supply-chain-forensics.md`)
- Prompt injection incidents where no package or artifact was installed (use the AF-02 playbook in `agent-forensics.md`)
- Model behavior anomalies without a supply chain compromise hypothesis (use `agent-forensics.md`)

---

## Trigger Conditions

Activate this playbook when one or more of the following triggers is observed:

| Trigger | Source | Confidence |
|---------|--------|------------|
| SCA scan detects newly registered package (< 30 days old) matching AI suggestion pattern | CI pipeline SCA output | MEDIUM — investigate |
| PR introduces dependency with publish date < 30 days from a first-time author | Dependency review gate | MEDIUM — investigate |
| Post-install script executes in CI runner for a package with no prior version history | CI runner process telemetry | HIGH — initiate Phase 1 immediately |
| AI-powered dependency update agent introduces a package not in the approved registry | Change management log | HIGH — block and investigate |
| Model artifact digest mismatch detected at load time | Model loading infrastructure | HIGH — halt pipeline, initiate Phase 1 |
| Package flagged in PyPI/npm malware removal notifications matching a package in use | External threat feed | HIGH — initiate Phase 1 immediately |
| Developer reports that an AI tool suggested a package that does not exist, and a new package with that name was subsequently discovered | Developer report | MEDIUM — investigate |

---

## Pre-Investigation Checklist

Before initiating formal investigation phases, confirm the following:

- [ ] Incident ticket created and assigned to primary owner
- [ ] Secondary owner (platform team) notified
- [ ] Severity baseline assessed (default HIGH; escalate if production confirmed affected)
- [ ] Scope of potential exposure determined at a high level: developer machine only, CI runners only, container images, production deployments
- [ ] If model supply chain trigger: AI pipeline component halted to prevent further processing against potentially compromised model
- [ ] If malicious post-install script trigger: affected CI runner quarantined

---

## Phase 1 — Evidence Preservation

Evidence preservation must be completed before any remediation actions are taken. Remediation before preservation will destroy forensic evidence and may violate legal hold requirements.

### 1.1 CI/CD Run Artifact Preservation

Preserve all artifacts from the affected pipeline execution:

- **Workflow run logs**: Full log output from the CI/CD run in which the suspect package was installed or the model artifact loaded. Download and store locally; do not rely on the CI platform's log retention, which may expire.
- **Runner environment snapshot**: If the CI runner is a persistent host (not ephemeral), capture a filesystem snapshot or memory dump before any cleanup occurs. For ephemeral runners (e.g., GitHub Actions ephemeral VMs), the runner is already gone; focus on log artifacts.
- **Artifact manifests**: Build artifacts (container images, compiled binaries, deployment packages) produced by the affected run. Preserve the manifest hash and the artifact itself if storage permits.
- **SBOM at time of install**: If the pipeline generates a Software Bill of Materials (SBOM), preserve the SBOM from the affected run. If no SBOM was generated, generate one retroactively from the build environment if still accessible.
- **Lock files**: Preserve the exact state of `package-lock.json`, `poetry.lock`, `Pipfile.lock`, `go.sum`, or equivalent lock files as committed at the time of the affected run.

### 1.2 Package Registry State Capture

Capture the registry metadata for the suspect package at the time of investigation. Registry metadata can change (packages can be yanked or modified); capture it before reporting to the registry.

For PyPI:
```bash
# Capture full package metadata JSON
curl -s "https://pypi.org/pypi/{PACKAGE_NAME}/json" > evidence/pypi_{PACKAGE_NAME}_metadata.json

# Capture release-specific metadata
curl -s "https://pypi.org/pypi/{PACKAGE_NAME}/{VERSION}/json" > evidence/pypi_{PACKAGE_NAME}_{VERSION}_metadata.json

# Compute hash of captured metadata
sha256sum evidence/pypi_{PACKAGE_NAME}_metadata.json >> evidence/chain_of_custody.txt
```

For npm:
```bash
# Capture package metadata
curl -s "https://registry.npmjs.org/{PACKAGE_NAME}" > evidence/npm_{PACKAGE_NAME}_metadata.json

# Capture specific version
curl -s "https://registry.npmjs.org/{PACKAGE_NAME}/{VERSION}" > evidence/npm_{PACKAGE_NAME}_{VERSION}_metadata.json

sha256sum evidence/npm_{PACKAGE_NAME}_metadata.json >> evidence/chain_of_custody.txt
```

Download the package tarball for static analysis:
```bash
# PyPI
pip download {PACKAGE_NAME}=={VERSION} --no-deps -d evidence/packages/

# npm (download without installing)
npm pack {PACKAGE_NAME}@{VERSION} --dry-run
curl -L $(npm view {PACKAGE_NAME}@{VERSION} dist.tarball) -o evidence/packages/{PACKAGE_NAME}-{VERSION}.tgz

sha256sum evidence/packages/* >> evidence/chain_of_custody.txt
```

### 1.3 Git and PR Metadata Preservation

```bash
# Capture the commit that introduced the dependency
git log --oneline --diff-filter=A -- requirements.txt package.json pyproject.toml | head -20

# Capture full commit metadata
git show {COMMIT_HASH} > evidence/git_commit_{COMMIT_HASH}.txt

# Capture PR metadata via GitHub API
gh api repos/{ORG}/{REPO}/pulls/{PR_NUMBER} > evidence/pr_{PR_NUMBER}_metadata.json
gh api repos/{ORG}/{REPO}/pulls/{PR_NUMBER}/comments > evidence/pr_{PR_NUMBER}_comments.json

sha256sum evidence/git_commit_*.txt evidence/pr_*.json >> evidence/chain_of_custody.txt
```

### 1.4 AI Tool Interaction Log Preservation

If the dependency was introduced following AI coding assistant use, preserve available interaction logs:

- **IDE extension logs**: Copilot, Cursor, and other IDE extensions may write suggestion logs to local disk. Collect before the developer's machine is reimaged.
  - GitHub Copilot: check `~/.copilot/logs/` or IDE-specific log directories
  - Cursor: check `~/.cursor/logs/`
  - Amazon CodeWhisperer: check CloudWatch Logs if enterprise telemetry is enabled
- **CI AI component logs**: If the package was suggested by an AI component in the CI pipeline (AI-powered dependency update agent, AI code reviewer), capture its full log output from the affected run.
- **Chat or inline suggestion history**: Some enterprise AI deployments retain suggestion history accessible via API; query if available.

If interaction logs are unavailable, document this gap: the absence of AI interaction logs is itself a forensic finding that reflects on the organization's forensic readiness posture.

### 1.5 Chain of Custody

All captured evidence must be hashed on capture and recorded in the chain of custody file:

```
# evidence/chain_of_custody.txt format
TIMESTAMP | ANALYST | FILE | SHA256 | NOTES
2026-04-07T14:23:00Z | analyst@org.com | pypi_suspect-package_metadata.json | abc123... | PyPI metadata captured before reporting to registry
```

Store evidence in an append-only evidence store (S3 with Object Lock, Azure Blob with immutability policy, or equivalent). Evidence must not be stored on the same infrastructure that may have been compromised.

---

## Phase 2 — Investigation Steps

### Step 1: Package Lineage Analysis

Establish the full provenance chain for the suspect package: who introduced it, through what mechanism, when, and in what context.

**Questions to answer:**
- What commit introduced the dependency, and who authored that commit?
- Was the dependency introduced manually (developer typed the package name) or through an automated mechanism (AI suggestion accepted, Dependabot PR merged, AI agent action)?
- If introduced manually: can the developer confirm they intended to install this specific package and were not acting on an AI suggestion?
- If introduced via AI suggestion: what tool generated the suggestion, and is a log of the suggestion available?
- Was this package introduced as part of a larger feature change, or as a standalone dependency update?

**Evidence sources:** git log, PR metadata, developer interview, IDE interaction logs.

**Indicators of AI-facilitated introduction:**
- PR was created immediately after a developer's AI tool session
- PR description uses language consistent with AI-generated text (generic, unusually polished, lacks organizational context)
- The package name matches a common AI hallucination pattern (see [threat-intelligence.md](../../../ai-devsecops-framework/docs/threat-intelligence.md) for pattern reference)
- The developer's git history shows the package was not previously used in other projects

### Step 2: Package Registry Forensics

Establish the full publish history and author profile for the suspect package.

**Questions to answer:**
- When was the package first published?
- Who is the publisher? Do they have a history of legitimate package contributions?
- Is there a prior version of this package that predates recent AI assistant adoption, or is this a brand-new package?
- Does the package name closely resemble a legitimate package (typosquatting signal)?
- Is the package listed in any known malware registries or removal notices?

**Registry investigation steps:**

```python
import json, urllib.request, datetime

def investigate_pypi_package(package_name: str):
    url = f"https://pypi.org/pypi/{package_name}/json"
    with urllib.request.urlopen(url) as r:
        data = json.loads(r.read())
    
    info = data['info']
    releases = data['releases']
    
    # Find first release date
    all_dates = [
        upload['upload_time']
        for version_files in releases.values()
        for upload in version_files
        if upload.get('upload_time')
    ]
    first_release = min(all_dates) if all_dates else 'unknown'
    
    print(f"Package: {package_name}")
    print(f"Author: {info.get('author')} <{info.get('author_email')}>")
    print(f"First release: {first_release}")
    print(f"Total versions: {len(releases)}")
    print(f"Home page: {info.get('home_page')}")
    print(f"Summary: {info.get('summary')}")
    print(f"Requires dist: {info.get('requires_dist')}")

investigate_pypi_package("suspect-package-name")
```

**Red flags requiring escalation:**
- Package published within 30 days with no prior version history
- Publisher account created within 30 days
- Package has no homepage, no GitHub repository, or repository was created recently
- Package description is AI-generated boilerplate
- Package has no dependencies or minimal code but a non-trivial post-install script

### Step 3: Package Content Analysis

Perform static analysis of the downloaded package tarball to determine if malicious code is present.

**Post-install script analysis:**

```bash
# Extract the package
tar -xzf evidence/packages/suspect-package.tgz -C /tmp/pkg-analysis/

# Find post-install scripts
find /tmp/pkg-analysis/ -name "setup.py" -o -name "*.pth" | xargs grep -l "subprocess\|os.system\|exec\|eval\|urllib\|socket"

# For npm: check package.json scripts
cat /tmp/pkg-analysis/package/package.json | jq '.scripts'

# Check for encoded payloads
grep -r "base64\|b64decode\|eval(decode\|exec(compile" /tmp/pkg-analysis/
```

**Network behavior analysis (sandboxed environment only):**

If the package is to be executed for dynamic analysis, use an isolated sandbox environment (no network access to production infrastructure):

```bash
# Using strace to capture system calls during install (Linux)
strace -f -e trace=network,file pip install --no-deps suspect-package 2>&1 | tee evidence/strace_output.txt

# Filter for network connection attempts
grep -E "connect|socket|bind" evidence/strace_output.txt
```

**VirusTotal submission:**

Submit the package tarball to VirusTotal and preserve the analysis URL and results in the evidence record. This provides multi-engine malware scanning without executing the package locally.

**Indicators of confirmed malicious package:**
- Post-install script that reads environment variables (credential theft: `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`)
- Post-install script that makes outbound HTTP/HTTPS connections
- Post-install script that reads files from `~/.ssh/`, `~/.aws/`, `.env` files
- Runtime code that exfiltrates data on import
- Obfuscated code (base64-encoded strings decoded and executed)

### Step 4: AI Interaction Reconstruction

If the package was suggested by an AI tool, reconstruct what the AI was asked and what was in its context window at the time of the suggestion.

**Reconstruction approach:**

1. Identify the code context at the time of the AI suggestion: what file was open, what was the developer working on, what imports or dependencies were already present?
2. Reconstruct a query that would likely have produced the hallucinated package name suggestion. Test this query against the same AI tool (if accessible) to confirm the hallucination is reproducible.
3. Determine if the hallucination is consistent across multiple prompting strategies or only specific formulations. Consistent hallucinations indicate the package name is deeply embedded in training data.
4. Check if the hallucination has been documented by other organizations or researchers (search GitHub issues for the AI tool, security forums, and oss-security mailing list).

**Slopsquatting pattern confirmation:**

A slopsquatting attack is confirmed when:
- The AI tool reliably suggests the package name
- The package did not exist in the registry before a recent date
- The package content is malicious or suspicious
- The package name matches a predictable extension of a legitimate package

**Documenting AI tool contribution:**

Even if the package content is not confirmed malicious, document the AI suggestion pattern:
- The hallucinated package name
- The AI tool that produced it
- The code context that triggered it
- Whether the hallucination is reproducible

This documentation is used for responsible disclosure to the AI tool vendor and for updating internal developer guidance.

### Step 5: Blast Radius Assessment

Determine the full scope of exposure: where was the suspect package installed?

**Package install scope matrix:**

| Environment | Check | Evidence Source |
|-------------|-------|-----------------|
| Developer machine(s) | `pip show {package}` or `npm list {package}` on developer workstations | Developer self-report + EDR telemetry |
| CI runners (ephemeral) | Pipeline logs showing install; SBOM from CI run | CI/CD system logs |
| Container images | SBOM diff; `docker run {image} pip show {package}` | Container registry, image SBOMs |
| Deployed services | Service SBOM at deploy time; running process environment | Deployment manifest, APM agent |
| Developer machine via transitive dependency | Lock file analysis for transitive dependency chains | Lock file forensics |

**SBOM-based blast radius:**

```bash
# Generate SBOM from container image (if not already present)
syft {IMAGE}:{TAG} -o spdx-json > evidence/sbom_{IMAGE}_{TAG}.spdx.json

# Check if suspect package appears
jq '.packages[] | select(.name == "suspect-package")' evidence/sbom_{IMAGE}_{TAG}.spdx.json

# Find all builds within the exposure window
# (builds after the commit that introduced the dependency, before containment)
```

**Credential exposure assessment:**

If the package's post-install script reads credential files or environment variables, assess which credentials may have been exfiltrated:

- Developer machine: SSH private keys, `~/.aws/credentials`, `.env` files, browser-stored tokens, IDE tokens (Copilot, etc.)
- CI runner: CI secrets injected as environment variables (`GITHUB_TOKEN`, cloud provider credentials, registry credentials, signing keys)
- Identify all secrets that were in-scope during the affected pipeline execution from the secrets management system

### Step 6: Model Supply Chain Investigation

This step applies when the trigger condition involves a model artifact digest mismatch, anomalous model behavior, or a model supply chain compromise hypothesis.

**Model digest verification:**

```bash
# Compute SHA-256 of the model artifact
sha256sum /path/to/model.safetensors

# Compare against pinned digest in deployment configuration
# If digest does not match approved value: model has been modified
grep "model_digest" config/model-versions.yaml
```

**ModelScan execution:**

```bash
# Run ModelScan on the suspect artifact
modelscan --path /path/to/model.pkl
modelscan --path /path/to/model.safetensors

# Preserve scan output
modelscan --path /path/to/model.pkl --output json > evidence/modelscan_results.json
sha256sum evidence/modelscan_results.json >> evidence/chain_of_custody.txt
```

**Model behavior anomaly investigation:**

If the model is producing anomalous outputs (not a digest mismatch trigger):
- Identify the trigger inputs that produce anomalous outputs
- Test against the last known-good model version to confirm the behavior change is model-specific
- Determine if the anomaly follows a pattern consistent with a backdoor trigger (specific input patterns produce specific anomalous outputs) vs. general model degradation

**Registry access investigation:**

Query the model registry (Hugging Face API, internal model registry) for access logs:
- Who accessed or downloaded the model artifact in the period before the anomaly was detected?
- Were there any modifications to the model file or its metadata?
- Was the model version changed (a new version published under the same version tag)?

---

## Phase 3 — Attribution and Escalation

### Opportunistic Slopsquatting

**Indicators:**
- Package registered shortly (< 30 days) after the AI assistant hallucination pattern for that name became common
- No prior legitimate version of the package exists
- Malicious code in post-install script is generic (credential theft, cryptomining)
- Package registration account is new with no other published packages

**Attribution confidence:** Low to medium (opportunistic actors do not leave attributable infrastructure)

**Escalation path:**
- CISO notification with incident summary
- Dependency management team: review and update approved registry policy
- Report to registry security team (PyPI/npm) with evidence
- If developer credentials were exposed: escalate to credential rotation as CRITICAL priority

### Targeted Attack

**Indicators:**
- Package crafted specifically for the target organization's technology stack
- Package name is not a generic AI hallucination but a specific dependency used in the organization's codebase
- Malicious payload is triggered only under conditions specific to the target environment (reads organization-specific environment variables, targets internal services)
- PR description or commit message is sophisticated and tailored to pass the organization's review patterns

**Attribution confidence:** Low to medium (targeted attacks use infrastructure designed to avoid attribution)

**Escalation path:**
- CISO + Legal notification within 4 hours of targeted attack confirmation
- Activate full incident response team
- Engage external IR support if internal capability is insufficient
- Preserve all evidence under legal hold
- Law enforcement notification if criminal activity is confirmed

### Model Supply Chain Compromise

**Indicators:**
- Model digest mismatch confirmed
- ModelScan detects malicious payload in model artifact
- Model behavior anomaly is reproducible and follows backdoor trigger pattern
- Registry access logs show unauthorized write access to model artifact

**Attribution confidence:** Low (model supply chain attacks are sophisticated and use controlled infrastructure)

**Escalation path:**
- CISO + CTO notification immediately
- Halt all pipelines using the affected model
- Engage model provider security team (if third-party model)
- If internal model: activate insider threat investigation protocol
- Treat all outputs produced by the affected model as potentially compromised

---

## Containment Actions

Execute containment actions in parallel with Phase 2 investigation where time-sensitivity warrants it (do not delay containment waiting for investigation completion if the compromise is confirmed).

### Package Containment

| Action | Command/Method | Owner |
|--------|---------------|-------|
| Block package in private registry mirror | Add to registry blocklist; update mirror policy | Platform team |
| Remove package from lock files | `pip uninstall {package}` + update lock file | Developer / platform team |
| Quarantine affected builds | Mark builds as quarantined in deployment system; do not promote to higher environments | DevOps / Release team |
| Identify and rebuild affected container images | Rebuild from last clean base; rescan before promotion | Platform team |

### Credential Containment (if credential exposure confirmed)

| Credential Type | Rotation Method | Priority |
|----------------|----------------|----------|
| GitHub personal access tokens | Revoke via GitHub security settings | IMMEDIATE |
| CI/CD secrets (GitHub Actions, Jenkins, etc.) | Rotate in secrets manager; update pipeline configuration | IMMEDIATE |
| Cloud provider credentials (AWS, GCP, Azure) | Revoke IAM keys; check CloudTrail/audit logs for unauthorized use | IMMEDIATE within 1 hour |
| SSH private keys | Revoke authorized_keys entries; generate new key pair | HIGH within 4 hours |
| Registry credentials (Docker Hub, npm token, etc.) | Revoke token; check registry for unauthorized publishes | HIGH within 4 hours |

### Model Containment

| Action | Method |
|--------|--------|
| Halt pipeline using affected model | Disable the pipeline job or workflow |
| Roll back to last verified model version | Deploy pinned digest of last known-good version |
| Quarantine all outputs produced by affected model during exposure window | Flag in output storage system for review |

---

## Evidence Report Template

Complete this template at the conclusion of the investigation. The report is the deliverable for executive briefing, legal review, and regulatory notification.

---

**Incident ID:** [PS-01-YYYY-MM-DD-NNN]  
**Report date:** [DATE]  
**Investigating analyst:** [NAME, ROLE]  
**Classification:** [CONFIDENTIAL / RESTRICTED]

### 1. Incident Summary

[2–4 sentence summary: what was detected, when, through what trigger, and what the investigation determined]

### 2. Packages / Artifacts Involved

| Name | Version | Registry | First Published | Malicious Confirmed | Exposure Scope |
|------|---------|----------|-----------------|--------------------|-|
| [package] | [version] | [PyPI/npm/etc] | [date] | [YES/NO/SUSPECTED] | [developer/CI/prod] |

### 3. Affected Builds and Systems

| Build / System | Impact | Remediation Status |
|---------------|--------|--------------------|
| [CI run ID or system name] | [Malicious package installed / model loaded] | [Remediated / In progress / Not started] |

### 4. AI Tool Interaction Evidence

- **AI tool involved:** [Tool name, version if known]
- **Hallucination confirmed:** [YES / NO / INSUFFICIENT EVIDENCE]
- **Interaction logs available:** [YES / NO]
- **Reconstruction summary:** [Brief description of what the AI was asked and what it suggested]

### 5. Timeline

| Time | Event |
|------|-------|
| [T-0] | Package first published in registry |
| [T+X] | Dependency introduced to codebase (commit hash: [HASH]) |
| [T+Y] | Package installed in CI/developer environment |
| [T+Z] | Detection trigger fired |
| [T+Z+N] | Phase 1 evidence preservation complete |
| [T+Z+N] | Containment actions executed |

### 6. Remediation Actions

- [ ] Package blocked in private registry mirror
- [ ] Affected builds quarantined
- [ ] Credentials rotated (list affected credentials)
- [ ] Affected container images rebuilt
- [ ] Lock files updated and clean builds verified
- [ ] Registry security team notified
- [ ] AI tool vendor notified (if hallucination confirmed)
- [ ] Developer guidance updated

### 7. Residual Risk

[Any exposure that cannot be fully remediated; credentials that were potentially exfiltrated but cannot be confirmed as unexploited; production traffic that may have been processed by a compromised model]

### 8. Lessons Learned and Control Gaps

[Control gaps that allowed this incident to occur or to be detected late; recommended improvements]

---

## Cross-References

| Document | Relationship |
|----------|-------------|
| [ai-devsecops-framework/docs/threat-intelligence.md](../../../ai-devsecops-framework/docs/threat-intelligence.md) | Detection indicators, SIEM queries, pre-commit hooks for slopsquatting prevention |
| [ai-devsecops-framework/docs/model-supply-chain.md](../../../ai-devsecops-framework/docs/model-supply-chain.md) | Model artifact security, digest pinning, ModelScan integration |
| [forensics-and-incident-response-framework/docs/supply-chain-forensics.md](../supply-chain-forensics.md) | General supply chain forensics methodology |
| [forensics-and-incident-response-framework/docs/pipeline-forensics.md](../pipeline-forensics.md) | CI/CD pipeline forensics methodology |
| [forensics-and-incident-response-framework/docs/evidence-chain-of-custody.md](../evidence-chain-of-custody.md) | Evidence handling procedures |
