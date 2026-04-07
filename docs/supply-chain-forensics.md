# Supply Chain Forensics

## Table of Contents

1. [Supply Chain Forensics Overview](#supply-chain-forensics-overview)
2. [SBOM as Forensic Evidence](#sbom-as-forensic-evidence)
3. [SLSA Provenance for Build Lineage Reconstruction](#slsa-provenance-for-build-lineage-reconstruction)
4. [Cosign and Rekor: Chain of Custody for Artifacts](#cosign-and-rekor-chain-of-custody-for-artifacts)
5. [Dependency Confusion Forensics](#dependency-confusion-forensics)
6. [The Forensic SBOM Diff](#the-forensic-sbom-diff)
7. [VEX Statements as Forensic Evidence](#vex-statements-as-forensic-evidence)
8. [Registry Audit Logs](#registry-audit-logs)
9. [Cross-Reference: Supply Chain IR](#cross-reference-supply-chain-ir)

---

## Supply Chain Forensics Overview

Supply chain attacks target the build and distribution process rather than the running application. This makes them fundamentally different from runtime attacks: by the time a supply chain attack is detected, the malicious artifact has often already been deployed and running for weeks or months.

The key forensic question in a supply chain incident is not "what is happening now" but "what happened, when, which artifacts were affected, and which production environments are still running compromised artifacts."

The forensic tools most relevant to supply chain investigation are the same tools used for supply chain security in normal operations — SBOM, SLSA provenance, Cosign signatures, and Rekor log entries. These tools produce cryptographic evidence of artifact provenance that exists independent of the registry or the build system. An attacker who compromises the registry cannot retroactively modify a Rekor log entry or a Cosign signature.

**Prerequisite**: Supply chain forensics investigations require that Cosign signing, SLSA provenance, and SBOM generation were in place before the incident. If they were not, see the [Forensic Investigation Without Signing](#forensic-investigation-without-signing) section.

---

## SBOM as Forensic Evidence

An SBOM generated at build time and signed with Cosign is a timestamped, tamper-evident manifest of every component in an artifact. For supply chain forensics, SBOMs answer the question: "Which of our artifacts contained the compromised package, and which environments are currently running those artifacts?"

### Query Which Artifacts Contain a Compromised Dependency

```bash
# Scenario: log4j-core version 2.14.1 is discovered to be compromised
# Find all production images that contain this dependency

COMPROMISED_PACKAGE="log4j-core"
COMPROMISED_VERSION="2.14.1"

# For each production image, retrieve its SBOM and check for the package
# (assumes SBOMs are stored as Cosign attestations on each image)

# Get list of production images from Kubernetes
PRODUCTION_IMAGES=$(kubectl get pods -A -o json \
  | jq -r '.items[].spec.containers[].image' \
  | sort -u)

echo "Scanning production images for ${COMPROMISED_PACKAGE}:${COMPROMISED_VERSION}..."
echo "" > affected-images.txt

while IFS= read -r IMAGE; do
  # Retrieve SBOM attestation
  SBOM=$(cosign verify-attestation \
    --type cyclonedx \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer ".*" \
    "${IMAGE}" 2>/dev/null \
    | jq -r '.payload | @base64d | fromjson | .predicate')

  if [ -z "${SBOM}" ]; then
    echo "WARNING: No SBOM found for ${IMAGE}" >> sbom-gaps.txt
    continue
  fi

  # Check if the compromised package is present
  FOUND=$(echo "${SBOM}" | jq --arg pkg "${COMPROMISED_PACKAGE}" --arg ver "${COMPROMISED_VERSION}" \
    '.components[] | select(.name == $pkg and .version == $ver) | .name')

  if [ -n "${FOUND}" ]; then
    echo "${IMAGE}" >> affected-images.txt
    echo "AFFECTED: ${IMAGE}"
  fi
done <<< "${PRODUCTION_IMAGES}"

echo ""
echo "Affected images: $(wc -l < affected-images.txt)"
echo "Images without SBOM: $(wc -l < sbom-gaps.txt)"
```

### Query All Historical Artifacts Containing a Compromised Dependency

```bash
# For a broader investigation: query all artifact versions in the registry
# that may have contained the compromised package

# AWS ECR: get all image digests for a repository
REPO_NAME="${ORG}/${SERVICE_NAME}"

aws ecr describe-images \
  --repository-name ${REPO_NAME} \
  --query 'imageDetails[*].{digest: imageDigest, pushed: imagePushedAt, tags: imageTags}' \
  --output json \
  | jq --arg start "${COMPROMISE_WINDOW_START}" --arg end "${COMPROMISE_WINDOW_END}" \
  '[.[] | select(.pushed >= $start and .pushed <= $end)]' \
  > images-in-compromise-window.json

# For each image in the window, check the SBOM
jq -r '.[].digest' images-in-compromise-window.json | while read DIGEST; do
  cosign verify-attestation \
    --type cyclonedx \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer ".*" \
    "${REGISTRY}/${REPO_NAME}@${DIGEST}" 2>/dev/null \
    | jq --arg pkg "${COMPROMISED_PACKAGE}" --arg ver "${COMPROMISED_VERSION}" --arg digest "${DIGEST}" \
    'select(.payload != null) |
     .payload | @base64d | fromjson | .predicate |
     .components[] | select(.name == $pkg and .version == $ver) |
     {affected_digest: $digest, package: .name, version: .version}'
done
```

### Using grype Against an SBOM

```bash
# Scan an SBOM for vulnerabilities (useful during investigation to understand exposure)
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > /tmp/sbom-for-analysis.json

grype sbom:/tmp/sbom-for-analysis.json \
  --output json \
  | jq '.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High") | {
    vulnerability: .vulnerability.id,
    severity: .vulnerability.severity,
    package: .artifact.name,
    version: .artifact.version,
    fix_versions: .vulnerability.fix.versions
  }'
```

---

## SLSA Provenance for Build Lineage Reconstruction

SLSA provenance attestations record the complete build context for an artifact. For forensic investigation, provenance allows you to:
1. Determine which source commit produced a given artifact
2. Verify that the build was performed by the expected pipeline, not by an attacker
3. Reconstruct the build invocation, including which secrets and tools were available

### Extract Build Lineage from Provenance

```bash
# Retrieve and parse SLSA provenance for a production artifact
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "^https://github.com/${ORG}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.payload | @base64d | fromjson | .predicate | {
      builder_id: .builder.id,
      build_invocation_id: .metadata.buildInvocationID,
      build_started: .metadata.buildStartedOn,
      build_finished: .metadata.buildFinishedOn,
      reproducible: .metadata.completeness.parameters,
      source_uri: .materials[0].uri,
      source_commit: .materials[0].digest.sha1,
      workflow_ref: .buildConfig.steps[0].environment.GITHUB_WORKFLOW_REF,
      triggered_by: .buildConfig.steps[0].environment.GITHUB_EVENT_NAME
    }'
```

### Verify Source Commit Integrity

The provenance records the source commit SHA that was used as build input. Verify this commit:

```bash
# Extract the source commit SHA from the provenance
SOURCE_COMMIT=$(cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq -r '.payload | @base64d | fromjson | .predicate.materials[0].digest.sha1')

echo "Artifact was built from commit: ${SOURCE_COMMIT}"

# Verify this commit exists in the repository and was not force-pushed away
git log --all --oneline | grep ${SOURCE_COMMIT}

# If the commit is not found, it may have been force-pushed or the repository history rewritten
# Check the reflog
git reflog --all | grep ${SOURCE_COMMIT}

# Retrieve the full commit details
git show ${SOURCE_COMMIT} -- .github/workflows/ > workflow-at-build-time.txt

# Check who signed or approved this commit
gh api /repos/${ORG}/${REPO}/commits/${SOURCE_COMMIT}/check-runs \
  | jq '.check_runs[] | {name, conclusion, completed_at}' > commit-check-runs.json

# Verify the commit was part of a reviewed PR
gh api /repos/${ORG}/${REPO}/commits/${SOURCE_COMMIT}/pulls \
  | jq '.[] | {number: .number, merged_by: .merged_by.login, merged_at: .merged_at, reviewers: [.requested_reviewers[].login]}' \
  > commit-pr-history.json
```

### Detect Artifact Produced Outside Normal Pipeline

If an artifact's provenance indicates it was built by a different builder than expected, or if no valid provenance exists, investigate:

```bash
# Check the builder ID in the provenance against expected values
BUILDER_ID=$(cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq -r '.payload | @base64d | fromjson | .predicate.builder.id')

echo "Artifact builder: ${BUILDER_ID}"

# Compare against known good builders (document these for your environment)
EXPECTED_BUILDERS=(
  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
  "https://github.com/${ORG}/.github-workflows/.github/workflows/build.yml@refs/heads/main"
)

BUILDER_KNOWN=false
for EXPECTED in "${EXPECTED_BUILDERS[@]}"; do
  if [ "${BUILDER_ID}" == "${EXPECTED}" ]; then
    BUILDER_KNOWN=true
    break
  fi
done

if [ "${BUILDER_KNOWN}" == "false" ]; then
  echo "WARNING: Artifact was built by an unknown builder: ${BUILDER_ID}"
  echo "This may indicate a compromised build or an unauthorized build"
fi
```

---

## Cosign and Rekor: Chain of Custody for Artifacts

### Extract Certificate Metadata from a Cosign Signature

A Cosign keyless signature contains a Fulcio certificate with the signer's OIDC identity. This certificate is the chain-of-custody record for who signed the artifact.

```bash
# Extract the full certificate from the signature
cosign verify \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  2>&1 | jq '.[0] | {
    issuer: .optional.Issuer,
    subject: .optional.Subject,
    build_signer_uri: .optional."build-signer-uri",
    build_signer_digest: .optional."build-signer-digest",
    runner_environment: .optional."runner-environment",
    github_repo: .optional."github-repo-id",
    github_workflow_ref: .optional."github-workflow-ref",
    github_sha: .optional."github-sha",
    github_repository: .optional."github-repository",
    event_name: .optional."github-event-name",
    run_id: .optional."run-id",
    run_attempt: .optional."run-attempt"
  }'
```

### Retrieve and Verify Rekor Log Entry

```bash
# Find the Rekor entry for an artifact
# Method 1: Search by artifact digest
ARTIFACT_DIGEST=$(crane digest ${REGISTRY}/${IMAGE}@${DIGEST})
rekor-cli search --sha ${ARTIFACT_DIGEST}

# Method 2: Retrieve from Cosign bundle (stored in the OCI registry)
cosign download signature ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.Bundle.Payload | {logIndex: .logIndex, integratedTime: (.integratedTime | todate), body: (.body | @base64d | fromjson)}'

# Method 3: Direct UUID lookup if known
rekor-cli get --uuid ${REKOR_UUID} --format json \
  | jq '{
    log_index: .logIndex,
    integrated_time: (.integratedTime | strftime("%Y-%m-%dT%H:%M:%SZ")),
    log_id: .logID,
    body: (.body | @base64d | fromjson | {
      apiVersion,
      kind,
      spec: .spec | {
        signature: .signature.publicKey,
        data_hash: .data.hash
      }
    })
  }'

# Verify the Rekor entry inclusion proof (confirms the entry is in the log and unmodified)
rekor-cli verify --uuid ${REKOR_UUID}
```

---

## Dependency Confusion Forensics

Dependency confusion attacks exploit misconfigured package managers that pull internal package names from public registries when the internal registry does not have a version with a higher version number. For forensic investigation, the goal is to determine whether any build consumed a malicious public package that shares a name with an internal package.

### Identify Suspicious Dependencies in SBOM

```bash
# Extract all dependencies from the SBOM
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq -r '.payload | @base64d | fromjson | .predicate.components[] |
    "\(.name) \(.version) \(.purl)"' \
  > sbom-components.txt

# For each internal package name, check whether the SBOM component
# was sourced from an internal or external registry
# PURL (Package URL) format: pkg:npm/%40myorg/internal-lib@1.0.0
# If the PURL does not reference the internal registry, it came from a public one

# Flag components that are internal package names but sourced externally
grep -E "^myorg-|^@myorg/" sbom-components.txt | grep -v "internal.registry.example.com"
```

### Verify Package Origin

```bash
# For a specific package, determine where it was downloaded from
# Check the build log for the pip/npm/go install step

# GitHub Actions: retrieve the specific job log
gh run view ${RUN_ID} --repo ${ORG}/${REPO} --log \
  | grep -E "(pip install|npm install|go get)" \
  > package-install-log.txt

# For npm: check for a lockfile in the SBOM source commit
git show ${SOURCE_COMMIT}:package-lock.json \
  | jq '.packages["${PACKAGE_NAME}"] | {version, resolved, integrity}'

# The 'resolved' field shows where the package was downloaded from:
# - "https://registry.npmjs.org/..." = public npm registry
# - "https://internal.registry.example.com/..." = internal registry

# For Python/pip: check the pyproject.toml or requirements.txt
git show ${SOURCE_COMMIT}:requirements.txt | grep "${PACKAGE_NAME}"
git show ${SOURCE_COMMIT}:pyproject.toml | grep -A5 "\[tool.poetry.source\]"
```

---

## The Forensic SBOM Diff

Comparing SBOMs from two versions of an artifact — before and after a suspected compromise — reveals what changed in the dependency set. This is the supply chain equivalent of a git diff.

```bash
# Retrieve SBOMs for two artifact versions
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST_BEFORE} \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > sbom-before.json

cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST_AFTER} \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > sbom-after.json

# Generate dependency diff: packages added between versions
echo "=== Packages ADDED in post-incident version ==="
diff \
  <(jq -r '.components[] | "\(.name)@\(.version)"' sbom-before.json | sort) \
  <(jq -r '.components[] | "\(.name)@\(.version)"' sbom-after.json | sort) \
  | grep "^>" | sed 's/^> //'

echo ""
echo "=== Packages REMOVED in post-incident version ==="
diff \
  <(jq -r '.components[] | "\(.name)@\(.version)"' sbom-before.json | sort) \
  <(jq -r '.components[] | "\(.name)@\(.version)"' sbom-after.json | sort) \
  | grep "^<" | sed 's/^< //'

echo ""
echo "=== Version CHANGES (same package, different version) ==="
join \
  <(jq -r '.components[] | "\(.name) \(.version)"' sbom-before.json | sort -k1) \
  <(jq -r '.components[] | "\(.name) \(.version)"' sbom-after.json | sort -k1) \
  | awk '$2 != $3 {print "CHANGED:", $1, $2, "->", $3}'
```

---

## VEX Statements as Forensic Evidence

VEX (Vulnerability Exploitability eXchange) statements document that a known vulnerability in a component does not affect a specific product — because the vulnerable code path is not called, the vulnerable feature is disabled, or the vulnerability has been mitigated by another control.

In a forensic context, VEX statements serve as evidence of the organization's documented security assessment at a specific point in time. If a vulnerability was later exploited and the organization had issued a VEX statement claiming non-exploitability, the VEX statement is forensic evidence of either the assessment methodology at the time or a failure to update the VEX statement when conditions changed.

```bash
# Generate a VEX document for an artifact and attach as Cosign attestation
# (using OpenVEX format)

cat > vex-statement.json << EOF
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://example.com/vex/${ARTIFACT_DIGEST}",
  "author": "Security Engineering Team",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "1",
  "statements": [
    {
      "vulnerability": {"@id": "https://osv.dev/vulnerability/${CVE_ID}"},
      "products": [{"@id": "${REGISTRY}/${IMAGE}@${ARTIFACT_DIGEST}"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable function is in a code path that is not reachable from the application's entry points based on static analysis."
    }
  ]
}
EOF

cosign attest --yes \
  --predicate vex-statement.json \
  --type openvex \
  ${REGISTRY}/${IMAGE}@${ARTIFACT_DIGEST}

# Retrieve VEX attestation during investigation
cosign verify-attestation \
  --type openvex \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${ARTIFACT_DIGEST} \
  | jq '.payload | @base64d | fromjson | .predicate | {
    author, timestamp, version,
    statements: [.statements[] | {
      cve: .vulnerability."@id",
      product: .products[]."@id",
      status,
      justification,
      impact: .impact_statement
    }]
  }'
```

---

## Registry Audit Logs

Registry audit logs record who pushed what image, when, and from where. This is the lowest-level supply chain evidence — an artifact's registry push event is the moment it entered the distribution chain.

### AWS ECR Audit Logs

```bash
# Find all ECR push events in the incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time ${INCIDENT_START} \
  --end-time ${INCIDENT_END} \
  --output json \
  | jq '[.Events[] | .CloudTrailEvent | fromjson | {
    time: .eventTime,
    actor: .userIdentity.arn,
    source_ip: .sourceIPAddress,
    user_agent: .userAgent,
    repository: .requestParameters.repositoryName,
    image_tag: .requestParameters.imageTag,
    image_digest: .responseElements.image.imageId.imageDigest
  }]' > ecr-push-events.json

# Find pushes by non-CI identities (potential unauthorized push)
# Document the expected CI role ARN pattern for your environment
jq '[.[] | select(.actor | contains("ci-pipeline") | not)]' \
  ecr-push-events.json \
  > suspicious-ecr-pushes.json

# Correlate each push with a CI pipeline run
# An artifact push that has no corresponding pipeline run in the same time window is suspicious
jq -r '.[] | "\(.time) \(.image_digest)"' ecr-push-events.json | while read TIME DIGEST; do
  # Check for a GitHub Actions run that produced this artifact
  RUNS=$(gh api "/repos/${ORG}/${REPO}/actions/runs" \
    --field created="$(date -d "${TIME}" -u "+%Y-%m-%dT%H:%M:%SZ")" \
    | jq '.workflow_runs | length')
  echo "${TIME}: ${DIGEST} — ${RUNS} pipeline runs in same minute"
done
```

### Docker Hub / GCR / GHCR Audit Logs

```bash
# GitHub Container Registry (GHCR): audit via GitHub audit log
gh api "/orgs/${ORG}/audit-log" \
  --field phrase="action:package.version_published" \
  --field created=">=${INCIDENT_START}" \
  | jq '[.[] | {
    timestamp: .created_at,
    actor: .actor,
    action: .action,
    package_name: .name,
    package_version: .package_version
  }]' > ghcr-push-audit.json

# Google Artifact Registry: via GCP Audit Logs
gcloud logging read \
  'protoPayload.serviceName="artifactregistry.googleapis.com"
   AND protoPayload.methodName="google.devtools.artifactregistry.v1.ArtifactRegistry.UpdateTag"' \
  --format=json \
  --freshness=30d \
  > gar-push-events.json
```

---

## Forensic Investigation Without Signing

If Cosign signing and SLSA provenance were not in place when the incident occurred, the investigation is significantly constrained. The following compensating procedures provide partial coverage:

```bash
# Without Cosign: use registry manifest digest as artifact identifier
# Registry manifests are content-addressed and cannot be retroactively modified
# (but they can be retagged — the manifest remains, the tag may be overwritten)

# Get the manifest and compute its digest
docker manifest inspect ${REGISTRY}/${IMAGE}:${TAG} \
  | sha256sum > artifact-manifest.sha256

# Cross-reference with build log: does the CI pipeline log show the same digest?
# This establishes that the artifact in the registry matches what the pipeline produced

# Without SLSA provenance: reconstruct build lineage from CI platform audit log
gh api "/repos/${ORG}/${REPO}/actions/runs/${RUN_ID}" \
  | jq '{
    run_id: .id,
    workflow: .name,
    head_sha: .head_sha,
    head_branch: .head_branch,
    event: .event,
    triggered_by: .triggering_actor.login,
    status: .status,
    conclusion: .conclusion,
    created_at: .created_at
  }' > ci-run-reconstruction.json

echo "LIMITATION: Without SLSA provenance, the link between CI run and artifact digest
     is established by log correlation, not cryptographic proof. This is weaker evidence."
```

---

## Cross-Reference: Supply Chain IR

- [software-supply-chain-security-framework/docs/incident-response-playbook.md](../../software-supply-chain-security-framework/docs/incident-response-playbook.md) — Supply chain incident response
- [architecture.md — Artifact Integrity Infrastructure](architecture.md)
- [pipeline-forensics.md — PL-02: Compromised Build Artifact](pipeline-forensics.md)
- [evidence-chain-of-custody.md](evidence-chain-of-custody.md)
