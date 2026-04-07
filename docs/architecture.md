# Forensics Architecture: Evidence Infrastructure for DevSecOps

## Table of Contents

1. [The Evidence Architecture Principle](#the-evidence-architecture-principle)
2. [Evidence Type Inventory](#evidence-type-inventory)
3. [Immutable Log Storage](#immutable-log-storage)
4. [Artifact Integrity Infrastructure](#artifact-integrity-infrastructure)
5. [The Rekor Transparency Log as Forensic Evidence](#the-rekor-transparency-log-as-forensic-evidence)
6. [Kubernetes Audit Logs](#kubernetes-audit-logs)
7. [CI/CD Audit Trail Requirements](#cicd-audit-trail-requirements)
8. [Network Evidence](#network-evidence)
9. [AI and Agent Audit Infrastructure](#ai-and-agent-audit-infrastructure)
10. [Architecture Validation Checklist](#architecture-validation-checklist)

---

## The Evidence Architecture Principle

Forensic evidence in DevSecOps must be collected continuously, automatically, and in tamper-evident storage — because the environment that generated it will no longer exist by the time you know you need the evidence.

The architecture described in this document is not a forensics tool. It is the prerequisite infrastructure that makes forensic investigation possible. Every investigation playbook in this framework depends on one or more of the evidence sources described here. If a source is absent when an incident occurs, the corresponding investigation procedure will either produce incomplete findings or fail entirely.

The design principle is **defense in depth for evidence**: no single evidence source is trusted as the only record. Correlation across multiple independent sources — CI audit log, cloud audit log, artifact provenance, network flow log — provides both completeness and tamper-evidence. An attacker who can modify one source would need to simultaneously modify all correlated sources to cover their tracks.

---

## Evidence Type Inventory

The following table covers all forensically significant evidence types in a DevSecOps environment. Each row identifies whether the evidence source is tamper-evident by default or by configuration, and its relative forensic value.

| Evidence Type | Source | Default Retention | Tamper-Evident? | Forensic Value | Notes |
|---|---|---|---|---|---|
| GitHub Actions workflow run logs | GitHub (CI platform) | 90 days | No by default | High — shows every step executed and its output | Export and protect; GitHub can delete these |
| GitHub audit log | GitHub Enterprise/Org | 180 days | No by default | High — org-level actor actions | Export to SIEM; API paginated |
| GitLab audit events | GitLab instance | Configurable | No by default | High | Requires export to external store |
| Jenkins build log | Jenkins server | Until rotation | No | High | Must be shipped to external log store |
| HashiCorp Vault audit log | Vault server filesystem | Until rotation | No by default | Critical — every secret access | Must be shipped to SIEM immediately; file rotation can destroy evidence |
| AWS CloudTrail | AWS S3 bucket | 90 days default | With Object Lock | Critical — every AWS API call | Enable Object Lock on log bucket; use CloudTrail Lake for querying |
| AWS Secrets Manager access | CloudTrail (embedded) | With CloudTrail | With Object Lock | Critical | Included in CloudTrail; no separate configuration required |
| GCP Audit Logs | GCP Cloud Logging | 30–400 days by tier | With log sink + GCS Object Lock | High | Export to GCS bucket with retention policy |
| Azure Activity Log | Azure Monitor | 90 days | With Immutable Storage | High | Export to Storage Account with WORM policy |
| Kubernetes audit log | API server log file | Until rotation | No | Critical — every API server action | Must be shipped to external SIEM; local storage is not tamper-evident |
| VPC Flow Logs (AWS) | S3 or CloudWatch | Configurable | With Object Lock | High — network-level evidence | Enable on all production VPCs; retain 90 days minimum |
| Container runtime events | Falco / eBPF | In-memory / SIEM | Only in SIEM | High — syscall-level visibility | Must export to SIEM; in-memory ring buffer not persistent |
| OCI image manifest digest | Container registry | With image retention | By digest (content-addressed) | High — tamper-evident by design | Digests are immutable; tags can be overwritten |
| Cosign artifact signatures | Rekor / OCI registry | Rekor: permanent | Yes (Rekor) | Critical — chain of custody | Rekor entries cannot be modified or deleted |
| SLSA provenance attestation | OCI registry (attestation tag) | With image retention | Via Cosign signature | Critical — build lineage | Must be stored alongside the artifact |
| SBOM (CycloneDX / SPDX) | OCI registry (attestation) | With image retention | Via Cosign signature | High — dependency forensics | Sign SBOMs with Cosign; store with artifact |
| Rekor transparency log entry | Rekor (public or private) | Permanent | Yes (append-only, Merkle tree) | Critical | All Cosign signatures produce Rekor entries |
| Git reflog | Git repository server | Configurable | No (can be rewritten) | High — detects force push / history rewrite | Mirror repositories; preserve reflog before remediation |
| Agent tool call log | Application logging / SIEM | Application-defined | Only in SIEM | Critical (for agent investigations) | Must be structured (JSON), immutable on export |
| Agent system prompt version | Git / version control | Git history | Partial (git can be rewritten) | High — establishes agent authorization boundary | Store in append-only store with hash reference |
| Lambda execution logs | CloudWatch Logs | Configurable | No by default | Medium — execution events only | Export to S3 with Object Lock; no disk forensics possible |

---

## Immutable Log Storage

### S3 Object Lock (AWS)

S3 Object Lock in **Compliance mode** is the strongest tamper-evidence guarantee available in AWS. In Compliance mode, no user — including the root account — can delete or modify locked objects before the retention period expires.

```bash
# Create an S3 bucket with Object Lock enabled
# Object Lock can only be enabled at bucket creation time
aws s3api create-bucket \
  --bucket forensics-evidence-${ACCOUNT_ID} \
  --region us-east-1 \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=us-east-1

# Configure a default retention policy: Compliance mode, 2555 days (7 years)
aws s3api put-object-lock-configuration \
  --bucket forensics-evidence-${ACCOUNT_ID} \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 2555
      }
    }
  }'

# Enable versioning (required for Object Lock)
aws s3api put-bucket-versioning \
  --bucket forensics-evidence-${ACCOUNT_ID} \
  --versioning-configuration Status=Enabled

# Verify Object Lock configuration
aws s3api get-object-lock-configuration \
  --bucket forensics-evidence-${ACCOUNT_ID}
```

**CloudTrail configuration to ship to Object Lock bucket:**

```bash
# Create a CloudTrail trail targeting the Object Lock bucket
aws cloudtrail create-trail \
  --name forensics-cloudtrail \
  --s3-bucket-name forensics-evidence-${ACCOUNT_ID} \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation

# Enable the trail
aws cloudtrail start-logging --name forensics-cloudtrail

# Verify log file validation (produces digest files for tamper detection)
aws cloudtrail get-trail-status --name forensics-cloudtrail \
  | jq '{LoggingEnabled, LatestDigestDeliveryTime, LatestDigestDeliveryError}'
```

CloudTrail log file validation creates SHA-256 digest files every hour. These digests chain together, making retroactive modification of any log file detectable even if the S3 bucket were somehow compromised.

### Azure Immutable Blob Storage

```bash
# Create a storage account with immutability support
az storage account create \
  --name forensicsevidence${SUBSCRIPTION_ID:0:8} \
  --resource-group forensics-rg \
  --sku Standard_GRS \
  --kind StorageV2 \
  --allow-blob-public-access false

# Create a container
az storage container create \
  --name audit-logs \
  --account-name forensicsevidence${SUBSCRIPTION_ID:0:8}

# Set an immutability policy (time-based retention, 7 years)
az storage container immutability-policy create \
  --account-name forensicsevidence${SUBSCRIPTION_ID:0:8} \
  --container-name audit-logs \
  --period 2555 \
  --allow-protected-append-writes true

# Lock the policy (after locking, it cannot be shortened or deleted)
az storage container immutability-policy lock \
  --account-name forensicsevidence${SUBSCRIPTION_ID:0:8} \
  --container-name audit-logs \
  --if-match <ETAG_FROM_PREVIOUS_COMMAND>
```

### SIEM Forwarding Architecture

For real-time investigation capability, log forwarding to a SIEM (Splunk, Elastic, OpenSearch, or Panther) should run in parallel with Object Lock storage. The Object Lock bucket is the tamper-evident evidence of record; the SIEM is the investigation interface.

Use a separate IAM role or service principal with **write-only** access to the Object Lock bucket for the log forwarder. The log forwarder must not have delete permissions. The forensics investigator role must have read-only access. No role should have delete permissions on the evidence bucket in Compliance mode (it is technically impossible in Compliance mode, but the IAM policy documents your intent).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LogForwarderWriteOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/log-forwarder"
      },
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::forensics-evidence-${ACCOUNT_ID}/*"
    },
    {
      "Sid": "ForensicsInvestigatorReadOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/forensics-investigator"
      },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::forensics-evidence-${ACCOUNT_ID}",
        "arn:aws:s3:::forensics-evidence-${ACCOUNT_ID}/*"
      ]
    }
  ]
}
```

---

## Artifact Integrity Infrastructure

### Cosign Signatures

Cosign keyless signing (via Sigstore OIDC) produces signatures that are anchored to the OIDC token at the time of signing. The token contains the workflow identity, repository, branch, commit SHA, and the OIDC issuer. This is a forensic record of who built what and when.

```bash
# Sign an image after build (in CI pipeline, OIDC token is available automatically)
cosign sign \
  --yes \
  ${REGISTRY}/${IMAGE}@${DIGEST}

# The signature is uploaded to Rekor automatically

# Verify an image signature and extract the forensic metadata
cosign verify \
  --certificate-identity-regexp "^https://github.com/${ORG}/${REPO}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.[0] | {
    issuer: .optional.Issuer,
    subject: .optional.Subject,
    github_workflow_ref: .optional."github-workflow-ref",
    github_sha: .optional."github-sha",
    build_trigger: .optional."github-event-name",
    run_id: .optional."run-id",
    run_attempt: .optional."run-attempt"
  }'
```

### SLSA Provenance Attestations

SLSA provenance attestations record the full build context as a signed in-toto statement attached to the artifact.

```bash
# Generate SLSA provenance using slsa-github-generator (in GitHub Actions)
# Reference: https://github.com/slsa-framework/slsa-github-generator

# Verify SLSA provenance and extract build lineage
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "^https://github.com/slsa-framework/slsa-github-generator/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.payload | @base64d | fromjson | .predicate | {
    builder_id: .builder.id,
    build_invocation_id: .metadata.buildInvocationID,
    build_started_on: .metadata.buildStartedOn,
    build_finished_on: .metadata.buildFinishedOn,
    source_uri: .materials[0].uri,
    source_digest: .materials[0].digest
  }'
```

### SBOM Generation and Attestation

SBOMs are forensic artifacts. Generated at build time and signed, they record the exact dependency set of an artifact at the moment it was produced. This enables you to answer: "Which of our production artifacts contain the compromised version of this library?"

```bash
# Generate SBOM with syft and attach as Cosign attestation
syft ${REGISTRY}/${IMAGE}@${DIGEST} -o cyclonedx-json > sbom.cdx.json

cosign attest \
  --yes \
  --predicate sbom.cdx.json \
  --type cyclonedx \
  ${REGISTRY}/${IMAGE}@${DIGEST}

# Retrieve SBOM attestation for a given artifact
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/${ORG}/${REPO}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.payload | @base64d | fromjson | .predicate'
```

---

## The Rekor Transparency Log as Forensic Evidence

Rekor is an append-only, cryptographically consistent transparency log for supply chain artifacts. Every Cosign signature operation produces a Rekor entry by default. These entries are permanent, publicly verifiable, and cannot be modified or deleted.

For forensics, Rekor provides:

1. **Non-repudiation**: An artifact's Rekor entry proves it was signed with a specific OIDC identity at a specific time, even if the registry is later compromised or the artifact deleted.
2. **Timeline reconstruction**: Rekor timestamps are anchored to a signed tree root — the time cannot be modified retroactively.
3. **Inclusion proof**: You can verify that a specific artifact was included in the log, and that the log has not been modified since.

```bash
# Look up all Rekor entries for a given artifact digest
rekor-cli search --sha ${ARTIFACT_SHA256}

# Retrieve a specific Rekor entry and verify its inclusion proof
rekor-cli get --uuid ${ENTRY_UUID} --format json \
  | jq '{
    logIndex: .logIndex,
    integratedTime: (.integratedTime | strftime("%Y-%m-%dT%H:%M:%SZ")),
    body: (.body | @base64d | fromjson)
  }'

# Verify the Rekor entry's inclusion proof (cryptographic verification)
rekor-cli verify --uuid ${ENTRY_UUID}

# Search for all entries signed by a specific workflow identity
rekor-cli search \
  --email "https://github.com/${ORG}/${REPO}/.github/workflows/${WORKFLOW}@refs/heads/main"
```

### Running a Private Rekor Instance

For internal artifacts that should not appear in the public log, run a private Rekor instance and configure Cosign to use it:

```bash
# Configure Cosign to use private Rekor
export COSIGN_REKOR_URL=https://rekor.internal.example.com

# All subsequent cosign sign operations will use the private instance
cosign sign --yes ${REGISTRY}/${IMAGE}@${DIGEST}
```

The private Rekor instance must be treated as critical forensic infrastructure: it must run on highly available, access-controlled infrastructure with its own tamper-evident log storage.

---

## Kubernetes Audit Logs

Kubernetes audit logs record every API server request: who made it (user or service account), what they requested (verb, resource, namespace), when, and whether it was allowed or denied. For container forensics, this is the primary evidence source for reconstructing what happened inside a cluster.

### API Server Audit Policy

The default Kubernetes audit policy logs very little. A forensically useful policy must be explicitly configured:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all pod exec, port-forward, and attach (high-value forensic events)
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward", "pods/attach"]

  # Log secret reads at RequestResponse level (captures the secret name accessed)
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
    verbs: ["get", "list", "watch"]

  # Log all changes to RBAC resources
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # Log all changes to workloads (pods, deployments, jobs)
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods", "replicationcontrollers"]
      - group: "apps"
        resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
      - group: "batch"
        resources: ["jobs", "cronjobs"]

  # Log all authentication failures
  - level: Metadata
    omitStages:
      - RequestReceived
    users: ["system:anonymous"]

  # Log everything else at Metadata level (record who did what, not the full body)
  - level: Metadata
    omitStages:
      - RequestReceived
```

### Exporting Audit Logs to External SIEM

The audit log file on the API server node must be exported immediately. Local storage is not tamper-evident, and the log will be lost if the control plane node is terminated.

For EKS, AWS enables audit logging via CloudWatch Logs:

```bash
# Enable audit logging for an EKS cluster
aws eks update-cluster-config \
  --name ${CLUSTER_NAME} \
  --region ${REGION} \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'

# Query EKS audit logs in CloudWatch Insights
aws logs start-query \
  --log-group-name /aws/eks/${CLUSTER_NAME}/cluster \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, @message
    | filter @logStream like /kube-apiserver-audit/
    | filter verb in ["create", "delete", "patch", "update"]
    | filter objectRef.resource in ["pods", "secrets", "serviceaccounts", "clusterrolebindings"]
    | sort @timestamp desc
    | limit 500'
```

---

## CI/CD Audit Trail Requirements

### GitHub Audit Log

GitHub's organization audit log records every action taken by any member or application in the organization. For forensics, the critical events are:

- `workflows.*` — workflow file changes, run triggers
- `protected_branch.*` — branch protection rule changes
- `org.oauth_app_access_approved` — third-party OAuth application authorized
- `repo.access` — repository visibility changes
- `team.add_member` / `org.add_member` — membership changes

```bash
# Export GitHub audit log for a time window (requires GitHub Enterprise or Org admin)
gh api "/orgs/${ORG}/audit-log" \
  --paginate \
  --field phrase="created:${START_DATE}..${END_DATE}" \
  --field per_page=100 \
  > github-audit-log.json

# Filter for workflow-related events
jq 'select(.action | startswith("workflows."))' github-audit-log.json

# Filter for authentication events (compromised account investigation)
jq 'select(.action | startswith("user.login") or startswith("user.failed_login"))' \
  github-audit-log.json

# Filter for branch protection changes (key signal for pipeline compromise)
jq 'select(.action | startswith("protected_branch."))' github-audit-log.json
```

### GitLab Audit Events

```bash
# Export GitLab audit events via API
curl --header "PRIVATE-TOKEN: ${PAT}" \
  "https://gitlab.example.com/api/v4/audit_events?\
created_after=${START_ISO8601}&\
created_before=${END_ISO8601}&\
per_page=100" \
  | jq '[.[] | {
    id: .id,
    author: .author_name,
    entity_type: .entity_type,
    target_type: .target_type,
    action: .details.custom_message,
    timestamp: .created_at,
    ip: .details.ip_address
  }]' > gitlab-audit-events.json
```

### HashiCorp Vault Audit Log

Vault's audit log is the most forensically critical CI/CD artifact — it records every secret access, by which identity, from which IP address, at which time, and whether it succeeded.

```bash
# Enable file audit log (recommended: also enable syslog for redundancy)
vault audit enable file file_path=/var/log/vault/audit.log

# Enable syslog audit device as backup
vault audit enable syslog

# Query vault audit log for secrets accessed during an incident window
# (assumes log is in newline-delimited JSON format)
jq -c 'select(
  .time >= "'"${INCIDENT_START}"'" and
  .time <= "'"${INCIDENT_END}"'" and
  .type == "response" and
  (.request.path | startswith("secret/data/"))
) | {
  time: .time,
  path: .request.path,
  operation: .request.operation,
  client_token_accessor: .auth.accessor,
  entity_id: .auth.entity_id,
  remote_address: .request.remote_address,
  error: .error
}' /var/log/vault/audit.log > vault-secret-access-incident.json
```

---

## Network Evidence

### VPC Flow Logs

VPC Flow Logs capture connection-level metadata: source IP, destination IP, port, protocol, bytes transferred, accept/reject status. They do not capture payload content. For forensics, they establish whether data exfiltration occurred, what external IPs were contacted from a compromised instance, and whether lateral movement occurred within the VPC.

```bash
# Enable VPC Flow Logs to S3 with all traffic fields
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids ${VPC_ID} \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::forensics-evidence-${ACCOUNT_ID}/vpc-flow-logs/ \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${windowstart} ${windowend} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${pkt-srcaddr} ${pkt-dstaddr}'

# Query Flow Logs using CloudWatch Insights (if logs are in CloudWatch)
aws logs start-query \
  --log-group-name /vpc/flow-logs/${VPC_ID} \
  --start-time ${INCIDENT_EPOCH_START} \
  --end-time ${INCIDENT_EPOCH_END} \
  --query-string 'fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, bytes, action
    | filter srcAddr like "${COMPROMISED_INSTANCE_IP}"
    | filter action = "ACCEPT"
    | filter dstAddr not like "10."
    | filter dstAddr not like "172.16."
    | filter dstAddr not like "192.168."
    | stats sum(bytes) as totalBytes by dstAddr
    | sort totalBytes desc'
```

### eBPF Network Observability

For Kubernetes environments, eBPF-based network observability (Cilium Hubble, Falco with network rules) provides pod-level network telemetry that VPC Flow Logs do not capture (VPC Flow Logs see the node IP, not the pod IP).

```bash
# Export Hubble flow logs for a specific pod during an incident window
hubble observe \
  --pod ${NAMESPACE}/${POD_NAME} \
  --since ${INCIDENT_START} \
  --until ${INCIDENT_END} \
  --output json \
  > hubble-pod-flows.json

# Find outbound connections from a pod to unexpected external addresses
jq 'select(
  .flow.l4.TCP != null and
  .flow.traffic_direction == "EGRESS" and
  (.flow.destination.labels | map(startswith("reserved:world")) | any)
) | {
  time: .time,
  source_pod: .flow.source.pod_name,
  dest_ip: .flow.destination.identity,
  dest_port: .flow.l4.TCP.destination_port,
  verdict: .flow.verdict
}' hubble-pod-flows.json
```

---

## AI and Agent Audit Infrastructure

AI agents operating in DevSecOps pipelines require specialized audit infrastructure. Standard application logs capture what the agent produced, but forensics requires knowing what the agent was asked to do, what context it received, and what tools it invoked.

### Required Agent Audit Components

**1. Immutable Tool Call Log**

Every tool invocation by an agent must be logged with sufficient context to reconstruct the agent's reasoning and verify its authorization. The minimum log record structure:

```json
{
  "timestamp": "2024-01-15T14:23:01.452Z",
  "trace_id": "tr-8f2a1c3e",
  "agent_id": "devsecops-triage-agent-v2.1",
  "session_id": "sess-ab3f91c2",
  "tool_name": "github_create_issue",
  "tool_input_hash": "sha256:a3f92b...",
  "tool_input": {
    "repo": "org/service-name",
    "title": "CVE-2024-1234 detected in production",
    "labels": ["security", "automated"]
  },
  "tool_output_hash": "sha256:c91fe2...",
  "tool_output_summary": "Issue #2341 created",
  "authorization_policy_version": "v1.3",
  "authorization_decision": "ALLOW",
  "system_prompt_hash": "sha256:8b3a1f..."
}
```

This log must be exported immediately to the tamper-evident log store. If the agent can write to its own log store, the log is not forensically sound.

**2. System Prompt Versioning**

System prompts define the agent's authorization boundary and behavioral constraints. For forensic purposes, the exact system prompt in effect at the time of any action must be reproducible. Store system prompts in version control and reference them by content hash:

```bash
# Hash the system prompt
PROMPT_HASH=$(sha256sum system-prompt.txt | awk '{print $1}')

# Store in version control with the hash as filename for content-addressing
git add system-prompt.txt
git commit -m "Update system prompt for devsecops-triage-agent: ${PROMPT_HASH}"

# At agent runtime, record the hash in the tool call log
echo "System prompt: sha256:${PROMPT_HASH}" >> agent-session-metadata.json
```

**3. Model Input/Output Pair Logging**

The full conversation — each user/system message and the model's response — must be logged at the session level. This provides the raw evidence for prompt injection investigation.

Log structure (per turn):

```json
{
  "session_id": "sess-ab3f91c2",
  "turn": 3,
  "timestamp": "2024-01-15T14:23:00.101Z",
  "role": "user",
  "content_hash": "sha256:e7f82a...",
  "content_length": 1247,
  "content_source": "github_pr_description",
  "content_source_ref": "https://github.com/org/repo/pull/891"
}
```

Note: Full content must be stored, but should be stored in a restricted-access location due to potential sensitivity. The hash in the main log allows integrity verification without exposing content to investigators who do not require it.

**4. OIDC Token Per Agent Session**

Each agent session should receive a unique OIDC token bound to that session's identity. This enables artifact signing that is attributable to a specific session, not just the agent type. See [agent-forensics.md — Agent Chain of Custody](agent-forensics.md) for the signing procedure.

---

## Architecture Validation Checklist

Use this checklist to validate that your forensics evidence architecture meets the requirements for this framework's investigation playbooks.

### Log Storage

```
[ ] CloudTrail enabled across all regions with multi-region trail
[ ] CloudTrail log validation enabled (SHA-256 digest chaining)
[ ] CloudTrail S3 bucket uses Object Lock in COMPLIANCE mode
[ ] VPC Flow Logs enabled for all production VPCs
[ ] VPC Flow Log destination bucket uses Object Lock
[ ] Kubernetes audit policy deployed with pod/exec and secret-access logging
[ ] Kubernetes audit logs shipped to external SIEM in real time
[ ] Vault audit log enabled (file + syslog) and shipped to SIEM
[ ] CI platform audit logs exported to SIEM (GitHub/GitLab/Jenkins)
[ ] SIEM retention policy: minimum 1 year, 7 years for regulated data
```

### Artifact Integrity

```
[ ] Cosign keyless signing configured for all production artifact builds
[ ] SLSA provenance level 2+ attestation generated for all production builds
[ ] SBOM generated (syft/cyclonedx) and attached as signed attestation
[ ] Cosign verification enforced at deployment promotion gates
[ ] Rekor instance accessible (public or private) from investigation environment
```

### Agent Audit (if AI agents are in use)

```
[ ] Structured tool call logging deployed to tamper-evident store
[ ] System prompts versioned in git and referenced by hash in tool call logs
[ ] Model input/output pairs logged per session
[ ] Agent OIDC identity issued per session (not shared per agent type)
[ ] Tool authorization policy documented as code and versioned
```
