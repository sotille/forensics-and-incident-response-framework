# Building Forensics Capability: Phased Implementation Guide

## Table of Contents

1. [Implementation Philosophy](#implementation-philosophy)
2. [Phase 1 (0–30 Days): Enable and Protect](#phase-1-030-days-enable-and-protect)
3. [Phase 2 (30–90 Days): Artifact Integrity](#phase-2-3090-days-artifact-integrity)
4. [Phase 3 (90–180 Days): Integration and Automation](#phase-3-90180-days-integration-and-automation)
5. [Phase 4 (180+ Days): Agent Forensics and Continuous Evidence](#phase-4-180-days-agent-forensics-and-continuous-evidence)
6. [Implementation Across Cloud Providers](#implementation-across-cloud-providers)

---

## Implementation Philosophy

Forensics capability cannot be built in response to an incident — it must be operational before one occurs. This creates a planning challenge: it is difficult to justify investment in forensics infrastructure that produces no immediate operational benefit.

The approach taken in this guide is to sequence implementation so that each phase delivers independent value (improved observability, regulatory compliance, supply chain security) while simultaneously building forensics capability. An organization completing Phase 1 has not only improved its forensics readiness — it has also enabled the logging and monitoring infrastructure that supports general security operations.

**Phases are independent but sequential.** Phase 2 can begin before Phase 1 is fully complete, but Phase 2 procedures that depend on Phase 1 infrastructure (Cosign signing that uses Vault for key storage) will fail if Phase 1 is incomplete. The acceptance criteria at the end of each phase are the gateway criteria for the next phase.

---

## Phase 1 (0–30 Days): Enable and Protect

**Objective**: Enable all required evidence sources and configure tamper-evident storage. By the end of Phase 1, you have the evidence that will make Phase 3's SIEM integration and Phase 5's investigations possible.

**Starting State Assumption**: Evidence sources may or may not be enabled; no systematic protection of log storage; no artifact signing.

### Actions

#### Week 1: Cloud Audit Logging

**AWS**:
```bash
# 1. Enable CloudTrail in all regions
aws cloudtrail create-trail \
  --name org-forensics-trail \
  --s3-bucket-name ${FORENSICS_BUCKET} \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name org-forensics-trail

# 2. Enable CloudTrail for all accounts in the organization (from management account)
aws cloudtrail create-trail \
  --name org-forensics-trail \
  --s3-bucket-name ${FORENSICS_BUCKET} \
  --is-organization-trail \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation

# 3. Verify log delivery
aws cloudtrail get-trail-status --name org-forensics-trail \
  | jq '{IsLogging, LatestDeliveryTime, LatestDeliveryError}'
```

**Enable VPC Flow Logs for all production VPCs**:
```bash
# Get all VPC IDs in region
VPC_IDS=$(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text)

for VPC_ID in ${VPC_IDS}; do
  aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids ${VPC_ID} \
    --traffic-type ALL \
    --log-destination-type s3 \
    --log-destination "arn:aws:s3:::${FORENSICS_BUCKET}/vpc-flow-logs/${VPC_ID}/"
  echo "Flow logs enabled for ${VPC_ID}"
done
```

#### Week 1: Configure Tamper-Evident Log Storage

Create the evidence bucket with Object Lock (this must be done at bucket creation):

```bash
# Create evidence bucket with Object Lock — cannot be added to existing bucket
aws s3api create-bucket \
  --bucket ${FORENSICS_BUCKET} \
  --region ${REGION} \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=${REGION}

# Enable versioning (required for Object Lock)
aws s3api put-bucket-versioning \
  --bucket ${FORENSICS_BUCKET} \
  --versioning-configuration Status=Enabled

# Set compliance-mode retention (2555 days = 7 years)
aws s3api put-object-lock-configuration \
  --bucket ${FORENSICS_BUCKET} \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 2555
      }
    }
  }'

# Block all public access
aws s3api put-public-access-block \
  --bucket ${FORENSICS_BUCKET} \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Apply bucket policy restricting access (replace role ARNs with your values)
aws s3api put-bucket-policy \
  --bucket ${FORENSICS_BUCKET} \
  --policy file://evidence-bucket-policy.json
```

**Acceptance Criteria — Week 1**:
- [ ] CloudTrail delivering logs to Object Lock bucket in all regions
- [ ] VPC Flow Logs enabled for all production VPCs, delivering to Object Lock bucket
- [ ] No entity (including root) can delete logs before retention period expires
- [ ] Bucket policy documented and reviewed by at least two team members

#### Week 2: CI/CD Audit Logs

Export CI platform audit logs to the tamper-evident store. The exact mechanism depends on your platform.

**GitHub Actions — automated audit log export**:

```yaml
# .github/workflows/audit-log-export.yml
name: Export GitHub Audit Log
on:
  schedule:
    - cron: '0 * * * *'  # Hourly

jobs:
  export:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Assume forensics writer role
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${ACCOUNT_ID}:role/audit-log-writer
          aws-region: us-east-1

      - name: Export GitHub audit log
        env:
          GH_TOKEN: ${{ secrets.AUDIT_LOG_PAT }}
        run: |
          SINCE=$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)
          gh api "/orgs/${GITHUB_ORG}/audit-log" \
            --paginate \
            --field created=">${SINCE}" \
            --field per_page=100 \
            > audit-log-$(date +%Y%m%d%H).json

          aws s3 cp audit-log-$(date +%Y%m%d%H).json \
            s3://${FORENSICS_BUCKET}/github-audit-log/$(date +%Y/%m/%d)/
```

**Vault audit log shipping**:

```bash
# Configure Vault audit log to syslog (in addition to file)
vault audit enable syslog

# Configure rsyslog to forward to SIEM
cat >> /etc/rsyslog.d/vault-audit.conf << 'EOF'
# Forward Vault audit events to SIEM
if $programname == 'vault' then @@siem.internal.example.com:514
EOF

systemctl restart rsyslog

# Verify audit logging is working
vault audit list
```

**Acceptance Criteria — Week 2**:
- [ ] GitHub/GitLab organization audit log exported to Object Lock bucket hourly
- [ ] Vault audit log enabled (file and syslog), shipped to SIEM
- [ ] Jenkins/CI build logs exported to external store on pipeline completion
- [ ] Secret access events (AWS Secrets Manager, Azure Key Vault) confirmed in audit trail

#### Week 3: Kubernetes Audit Logs

```bash
# For self-managed clusters: update kube-apiserver manifest
# /etc/kubernetes/manifests/kube-apiserver.yaml — add:
# --audit-policy-file=/etc/kubernetes/audit-policy.yaml
# --audit-log-path=/var/log/kubernetes/audit/audit.log
# --audit-log-maxage=7
# --audit-log-maxbackup=10
# --audit-log-maxsize=100

# Deploy the audit policy (see architecture.md for full policy)
cp docs/audit-policy.yaml /etc/kubernetes/audit-policy.yaml

# Verify audit logging is working
tail -f /var/log/kubernetes/audit/audit.log | jq '.verb, .objectRef.resource'

# Configure Fluentd or Fluent Bit to ship audit logs to SIEM
cat > /etc/fluent-bit/conf.d/k8s-audit.conf << 'EOF'
[INPUT]
    Name              tail
    Path              /var/log/kubernetes/audit/audit.log
    Parser            json
    Tag               k8s.audit
    DB                /var/log/fluentbit_k8s_audit.db
    Mem_Buf_Limit     5MB

[OUTPUT]
    Name              http
    Match             k8s.audit
    Host              siem.internal.example.com
    Port              8088
    URI               /services/collector/event
    Format            json
    Header            Authorization Splunk ${HEC_TOKEN}
EOF
```

#### Week 4: Documentation and Inventory

**Document the evidence inventory** — what is being collected, where it is stored, and the retention period.

Use this template for each evidence source:

```
Evidence Source: AWS CloudTrail
Storage Location: s3://forensics-evidence-${ACCOUNT_ID}/cloudtrail/
Retention: 2555 days (COMPLIANCE mode Object Lock)
Tamper-Evident: Yes (Object Lock + digest chain)
Accessible To: forensics-investigator role (read-only)
Written By: cloudtrail service principal
Gap/Limitation: Data events for S3 not enabled by default (enables separately if needed)
Date Enabled: 2024-01-15
Responsible Owner: Security Engineering
```

**Acceptance Criteria — Phase 1 Complete**:
- [ ] All cloud audit logs flowing to tamper-evident storage
- [ ] VPC Flow Logs enabled for all production VPCs
- [ ] CI/CD audit logs exported to tamper-evident storage
- [ ] Vault audit log enabled and shipped to SIEM
- [ ] Kubernetes audit logs shipped to SIEM (if Kubernetes is in use)
- [ ] Evidence inventory document complete and reviewed
- [ ] No entity can delete or modify evidence in the Object Lock bucket

---

## Phase 2 (30–90 Days): Artifact Integrity

**Objective**: Deploy artifact signing (Cosign), SLSA provenance generation, and SBOM generation for all production artifact builds. By the end of Phase 2, every production artifact has a cryptographically verifiable chain of custody.

**Starting State Assumption**: Phase 1 complete; CI/CD pipelines are the build source for production artifacts.

### Actions

#### Month 2: Cosign Signing in CI/CD

Integrate Cosign keyless signing into every CI pipeline that produces production artifacts.

**GitHub Actions integration**:

```yaml
# Add to existing build workflow after the image build step
- name: Sign container image with Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign the image
  env:
    COSIGN_EXPERIMENTAL: 1
  run: |
    cosign sign --yes \
      ${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST}
  # The --yes flag accepts the Rekor log entry without interactive prompt
  # No key management required — OIDC token from GitHub Actions is used automatically
```

**Verify signatures are being produced correctly**:

```bash
# Verify a recently signed image
cosign verify \
  --certificate-identity-regexp "^https://github.com/${ORG}/${REPO}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${REGISTRY}/${IMAGE}@${DIGEST}

# Confirm the expected metadata fields are present
cosign verify \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.[0].optional | {
    Issuer,
    Subject,
    "github-workflow-ref",
    "github-sha",
    "run-id"
  }'
```

**Add signature verification to deployment gates** (Kubernetes admission controller):

```yaml
# Kyverno policy: require Cosign signature on all production images
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - production
                - staging
      verifyImages:
        - imageReferences:
            - "${REGISTRY}/${ORG}/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/${ORG}/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

#### Month 2: SLSA Provenance

```yaml
# GitHub Actions: generate SLSA level 3 provenance using slsa-github-generator
# Add as a separate job after the build job

jobs:
  build:
    # ... your existing build job
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}

  provenance:
    needs: build
    permissions:
      id-token: write
      contents: read
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${REGISTRY}/${IMAGE_NAME}
      digest: ${{ needs.build.outputs.image-digest }}
      registry-username: ${{ github.actor }}
    secrets:
      registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

#### Month 3: SBOM Generation

```yaml
# GitHub Actions: generate SBOM and attach as attestation
- name: Generate SBOM
  run: |
    syft ${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST} \
      -o cyclonedx-json \
      > sbom.cdx.json

- name: Attest SBOM
  env:
    COSIGN_EXPERIMENTAL: 1
  run: |
    cosign attest --yes \
      --predicate sbom.cdx.json \
      --type cyclonedx \
      ${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST}
```

**Validate SBOM retrieval**:

```bash
# Verify the SBOM attestation exists and is valid
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/${ORG}/${REPO}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${REGISTRY}/${IMAGE}@${DIGEST} \
  | jq '.payload | @base64d | fromjson | .predicate.components | length'
# Should return the number of components in the SBOM — verify it's non-zero
```

**Acceptance Criteria — Phase 2 Complete**:
- [ ] 100% of production artifact builds produce a Cosign signature
- [ ] 100% of production artifact builds produce a SLSA provenance attestation
- [ ] 100% of production container image builds produce a signed SBOM
- [ ] Signature verification enforced at deployment gate (Kyverno or OPA Gatekeeper policy)
- [ ] At least one deployment was blocked by signature verification failure (policy is enforcing)
- [ ] Rekor entries verified for a sample of production artifacts

---

## Phase 3 (90–180 Days): Integration and Automation

**Objective**: Integrate evidence sources into SIEM with correlation rules; deploy automated anomaly alerting; develop and test investigation runbooks.

**Starting State Assumption**: Phases 1 and 2 complete; all evidence sources flowing; artifact signing in place.

### Actions

#### Month 4: SIEM Integration and Correlation Rules

Connect all evidence sources to the SIEM and create cross-source correlation rules for the highest-priority incident types.

**Priority correlation rules to deploy first**:

```
Rule: Secret accessed from unexpected IP
Logic: Vault audit event WHERE client_ip NOT IN (known_ci_runner_cidr)
       AND operation = "read"
       AND path MATCHES "secret/data/production/*"
Severity: P2
Action: Alert + create incident ticket

Rule: Artifact pushed to registry without pipeline run
Logic: Registry push event (CloudTrail ECR PutImage) WHERE
       timestamp NOT WITHIN 30min of any CI pipeline run event
       AND repository MATCHES production/*
Severity: P1
Action: Alert + page on-call + suspend artifact promotion

Rule: Pipeline definition modified without PR review
Logic: git push event to .github/workflows/* WHERE
       push was direct to default branch (no PR merge event)
       OR PR was merged with < 1 approver
Severity: P2
Action: Alert + create incident ticket

Rule: Kubernetes API exec into production pod
Logic: k8s audit event WHERE verb = "create"
       AND resource = "pods/exec"
       AND namespace = "production"
Severity: P2
Action: Alert + capture pod state immediately
```

#### Month 5: Automated Runbook Development

Develop investigation runbooks for the top five incident types observed in your environment. Runbooks must include:

1. Detection signal that triggers the runbook
2. Evidence collection commands specific to your environment (with actual cluster names, bucket names, account IDs — not placeholders)
3. Triage decision tree
4. Containment procedure
5. Escalation criteria

**Test every runbook against a simulated incident** before approving it for production use. Tabletop exercises are acceptable for initial validation; live fire exercises are required for Level 4 readiness.

#### Month 6: Evidence Retention Verification

Run a retention audit to verify that evidence is actually accumulating in the tamper-evident store and has not been accidentally misconfigured or interrupted:

```bash
# Verify CloudTrail is delivering logs (check for recent files)
aws s3 ls s3://${FORENSICS_BUCKET}/cloudtrail/ --recursive \
  | sort -r | head -20

# Verify log file integrity for a specific date
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/org-forensics-trail \
  --start-time $(date -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date +%Y-%m-%dT%H:%M:%SZ)

# Count evidence objects by source to verify all sources are active
aws s3 ls s3://${FORENSICS_BUCKET}/ --recursive \
  | awk '{print $4}' \
  | cut -d'/' -f1 \
  | sort | uniq -c | sort -rn
```

**Acceptance Criteria — Phase 3 Complete**:
- [ ] SIEM connected to all evidence sources from Phases 1 and 2
- [ ] At minimum 5 correlation rules deployed and producing alerts
- [ ] Alert-to-ticket automation operational (no manual ticket creation for automated alerts)
- [ ] Investigation runbooks written for top 5 incident types
- [ ] At least one tabletop exercise completed using the runbooks
- [ ] Evidence retention audit confirms all sources are delivering
- [ ] MTTD baseline measured for at least one incident type

---

## Phase 4 (180+ Days): Agent Forensics and Continuous Evidence

**Objective**: If AI agents are deployed in the DevSecOps environment, build the forensic infrastructure required to investigate agent incidents. Implement continuous evidence integrity monitoring and regulatory evidence packaging.

**Starting State Assumption**: Phases 1–3 complete; SIEM operational; runbooks tested.

### Actions

#### Month 7–9: Agent Forensics Infrastructure

This phase is only applicable if AI agents are deployed in your DevSecOps pipeline. If not, proceed to the continuous evidence section.

**Deploy structured tool call logging**:

```python
# Example: tool call logging wrapper for an agent framework
import hashlib
import json
import time
from datetime import datetime, timezone

class ForensicToolLogger:
    def __init__(self, agent_id: str, session_id: str,
                 system_prompt_hash: str, log_store):
        self.agent_id = agent_id
        self.session_id = session_id
        self.system_prompt_hash = system_prompt_hash
        self.log_store = log_store

    def log_tool_call(self, tool_name: str, tool_input: dict,
                      tool_output: dict, authorization_decision: str,
                      policy_version: str) -> str:
        input_json = json.dumps(tool_input, sort_keys=True)
        output_json = json.dumps(tool_output, sort_keys=True)

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": self._generate_trace_id(),
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": tool_name,
            "tool_input_hash": hashlib.sha256(input_json.encode()).hexdigest(),
            "tool_input": tool_input,
            "tool_output_hash": hashlib.sha256(output_json.encode()).hexdigest(),
            "tool_output": tool_output,
            "authorization_policy_version": policy_version,
            "authorization_decision": authorization_decision,
            "system_prompt_hash": self.system_prompt_hash
        }

        # Write to immutable log store (must not be writable by the agent itself)
        self.log_store.append(record)
        return record["trace_id"]

    def _generate_trace_id(self) -> str:
        return f"tr-{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:16]}"
```

**System prompt versioning**:

```bash
# Store system prompt with content hash as reference
PROMPT_CONTENT=$(cat system-prompts/devsecops-triage-agent.txt)
PROMPT_HASH=$(echo -n "${PROMPT_CONTENT}" | sha256sum | awk '{print $1}')

# Commit to version control
git add system-prompts/devsecops-triage-agent.txt
git commit -m "Update system prompt [hash: ${PROMPT_HASH}]"

# Tag the commit for easy retrieval
git tag "prompt-${PROMPT_HASH:0:12}" HEAD

# At agent startup, record the prompt hash
echo "{\"agent_id\": \"devsecops-triage-agent\", \"session_start\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"system_prompt_hash\": \"${PROMPT_HASH}\"}" \
  | aws s3 cp - s3://${FORENSICS_BUCKET}/agent-sessions/${SESSION_ID}/metadata.json
```

#### Month 10–12: Continuous Evidence Monitoring

Deploy monitoring that alerts when evidence collection gaps are detected:

```bash
# Lambda function to check for CloudTrail delivery gaps
# If no new logs in 2 hours, alert

import boto3
import json
from datetime import datetime, timezone, timedelta

def check_evidence_gaps(event, context):
    s3 = boto3.client('s3')
    sns = boto3.client('sns')

    bucket = os.environ['FORENSICS_BUCKET']
    alert_topic = os.environ['ALERT_TOPIC_ARN']

    # Check for CloudTrail logs in the last 2 hours
    prefix = f"cloudtrail/AWSLogs/{os.environ['ACCOUNT_ID']}/"
    cutoff = datetime.now(timezone.utc) - timedelta(hours=2)

    response = s3.list_objects_v2(
        Bucket=bucket,
        Prefix=prefix
    )

    recent_objects = [
        obj for obj in response.get('Contents', [])
        if obj['LastModified'] > cutoff
    ]

    if not recent_objects:
        sns.publish(
            TopicArn=alert_topic,
            Subject='FORENSICS ALERT: CloudTrail delivery gap detected',
            Message=json.dumps({
                'alert_type': 'evidence_gap',
                'evidence_source': 'cloudtrail',
                'gap_since': cutoff.isoformat(),
                'bucket': bucket
            })
        )
```

#### Month 11–12: Regulatory Evidence Packages

For regulated environments, implement the ability to generate a complete evidence package for a given incident or time period on demand:

```bash
#!/bin/bash
# generate-evidence-package.sh
# Usage: ./generate-evidence-package.sh <INCIDENT_ID> <START_ISO8601> <END_ISO8601>

INCIDENT_ID=$1
START=$2
END=$3
PACKAGE_DIR="evidence-package-${INCIDENT_ID}"

mkdir -p ${PACKAGE_DIR}/{cloudtrail,vpc-flow-logs,k8s-audit,vault,ci-audit,artifacts}

echo "Collecting CloudTrail events..."
aws cloudtrail lookup-events \
  --start-time ${START} \
  --end-time ${END} \
  --output json \
  > ${PACKAGE_DIR}/cloudtrail/events.json

echo "Collecting VPC Flow Logs..."
aws s3 sync \
  s3://${FORENSICS_BUCKET}/vpc-flow-logs/ \
  ${PACKAGE_DIR}/vpc-flow-logs/ \
  --exclude "*" \
  --include "*/$(date -d ${START} +%Y/%m/%d)/*"

echo "Collecting Kubernetes audit events from SIEM..."
# Query SIEM API for k8s audit events in the window
curl -s -H "Authorization: Bearer ${SIEM_TOKEN}" \
  "${SIEM_URL}/api/search?index=k8s-audit&start=${START}&end=${END}" \
  > ${PACKAGE_DIR}/k8s-audit/events.json

echo "Generating manifest with SHA-256 hashes..."
find ${PACKAGE_DIR} -type f -exec sha256sum {} \; \
  | sort > ${PACKAGE_DIR}/MANIFEST.sha256

echo "Creating evidence package..."
tar czf evidence-package-${INCIDENT_ID}.tar.gz ${PACKAGE_DIR}/

PACKAGE_HASH=$(sha256sum evidence-package-${INCIDENT_ID}.tar.gz | awk '{print $1}')
echo "Package hash: ${PACKAGE_HASH}" > evidence-package-${INCIDENT_ID}.sha256

echo "GPG-signing the evidence package..."
gpg --armor --detach-sign \
  --local-user ${FORENSICS_GPG_KEY_ID} \
  evidence-package-${INCIDENT_ID}.tar.gz

echo "Uploading to evidence store..."
aws s3 cp evidence-package-${INCIDENT_ID}.tar.gz \
  s3://${FORENSICS_BUCKET}/incident-packages/${INCIDENT_ID}/
aws s3 cp evidence-package-${INCIDENT_ID}.sha256 \
  s3://${FORENSICS_BUCKET}/incident-packages/${INCIDENT_ID}/
aws s3 cp evidence-package-${INCIDENT_ID}.tar.gz.asc \
  s3://${FORENSICS_BUCKET}/incident-packages/${INCIDENT_ID}/

echo "Evidence package complete: ${PACKAGE_HASH}"
```

**Acceptance Criteria — Phase 4 Complete**:
- [ ] (If agents deployed) Structured tool call logging operational and shipping to immutable store
- [ ] (If agents deployed) System prompts versioned and hash-referenced in all tool call logs
- [ ] Continuous evidence gap monitoring deployed and alerting on gaps
- [ ] Evidence package generation script tested against at least one historical incident
- [ ] Evidence packages verified against MANIFEST.sha256 and GPG signature
- [ ] Regulatory evidence package format reviewed by legal counsel

---

## Implementation Across Cloud Providers

### GCP Implementation Notes

```bash
# Enable GCP Audit Logs for all services in a project
gcloud projects get-iam-policy ${PROJECT_ID} > iam-policy.json

# Add audit log configuration to the policy (edit iam-policy.json):
# "auditConfigs": [
#   {
#     "service": "allServices",
#     "auditLogConfigs": [
#       {"logType": "ADMIN_READ"},
#       {"logType": "DATA_READ"},
#       {"logType": "DATA_WRITE"}
#     ]
#   }
# ]

gcloud projects set-iam-policy ${PROJECT_ID} iam-policy.json

# Export audit logs to GCS bucket with retention lock
gcloud logging sinks create forensics-sink \
  storage.googleapis.com/${FORENSICS_BUCKET} \
  --log-filter="protoPayload.@type=type.googleapis.com/google.cloud.audit.AuditLog" \
  --include-children

# Set retention lock on GCS bucket (cannot be shortened once set)
gcloud storage buckets update gs://${FORENSICS_BUCKET} \
  --retention-period=7y \
  --lock-retention-period
```

### Azure Implementation Notes

```bash
# Enable Azure Activity Log diagnostic settings
az monitor diagnostic-settings create \
  --name forensics-diagnostics \
  --subscription ${SUBSCRIPTION_ID} \
  --logs '[{"category": "Administrative", "enabled": true},
           {"category": "Security", "enabled": true},
           {"category": "ServiceHealth", "enabled": true},
           {"category": "Alert", "enabled": true},
           {"category": "Policy", "enabled": true}]' \
  --storage-account /subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT}

# Configure immutability policy (must be done before first data write to container)
az storage container immutability-policy create \
  --account-name ${STORAGE_ACCOUNT} \
  --container-name audit-logs \
  --period 2555 \
  --allow-protected-append-writes true
```
