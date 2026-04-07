# Evidence Chain of Custody

## Table of Contents

1. [Why Chain of Custody Matters](#why-chain-of-custody-matters)
2. [The Evidence Lifecycle](#the-evidence-lifecycle)
3. [Hashing and Timestamping Evidence](#hashing-and-timestamping-evidence)
4. [Immutable Storage Configuration](#immutable-storage-configuration)
5. [Evidence Packaging Format](#evidence-packaging-format)
6. [Access Control for Evidence](#access-control-for-evidence)
7. [Evidence Retention Schedule](#evidence-retention-schedule)

---

## Why Chain of Custody Matters

Chain of custody documentation establishes that evidence has not been tampered with, fabricated, or contaminated between the moment it was collected and the moment it is presented — to management, to regulators, or to a court.

In a DevSecOps forensics context, the chain of custody requirement arises in several situations:

**Regulatory investigation**: A data breach notification may trigger a regulatory investigation (FTC, state AG, ICO under GDPR, OCC for financial institutions). Regulators examining whether the organization responded adequately will ask to see evidence of what happened and when the organization knew. If the evidence cannot be authenticated or its integrity verified, the investigation's conclusions can be challenged.

**Litigation**: If a breach leads to litigation — class action, customer lawsuit, or legal action against a vendor whose compromised software was deployed — the forensic evidence becomes discovery material. Evidence that cannot be authenticated is inadmissible or subject to adverse inference.

**Internal accountability**: Even without external legal proceedings, a chain of custody establishes what evidence supports a finding. Without it, investigation conclusions are assertions rather than findings, and can be challenged or discredited.

**Law enforcement referral**: If the incident involves a criminal actor and the organization refers the matter to law enforcement (FBI, local law enforcement, INTERPOL), law enforcement forensics requirements are strict. Evidence that was not collected and preserved in a forensically sound manner may be unusable in a prosecution.

---

## The Evidence Lifecycle

Every piece of evidence goes through a defined lifecycle from collection to disposition. Each stage must be documented.

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  COLLECTION │ ──→ │ PRESERVATION │ ──→ │   ANALYSIS   │
│             │     │              │     │              │
│ Collect     │     │ Hash         │     │ Read-only    │
│ from source │     │ Timestamp    │     │ analysis on  │
│ Assign ID   │     │ Store in     │     │ copy, never  │
│ Open COC    │     │ WORM store   │     │ original     │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                          ┌──────────────────────┘
                          ▼
               ┌──────────────────┐     ┌──────────────┐
               │    REPORTING     │ ──→ │  LEGAL HOLD  │
               │                  │     │  or          │
               │ Findings report  │     │  DISPOSITION │
               │ Evidence cited   │     │              │
               │ Hashes verified  │     │ Retain or    │
               └──────────────────┘     │ destroy per  │
                                        │ schedule     │
                                        └──────────────┘
```

### Stage 1: Collection

When evidence is collected from its source, the following must be recorded in the chain of custody log immediately:

```
Evidence ID: EVD-{INCIDENT_ID}-{SEQUENCE_NUMBER}
Collected By: {name and role of collector}
Collection Time: {ISO8601 timestamp}
Source System: {system name, account/cluster, region}
Collection Method: {command used to collect; tool and version}
Evidence Description: {what this evidence contains}
SHA-256 Hash: {hash of the evidence file immediately after collection}
Chain of Custody Location: {where the evidence is stored}
Witness: {second team member who verified collection}
```

### Stage 2: Preservation

Evidence must be moved to tamper-evident storage immediately after collection. Do not store evidence on your laptop, a shared drive, or a non-WORM S3 bucket during investigation. These are not forensically sound storage locations.

```bash
# Immediately after collecting evidence, move to the forensics evidence bucket
EVIDENCE_ID="EVD-${INCIDENT_ID}-$(printf '%03d' ${SEQUENCE})"
EVIDENCE_FILE="cloudtrail-events-${INCIDENT_ID}.json"

# Hash the file
SHA256=$(sha256sum "${EVIDENCE_FILE}" | awk '{print $1}')
echo "${SHA256}  ${EVIDENCE_FILE}" > "${EVIDENCE_FILE}.sha256"

# Upload to evidence bucket (WORM storage)
aws s3 cp "${EVIDENCE_FILE}" \
  "s3://${FORENSICS_BUCKET}/incidents/${INCIDENT_ID}/evidence/${EVIDENCE_ID}-${EVIDENCE_FILE}"
aws s3 cp "${EVIDENCE_FILE}.sha256" \
  "s3://${FORENSICS_BUCKET}/incidents/${INCIDENT_ID}/evidence/${EVIDENCE_ID}-${EVIDENCE_FILE}.sha256"

# Record in chain of custody log
cat >> "coc-log-${INCIDENT_ID}.json" << EOF
{
  "evidence_id": "${EVIDENCE_ID}",
  "file": "${EVIDENCE_FILE}",
  "sha256": "${SHA256}",
  "collected_by": "${COLLECTOR_NAME}",
  "collection_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source": "${SOURCE_DESCRIPTION}",
  "storage_location": "s3://${FORENSICS_BUCKET}/incidents/${INCIDENT_ID}/evidence/${EVIDENCE_ID}-${EVIDENCE_FILE}",
  "witness": "${WITNESS_NAME}"
}
EOF
```

### Stage 3: Analysis

All analysis is performed on a copy of the evidence, never the original. The original in the WORM bucket is never modified.

```bash
# Create a working copy for analysis
mkdir -p /tmp/incident-${INCIDENT_ID}-workspace

# Download evidence for analysis
aws s3 cp \
  "s3://${FORENSICS_BUCKET}/incidents/${INCIDENT_ID}/evidence/${EVIDENCE_ID}-${EVIDENCE_FILE}" \
  /tmp/incident-${INCIDENT_ID}-workspace/${EVIDENCE_FILE}

# Verify integrity before analysis
DOWNLOADED_SHA256=$(sha256sum "/tmp/incident-${INCIDENT_ID}-workspace/${EVIDENCE_FILE}" | awk '{print $1}')
ORIGINAL_SHA256=$(cat "${EVIDENCE_FILE}.sha256" | awk '{print $1}')

if [ "${DOWNLOADED_SHA256}" != "${ORIGINAL_SHA256}" ]; then
  echo "INTEGRITY CHECK FAILED: Evidence may have been modified"
  echo "Original hash: ${ORIGINAL_SHA256}"
  echo "Downloaded hash: ${DOWNLOADED_SHA256}"
  exit 1
fi

echo "Integrity verified. Safe to analyze."
```

### Stage 4: Reporting

When evidence is cited in a forensic report, each citation must reference the Evidence ID, the SHA-256 hash of the evidence, and the specific data point in the evidence that supports the finding.

**Example evidence citation in a report**:
> The attacker's initial access occurred at 14:23:01 UTC. Evidence: CloudTrail log entry (EVD-INC-20240115-003, sha256:8b3a1f..., event index 447) shows an AssumeRole call from IP 198.51.100.42 — an address not in the known CI runner CIDR.

### Stage 5: Legal Hold or Disposition

At the end of the investigation, evidence either enters a legal hold (if litigation or regulatory investigation is anticipated) or is dispositioned per the retention schedule. See [legal-hold-procedures.md](legal-hold-procedures.md) for legal hold procedures.

---

## Hashing and Timestamping Evidence

### Hashing

Every evidence file must be SHA-256 hashed at the moment of collection, before it is moved to storage. The hash is the evidence of integrity — if the hash of the stored file matches the collection hash, the file has not been modified.

```bash
# Hash a single file
sha256sum evidence-file.json > evidence-file.json.sha256

# Hash multiple files and produce a manifest
find ./evidence-collection/ -type f -not -name "*.sha256" -not -name "MANIFEST*" \
  | sort \
  | xargs sha256sum \
  > MANIFEST.sha256

# Verify the manifest
sha256sum --check MANIFEST.sha256
```

### Timestamping

Timestamps in file metadata (mtime, ctime) are not forensically reliable — they can be modified with trivial tools. Forensically sound timestamping uses one of:

1. **Rekor timestamp**: For artifact evidence (Cosign signatures, SLSA provenance), the Rekor log entry provides a RFC 3339 timestamp with inclusion proof in an append-only Merkle tree. This is the strongest timestamp available for artifact evidence.

2. **CloudTrail timestamp**: For cloud event evidence, the CloudTrail event timestamp is authoritative for AWS API calls and is included in the log file integrity digest chain.

3. **Trusted timestamping (RFC 3161)**: For locally-collected evidence files, use a trusted timestamping authority to obtain a timestamp token:

```bash
# Generate a timestamp using an RFC 3161 TSA
# (many free TSAs available: DigiCert, Sectigo, Freetsa.org)

# Step 1: Create hash of the evidence file
openssl dgst -sha256 -binary evidence-file.json > evidence-file.hash

# Step 2: Create a timestamp request
openssl ts -query \
  -data evidence-file.json \
  -sha256 \
  -cert \
  -out evidence-file.tsq

# Step 3: Submit to TSA (example: using freetsa.org)
curl -H "Content-Type: application/timestamp-query" \
  --data-binary @evidence-file.tsq \
  https://freetsa.org/tsr \
  -o evidence-file.tsr

# Step 4: Verify the timestamp
openssl ts -verify \
  -data evidence-file.json \
  -in evidence-file.tsr \
  -CAfile /etc/ssl/certs/ca-certificates.crt

# The .tsr file contains the timestamp token and must be stored alongside the evidence
```

---

## Immutable Storage Configuration

Evidence storage must use WORM (Write Once, Read Many) guarantees. See [architecture.md — Immutable Log Storage](architecture.md) for full configuration procedures. Key requirements for evidence storage:

| Requirement | AWS | Azure | GCP |
|---|---|---|---|
| WORM storage | S3 Object Lock, Compliance mode | Azure Immutable Blob Storage, locked policy | GCS with locked retention policy |
| Minimum retention | 7 years (or per regulation, whichever is longer) | Same | Same |
| Delete prevention | Object Lock COMPLIANCE — even root cannot delete | Locked immutability policy — cannot be shortened | Locked retention — cannot be shortened or removed |
| Versioning | Required for S3 Object Lock | Built-in | Built-in |
| Encryption | SSE-S3 or SSE-KMS minimum | AES-256 with CMK recommended | CMEK recommended |
| Access logging | S3 Access Logs or CloudTrail data events | Azure Storage Diagnostics | GCS audit logging |

### Evidence Bucket Lifecycle Policy

Evidence should not sit in the same storage tier for its entire 7-year retention period. Use lifecycle policies to move older evidence to cheaper storage while maintaining immutability:

```json
{
  "Rules": [
    {
      "ID": "ForensicsEvidenceLifecycle",
      "Status": "Enabled",
      "Transitions": [
        {
          "Days": 90,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 365,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 730,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ]
    }
  ]
}
```

Note: Object Lock applies regardless of storage class. Evidence moved to Glacier DEEP_ARCHIVE remains locked until the retention period expires.

---

## Evidence Packaging Format

When delivering evidence to legal counsel, regulators, law enforcement, or external forensics firms, evidence must be packaged in a format that is self-documenting and verifiable.

### Standard Evidence Package Structure

```
evidence-package-${INCIDENT_ID}/
├── README.txt                    # Human-readable package description
├── MANIFEST.sha256               # SHA-256 hashes of all evidence files
├── chain-of-custody.json         # COC log for all evidence in this package
├── evidence/
│   ├── EVD-001-cloudtrail-events.json
│   ├── EVD-002-kubernetes-audit.json
│   ├── EVD-003-vault-audit.json
│   ├── EVD-004-github-audit.json
│   └── EVD-005-cosign-signatures.json
├── analysis/
│   ├── incident-timeline.json    # Reconstructed timeline (derived, not original evidence)
│   └── investigator-notes.txt   # Analyst notes (not evidence; analytical conclusions)
└── package-metadata.json        # Package ID, creation time, investigator, package hash
```

### Evidence Package Creation Script

```bash
#!/bin/bash
# create-evidence-package.sh
# Creates a signed, hashed evidence package for legal/regulatory delivery

INCIDENT_ID=${1}
PACKAGE_ID="PKG-${INCIDENT_ID}-$(date +%Y%m%d%H%M%S)"
PACKAGE_DIR="${PACKAGE_ID}"

echo "Creating evidence package: ${PACKAGE_ID}"

# Create package directory structure
mkdir -p "${PACKAGE_DIR}/evidence"
mkdir -p "${PACKAGE_DIR}/analysis"

# Copy evidence files from WORM bucket
echo "Downloading evidence from tamper-evident store..."
aws s3 sync \
  "s3://${FORENSICS_BUCKET}/incidents/${INCIDENT_ID}/evidence/" \
  "${PACKAGE_DIR}/evidence/"

# Verify all downloaded files against their collection hashes
echo "Verifying evidence integrity..."
INTEGRITY_FAILURES=0
for sha_file in "${PACKAGE_DIR}/evidence/"*.sha256; do
  evidence_file="${sha_file%.sha256}"
  if [ -f "${evidence_file}" ]; then
    if ! sha256sum --check "${sha_file}" > /dev/null 2>&1; then
      echo "INTEGRITY FAILURE: ${evidence_file}"
      INTEGRITY_FAILURES=$((INTEGRITY_FAILURES + 1))
    fi
  fi
done

if [ ${INTEGRITY_FAILURES} -gt 0 ]; then
  echo "ERROR: ${INTEGRITY_FAILURES} integrity failure(s) detected. Do not deliver this package."
  exit 1
fi

echo "All integrity checks passed."

# Copy chain of custody log
aws s3 cp \
  "s3://${FORENSICS_BUCKET}/incidents/${INCIDENT_ID}/chain-of-custody.json" \
  "${PACKAGE_DIR}/chain-of-custody.json"

# Generate package manifest
echo "Generating package manifest..."
find "${PACKAGE_DIR}" -type f -not -name "MANIFEST.sha256" \
  | sort \
  | xargs sha256sum \
  > "${PACKAGE_DIR}/MANIFEST.sha256"

# Generate package metadata
PACKAGE_HASH=$(sha256sum "${PACKAGE_DIR}/MANIFEST.sha256" | awk '{print $1}')
cat > "${PACKAGE_DIR}/package-metadata.json" << EOF
{
  "package_id": "${PACKAGE_ID}",
  "incident_id": "${INCIDENT_ID}",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "created_by": "${INVESTIGATOR_NAME}",
  "created_by_role": "${INVESTIGATOR_ROLE}",
  "evidence_count": $(ls "${PACKAGE_DIR}/evidence/" | grep -v "\.sha256$" | wc -l),
  "manifest_hash": "${PACKAGE_HASH}",
  "recipient": "${RECIPIENT_ORG}",
  "delivery_purpose": "${DELIVERY_PURPOSE}"
}
EOF

# Create tar archive
echo "Creating archive..."
tar czf "${PACKAGE_ID}.tar.gz" "${PACKAGE_DIR}/"

ARCHIVE_HASH=$(sha256sum "${PACKAGE_ID}.tar.gz" | awk '{print $1}')
echo "${ARCHIVE_HASH}  ${PACKAGE_ID}.tar.gz" > "${PACKAGE_ID}.tar.gz.sha256"

# GPG sign the archive
echo "Signing archive..."
gpg --armor \
  --detach-sign \
  --local-user "${FORENSICS_GPG_KEY_ID}" \
  "${PACKAGE_ID}.tar.gz"

# Upload completed package to evidence store
echo "Uploading to evidence store..."
aws s3 cp "${PACKAGE_ID}.tar.gz" \
  "s3://${FORENSICS_BUCKET}/incident-packages/${INCIDENT_ID}/${PACKAGE_ID}.tar.gz"
aws s3 cp "${PACKAGE_ID}.tar.gz.sha256" \
  "s3://${FORENSICS_BUCKET}/incident-packages/${INCIDENT_ID}/${PACKAGE_ID}.tar.gz.sha256"
aws s3 cp "${PACKAGE_ID}.tar.gz.asc" \
  "s3://${FORENSICS_BUCKET}/incident-packages/${INCIDENT_ID}/${PACKAGE_ID}.tar.gz.asc"

echo ""
echo "Evidence package complete:"
echo "  Package ID: ${PACKAGE_ID}"
echo "  Archive: ${PACKAGE_ID}.tar.gz"
echo "  SHA-256: ${ARCHIVE_HASH}"
echo "  GPG signature: ${PACKAGE_ID}.tar.gz.asc"
echo ""
echo "Verify the package with:"
echo "  gpg --verify ${PACKAGE_ID}.tar.gz.asc ${PACKAGE_ID}.tar.gz"
echo "  sha256sum --check ${PACKAGE_ID}.tar.gz.sha256"
```

### Recipient Verification Instructions

When delivering an evidence package to legal counsel, regulators, or law enforcement, include these verification instructions:

```
Evidence Package Verification Instructions
==========================================

Package ID: ${PACKAGE_ID}
Delivered by: ${INVESTIGATOR_NAME}, ${INVESTIGATOR_ROLE}
Delivery date: ${DATE}
Incident: ${INCIDENT_ID}

Step 1: Verify GPG signature
  gpg --import forensics-team-pubkey.asc
  gpg --verify ${PACKAGE_ID}.tar.gz.asc ${PACKAGE_ID}.tar.gz

Step 2: Verify SHA-256 hash
  sha256sum --check ${PACKAGE_ID}.tar.gz.sha256
  Expected: ${ARCHIVE_HASH}

Step 3: Extract and verify internal manifest
  tar xzf ${PACKAGE_ID}.tar.gz
  sha256sum --check ${PACKAGE_ID}/MANIFEST.sha256

If all three verification steps pass, the package has not been modified
since it was created by the forensics team.

Questions: ${FORENSICS_CONTACT}
```

---

## Access Control for Evidence

Evidence access must follow the principle of least privilege and separation of duties.

### Access Roles

| Role | Access Level | Who Holds This Role |
|---|---|---|
| Evidence Custodian | Read-only; list; can verify hashes | Designated security engineer or legal counsel |
| Forensics Investigator | Read-only; cannot delete or modify | On-call security engineers for active investigations |
| Evidence Writer | Write-only; cannot read | Automated collection systems, CI export scripts |
| Legal Hold Administrator | Can extend retention; cannot delete during hold | Legal counsel only |
| Audit | List only (no read); for access auditing | Compliance team |

### Evidence Access Log

Every read of an evidence file must be logged. This is automatic with S3 Server Access Logging:

```bash
# Enable S3 Server Access Logging on the evidence bucket
aws s3api put-bucket-logging \
  --bucket ${FORENSICS_BUCKET} \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "${FORENSICS_ACCESS_LOG_BUCKET}",
      "TargetPrefix": "evidence-access-logs/"
    }
  }'

# Or use CloudTrail data events for object-level logging
aws cloudtrail put-event-selectors \
  --trail-name org-forensics-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": false,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::${FORENSICS_BUCKET}/"]
    }]
  }]'
```

---

## Evidence Retention Schedule

Evidence retention must balance competing requirements: longer retention is better for forensics but creates regulatory obligations (GDPR right to erasure), storage costs, and legal risk (retained evidence can be compelled in litigation).

| Incident Type | Minimum Retention | Extended Retention Trigger | Maximum Retention |
|---|---|---|---|
| P3 (no confirmed compromise) | 1 year | Regulatory inquiry | 3 years |
| P2 (contained compromise) | 3 years | Litigation, regulatory inquiry, law enforcement | 7 years |
| P1 (production impact) | 7 years | Law enforcement referral | Indefinite (legal hold) |
| Regulatory incident (breach notification filed) | 7 years | Mandatory per regulation | Per regulation (often 10 years) |
| Legal hold | Until hold released | Court order | Until released by legal counsel |

**GDPR Retention Conflict**: If evidence contains personal data of EU data subjects, retention beyond the minimum necessary for the investigation purpose may conflict with GDPR Article 5(1)(e) (storage limitation). See [legal-hold-procedures.md — GDPR Considerations](legal-hold-procedures.md) for the framework for resolving this conflict.

### Scheduled Disposition

When evidence reaches its retention end date (and is not under legal hold), disposition must be documented:

```bash
# Verify no legal hold applies before disposition
aws s3api get-object-legal-hold \
  --bucket ${FORENSICS_BUCKET} \
  --key "incidents/${INCIDENT_ID}/evidence/${EVIDENCE_ID}.json" \
  2>/dev/null || echo "No legal hold applied"

# Document disposition
cat >> disposition-log.json << EOF
{
  "evidence_id": "${EVIDENCE_ID}",
  "incident_id": "${INCIDENT_ID}",
  "disposition_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "disposition_type": "retention_expired",
  "disposed_by": "${AUTHORIZED_BY}",
  "approval_reference": "${APPROVAL_TICKET}"
}
EOF

# Note: In S3 Object Lock Compliance mode, objects cannot be deleted before
# the retention period expires. Disposition is automatic at expiry.
# This log documents the intentional decision not to extend retention.
```
