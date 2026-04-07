# Legal Hold Procedures for Digital Evidence

## Table of Contents

1. [Overview](#overview)
2. [Trigger Conditions for Legal Hold](#trigger-conditions-for-legal-hold)
3. [Scope of a Legal Hold in DevSecOps](#scope-of-a-legal-hold-in-devsecops)
4. [Implementing Legal Hold by Evidence Source](#implementing-legal-hold-by-evidence-source)
5. [Coordination with Legal Counsel and External Firms](#coordination-with-legal-counsel-and-external-firms)
6. [The Escalation Matrix](#the-escalation-matrix)
7. [GDPR Considerations](#gdpr-considerations)
8. [Template: Legal Hold Notice for Engineering Teams](#template-legal-hold-notice-for-engineering-teams)

---

## Overview

A legal hold (also called a litigation hold or evidence preservation order) is a directive to preserve all potentially relevant information that might otherwise be deleted, modified, or overwritten in the normal course of business. In a DevSecOps environment, "the normal course of business" includes log rotation, CI artifact cleanup, container registry tag pruning, git repository maintenance, and automated evidence archival.

Legal holds in technology companies differ from traditional document holds in several ways:
- Data volumes are orders of magnitude larger (a single CloudTrail trail may produce hundreds of GB of logs per month)
- Evidence is distributed across dozens of systems (AWS, GitHub, Kubernetes clusters, Vault, CI platforms)
- Some evidence sources are ephemeral by design (CI runner logs, Lambda execution logs) and require active preservation to survive beyond their normal lifecycle
- Evidence may be held by third parties (GitHub, AWS, Google Cloud, Slack) who have their own retention schedules and legal processes

This document provides the procedures for implementing and managing legal holds across the evidence sources in a DevSecOps environment.

**Mandatory requirement**: Before any legal hold is implemented or released, legal counsel must be involved. Engineering teams must not make independent decisions to implement or release legal holds. The procedures in this document are for execution after legal counsel has directed the hold — not for deciding whether a hold is needed.

---

## Trigger Conditions for Legal Hold

A legal hold should be considered any time there is a reasonable anticipation of litigation, regulatory investigation, or law enforcement involvement. Engineering and security teams must escalate to legal counsel immediately when any of the following conditions occur:

### Automatic Escalation Triggers

| Condition | Escalate To | Escalation Method |
|---|---|---|
| Law enforcement contact or subpoena received | Legal Counsel immediately | Call the General Counsel's direct line; do not email |
| Regulatory inquiry or investigation notice received (SEC, FTC, ICO, OCC, state AG) | Legal Counsel immediately | Same — call immediately |
| External threat actor has confirmed exfiltrated customer personal data | Legal Counsel + CISO | P1 incident notification matrix |
| Customer or partner formal legal notice threatening litigation | Legal Counsel | Standard legal notification channel |
| Class action filing or notice of representative action | Legal Counsel | Standard legal notification channel |
| Government national security or law enforcement request for data | Legal Counsel; do not respond directly | Call Legal Counsel before acknowledging receipt |
| An incident that may require breach notification under applicable law | Legal Counsel + Compliance | P1 incident notification |

### Judgment-Required Triggers (escalate to Legal Counsel for determination)

- Discovery of a significant security incident that affected customer data, even if notification requirement is unclear
- Dispute with a major vendor or customer that has escalated to legal threats
- Internal investigation of employee misconduct involving company systems
- Acquisition or merger due diligence that requires preservation of records

**When in doubt, escalate.** The cost of an unnecessary legal hold is storage cost and operational inconvenience. The cost of failing to implement a required legal hold (spoliation of evidence) can be catastrophic: adverse inference instructions, evidentiary sanctions, or criminal obstruction liability.

---

## Scope of a Legal Hold in DevSecOps

Legal holds must cover all potentially relevant evidence. In a DevSecOps context, this is significantly broader than just email and documents. Legal Counsel will define the specific scope; the following table identifies the evidence types that are commonly in scope for different categories of incidents.

| Evidence Source | Security Incident (Breach) | Regulatory Investigation | Employment Dispute | Vendor Dispute |
|---|---|---|---|---|
| AWS CloudTrail | In scope | In scope | Partial (actor-specific) | In scope (vendor access) |
| Kubernetes audit logs | In scope | In scope | Partial | Partial |
| Git repositories (all branches, history, PRs) | In scope | In scope | Partial (actor-specific) | In scope (if code is disputed) |
| CI/CD pipeline logs | In scope | In scope | Partial | In scope |
| Vault audit logs | In scope | In scope | Partial | Partial |
| Container registry (all versions in window) | In scope | In scope | Rarely | In scope |
| SBOM and provenance attestations | In scope | In scope | Rarely | In scope |
| Slack/Teams communications | Partial (security team channels) | Partial | In scope (all) | In scope (relevant channels) |
| Email (security@, ciso@, legal@) | Partial | Partial | In scope | In scope |
| GitHub audit log | In scope | In scope | Partial | Partial |
| Lambda execution logs | In scope | Partial | Rarely | Partial |
| VPC Flow Logs | In scope | Partial | Rarely | Rarely |
| Agent tool call logs | In scope | Partial | Partial | Rarely |

The specific scope for any legal hold will be defined by Legal Counsel based on the matter. Engineering teams must not narrow the scope on their own judgment.

---

## Implementing Legal Hold by Evidence Source

For each evidence source under legal hold, the normal retention schedule is suspended and the evidence is protected from deletion until the hold is released. The specific mechanism depends on the storage system.

### AWS S3 (CloudTrail logs, VPC Flow Logs, evidence packages)

S3 Object Lock in Compliance mode already protects the evidence from deletion during the retention period. If a legal hold requires extending protection beyond the configured retention period:

```bash
# Apply an indefinite legal hold to specific objects
# S3 Object Lock LEGAL HOLD is separate from the retention date
# It prevents deletion indefinitely, even after the retention date expires

aws s3api put-object-legal-hold \
  --bucket ${FORENSICS_BUCKET} \
  --key "incidents/${INCIDENT_ID}/evidence/${EVIDENCE_FILE}" \
  --legal-hold Status=ON

# Apply legal hold to all objects in an incident folder
aws s3api list-objects-v2 \
  --bucket ${FORENSICS_BUCKET} \
  --prefix "incidents/${INCIDENT_ID}/" \
  --query 'Contents[*].Key' \
  --output text \
  | tr '\t' '\n' \
  | while read KEY; do
    aws s3api put-object-legal-hold \
      --bucket ${FORENSICS_BUCKET} \
      --key "${KEY}" \
      --legal-hold Status=ON
    echo "Legal hold applied: ${KEY}"
  done

# Verify legal hold is in effect
aws s3api get-object-legal-hold \
  --bucket ${FORENSICS_BUCKET} \
  --key "incidents/${INCIDENT_ID}/evidence/${EVIDENCE_FILE}" \
  | jq '.LegalHold.Status'
# Should return: "ON"

# Release legal hold (only when authorized by Legal Counsel)
# aws s3api put-object-legal-hold \
#   --bucket ${FORENSICS_BUCKET} \
#   --key "${KEY}" \
#   --legal-hold Status=OFF
```

**Important**: S3 Object Lock Legal Hold requires `s3:PutObjectLegalHold` permission. This permission must be restricted to the legal hold administrator role. No other role should have this permission.

### Azure Immutable Blob Storage

```bash
# Create a time-based immutability policy for legal hold duration
# If the policy is already locked, you cannot extend it with a new immutability policy
# Use a legal hold policy instead, which can be applied alongside a locked retention policy

az storage container legal-hold set \
  --account-name ${STORAGE_ACCOUNT} \
  --container-name ${CONTAINER_NAME} \
  --tags "${INCIDENT_ID}" "${MATTER_ID}"

# List active legal holds
az storage container legal-hold show \
  --account-name ${STORAGE_ACCOUNT} \
  --container-name ${CONTAINER_NAME}

# Release legal hold (only when authorized by Legal Counsel)
# az storage container legal-hold clear \
#   --account-name ${STORAGE_ACCOUNT} \
#   --container-name ${CONTAINER_NAME} \
#   --tags "${INCIDENT_ID}"
```

### GitHub Repository Archival

When a legal hold covers git repository state, export and preserve the full repository including all branches, tags, and the reflog:

```bash
# Create a complete repository archive (includes all branches, tags, packed refs)
git clone --mirror https://github.com/${ORG}/${REPO}.git ${REPO}-legal-hold.git

# Verify the mirror is complete
cd ${REPO}-legal-hold.git
git log --all --oneline | wc -l  # Total commit count
git branch -a | wc -l            # Branch count
git tag | wc -l                  # Tag count

# Create compressed archive
cd ..
tar czf ${REPO}-legal-hold-$(date +%Y%m%d).tar.gz ${REPO}-legal-hold.git/

# Hash and store
sha256sum ${REPO}-legal-hold-*.tar.gz > ${REPO}-legal-hold.sha256
aws s3 cp ${REPO}-legal-hold-*.tar.gz \
  s3://${FORENSICS_BUCKET}/legal-hold/${MATTER_ID}/github/

# Additionally: archive all PR descriptions and review comments
gh api /repos/${ORG}/${REPO}/pulls \
  --paginate \
  --field state=all \
  --field per_page=100 \
  | jq '[.[] | {
    number: .number,
    title: .title,
    body: .body,
    state: .state,
    created_at: .created_at,
    merged_at: .merged_at,
    author: .user.login,
    merged_by: .merged_by.login
  }]' > ${REPO}-all-prs.json

# Archive issue tracker
gh api /repos/${ORG}/${REPO}/issues \
  --paginate \
  --field state=all \
  --field per_page=100 \
  > ${REPO}-all-issues.json
```

**Prevent force-push during hold**:
```bash
# Enable all branch protection on default branch
gh api /repos/${ORG}/${REPO}/branches/main/protection \
  --method PUT \
  --raw-field '{"required_status_checks": null, "enforce_admins": true,
    "required_pull_request_reviews": null, "restrictions": null,
    "allow_force_pushes": false, "allow_deletions": false}'
```

### CI/CD Platform Log Export

CI platform logs are not under the organization's direct storage control — they are stored by the CI provider and have provider-defined retention limits. Export immediately upon legal hold trigger.

```bash
# GitHub Actions: export all run logs for repositories in scope
# (this must be done before the CI platform's retention period expires)

gh api /repos/${ORG}/${REPO}/actions/runs \
  --paginate \
  --field per_page=100 \
  --field created=">=${HOLD_START_DATE}" \
  | jq -r '.workflow_runs[].id' \
  | while read RUN_ID; do
    mkdir -p legal-hold-ci-logs/${REPO}/
    gh run view ${RUN_ID} --repo ${ORG}/${REPO} --log \
      > legal-hold-ci-logs/${REPO}/run-${RUN_ID}.log 2>/dev/null \
      && echo "Exported run ${RUN_ID}" \
      || echo "Failed to export run ${RUN_ID} (may be expired)"
  done

# Upload to legal hold storage
aws s3 sync legal-hold-ci-logs/ \
  s3://${FORENSICS_BUCKET}/legal-hold/${MATTER_ID}/ci-logs/
```

### HashiCorp Vault Audit Log

```bash
# Export Vault audit log for the hold period
# (assumes audit log is already in SIEM — export from SIEM query)

# Vault audit log backup from SIEM (Splunk example)
curl -s -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
  "${SPLUNK_URL}/services/search/jobs" \
  -d "search=search index=vault earliest=${HOLD_START_EPOCH} latest=${HOLD_END_EPOCH}&output_mode=json" \
  | jq -r '.sid' \
  | xargs -I {} curl -s -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
    "${SPLUNK_URL}/services/search/jobs/{}/results?count=0&output_mode=json" \
  > vault-audit-legal-hold.json

aws s3 cp vault-audit-legal-hold.json \
  s3://${FORENSICS_BUCKET}/legal-hold/${MATTER_ID}/vault/
```

---

## Coordination with Legal Counsel and External Forensics Firms

### Engaging Legal Counsel

When a legal hold trigger condition is met:

1. **Call** Legal Counsel immediately. Do not email, text, or Slack. Phone calls with attorneys are more likely to be protected by attorney-client privilege.
2. **Do not respond** to any external inquiry (law enforcement, regulator, opposing counsel) before speaking with Legal Counsel.
3. **Do not disclose** the existence of the investigation or legal hold to anyone outside the IR team and Legal Counsel without Legal Counsel's direction.
4. **Preserve everything**. Until Legal Counsel defines the scope, treat everything related to the incident as potentially subject to hold.

### Engaging External Forensics Firms

External forensics firms (Mandiant, CrowdStrike, KPMG Forensics, or equivalent) may be engaged when:
- The organization lacks internal forensics capability at the required depth
- Independence is required (regulatory or litigation context)
- The incident is of sufficient severity that an independent assessment is needed for credibility
- Law enforcement requires engagement of an approved firm

**Before engaging an external firm**:

```
[ ] Legal Counsel has approved the engagement
[ ] The firm has been cleared for access to the organization's systems (background check, NDA)
[ ] An engagement letter defining scope, access rights, and evidence handling is signed
[ ] The firm's findings are directed to Legal Counsel (to preserve privilege)
[ ] A dedicated environment for the firm's access is provisioned (do not give production admin access)
[ ] All firm actions will be logged (their access to evidence must be part of the chain of custody)
```

### Providing Evidence to Law Enforcement

If law enforcement presents a subpoena, warrant, or legal process requiring production of evidence:

1. **Contact Legal Counsel immediately** — before acknowledging receipt of the legal process to law enforcement.
2. **Do not produce evidence voluntarily** without Legal Counsel's direction — even if you believe it is the right thing to do.
3. Legal Counsel will determine whether to comply, challenge, or seek narrowing of the request.
4. If ordered to produce evidence, the chain of custody for produced evidence must be documented:

```
Evidence Production Log
=======================
Matter: ${MATTER_ID}
Production Date: ${DATE}
Produced To: ${LAW_ENFORCEMENT_AGENCY}, ${CASE_NUMBER}
Production Method: ${METHOD (secure file transfer, physical media, etc.)}
Evidence Produced:
  - ${EVIDENCE_ID}: ${DESCRIPTION}
  - ...
SHA-256 Manifest: ${MANIFEST_HASH}
Produced By: ${ATTORNEY_NAME}, ${LAW_FIRM} (on behalf of ${ORGANIZATION})
Engineering Contact: ${SECURITY_ENGINEER_NAME}
```

---

## The Escalation Matrix

The following matrix defines who makes decisions at each stage of a legal hold.

| Decision | Decision Maker | Must Consult | May Not Act Without |
|---|---|---|---|
| Whether to implement a legal hold | Legal Counsel | CISO, Engineering VP | Legal Counsel authorization |
| Scope of the legal hold | Legal Counsel | CISO, Security Engineering Lead | Legal Counsel direction |
| Extending retention beyond policy | Legal Counsel | Evidence Custodian | Legal Counsel authorization |
| Releasing a legal hold | Legal Counsel | CISO | Legal Counsel written release |
| Producing evidence to law enforcement | Legal Counsel | CISO, possibly Board | Legal Counsel authorization |
| Disclosing incident to regulator | Legal Counsel + CISO | External PR counsel | Legal Counsel + CISO joint decision |
| Engaging external forensics firm | Legal Counsel | CISO, CFO (budget) | Legal Counsel and CISO approval |
| Narrowing scope of legal hold | Legal Counsel | Evidence Custodian | Legal Counsel written direction |
| Destroying evidence under legal hold | Not permitted | — | Legal hold must be released first |

### Emergency Escalation Contacts

This section should be completed with your organization's specific contacts:

```
General Counsel / Legal Counsel:
  Primary: [NAME] | [DIRECT PHONE] | [SECURE EMAIL]
  Backup: [NAME] | [DIRECT PHONE] | [SECURE EMAIL]

CISO:
  Primary: [NAME] | [PHONE] | [EMAIL]
  On-call: [PAGERDUTY / ONCALL SCHEDULE URL]

Outside Legal Counsel (for regulatory and litigation matters):
  Firm: [LAW FIRM NAME]
  Partner: [NAME] | [PHONE] | [EMAIL]

External Forensics Firm (pre-approved):
  Firm: [FIRM NAME]
  Account Manager: [NAME] | [PHONE] | [EMAIL]
  Emergency Response Line: [PHONE]
```

---

## GDPR Considerations

### The Storage Limitation Conflict

GDPR Article 5(1)(e) requires that personal data be kept "no longer than is necessary for the purposes for which the personal data are processed" (storage limitation principle). A legal hold that requires retaining forensic evidence indefinitely may conflict with this principle when the evidence contains personal data of EU data subjects.

This conflict is real and requires a documented balancing exercise. The resolution framework:

**Step 1: Identify personal data in scope of the hold**

Forensic evidence may contain personal data in multiple forms:
- CloudTrail events that record actions by named employees
- Git history with author names and email addresses
- CI/CD logs that record developer usernames
- Kubernetes audit logs that record service account names and request details
- Agent tool call logs that include content from GitHub issues or Jira tickets (which may contain personal data)

**Step 2: Apply the legal obligation basis**

GDPR Article 6(1)(c) permits processing necessary for compliance with a legal obligation. If the legal hold is required by applicable law (a court order, regulatory requirement, or legal obligation), this provides a lawful basis for retention even beyond the normal storage limitation period.

Document this basis explicitly:
```
Legal Hold Basis:
  Legal obligation: [Court order / Regulatory requirement / Applicable law citation]
  Jurisdiction: [Country/jurisdiction]
  Expected duration of obligation: [Date or "until released by order"]
  Personal data categories affected: [List categories]
  Lawful basis for retention: GDPR Article 6(1)(c) — legal obligation
  Documented by: [Legal Counsel name and date]
```

**Step 3: Minimize personal data within the hold**

Where possible, apply the hold to aggregated or pseudonymized versions of evidence rather than the full personal data. However, do not pseudonymize or modify evidence in a way that impairs its forensic value — this decision must be made by Legal Counsel, not by engineering teams.

**Step 4: Data Subject Rights Requests During a Hold**

If a data subject exercises their right to erasure (Article 17) for data that is under legal hold:

1. The erasure request must be logged and responded to within the GDPR response timeline (30 days for acknowledgment).
2. The response must explain that the data is subject to legal hold under Article 17(3)(e) (necessary for the establishment, exercise, or defense of legal claims) or 17(3)(b) (compliance with a legal obligation).
3. Legal Counsel must review every erasure request that touches data under legal hold.
4. Do not delete data under legal hold to fulfill an erasure request without Legal Counsel authorization.

Template response to erasure request for data under legal hold:

```
Dear [Data Subject],

We have received your request to erase your personal data under Article 17 of the GDPR.

Some or all of the personal data you have requested to be erased is currently subject to a legal hold imposed in connection with [describe generically: a legal proceeding / regulatory investigation / compliance obligation] (Article 17(3)(b)/(e) of the GDPR). We are required by law to retain this data for the duration of the hold.

We will re-evaluate your erasure request upon resolution of the legal hold. We will notify you when the hold is released and process your request at that time, subject to any other applicable retention obligations.

Please contact our Data Protection Officer at [DPO contact] with any questions.
```

### GDPR and Law Enforcement Requests

An EU data subject's personal data may only be transferred to law enforcement outside the EU under the conditions of GDPR Chapter V (transfers to third countries) or under an applicable international legal assistance treaty (MLAT). A US law enforcement subpoena or warrant does not, by itself, authorize the transfer of EU personal data to US law enforcement. This requires consultation with Legal Counsel who has EU law expertise.

---

## Template: Legal Hold Notice for Engineering Teams

When a legal hold is implemented, the following notice must be sent to all engineering teams who manage systems in scope of the hold. This notice is sent by Legal Counsel (or by the CISO at Legal Counsel's direction).

```
LEGAL HOLD NOTICE — ACTION REQUIRED
=====================================

Matter Reference: ${MATTER_ID}
Date of Notice: ${DATE}
Issued by: [LEGAL COUNSEL NAME], [TITLE]

SUMMARY
This is a legal hold notice. You are required to take immediate action to preserve
certain information that may be relevant to [a legal proceeding / regulatory inquiry /
investigation] (the "Matter"). The specific nature of the Matter is [describe generically
or as directed by Legal Counsel].

YOU MUST NOT:
- Delete, modify, move, or transfer any information described below
- Apply any routine data destruction, archival, or cleanup processes to the systems in scope
- Discuss this notice outside the team members listed below
- Respond to any external inquiry about this matter without first consulting Legal Counsel

YOU MUST:
- Immediately suspend all automated deletion and archival for the systems and data listed below
- Confirm in writing (by reply to this notice) that you have received and understood this notice
- Report any changes to, or loss of, preserved data immediately to [LEGAL COUNSEL CONTACT]

SYSTEMS AND DATA IN SCOPE
[Legal Counsel will specify the exact scope. Example format:]

1. AWS CloudTrail logs — [account IDs] — all logs from ${START_DATE} through present
2. Kubernetes audit logs — [cluster names] — all logs from ${START_DATE} through present
3. GitHub repositories — ${ORG}/${REPO} — all branches, history, PRs from ${START_DATE}
4. CI/CD pipeline logs — [platform, org/repo] — all runs from ${START_DATE}
5. HashiCorp Vault audit log — [cluster name] — all entries from ${START_DATE}

ACTIONS REQUIRED BY ENGINEERING TEAMS:
For each system in scope:
1. Confirm to [LEGAL HOLD CUSTODIAN] that automated deletion/archival has been suspended
2. Identify any data in scope that was deleted or archived after ${START_DATE}
3. Report any inability to preserve data in scope immediately

For AWS S3 buckets in scope:
- Apply S3 Object Lock Legal Hold to all in-scope objects
- Disable any lifecycle rules that would delete or archive in-scope data
- Command: [see implementing-legal-hold.md, Section "AWS S3"]

For GitHub repositories in scope:
- Enable force-push protection on all branches
- Export full repository mirror immediately
- Disable any automated branch cleanup or PR/issue deletion

QUESTIONS
Direct all questions about this notice or its scope to:
Legal Counsel: [NAME] | [PHONE] | [EMAIL]
Legal Hold Custodian: [NAME] | [PHONE] | [EMAIL]

Do not take any action based on this notice without consulting Legal Counsel if you
are uncertain about whether a specific action is required or prohibited.

CONFIRMATION REQUIRED
Please reply to [EMAIL] by [DATE/TIME] confirming that:
(a) You have received this notice
(b) You have identified all systems in scope under your management
(c) You have suspended automated deletion and archival for those systems
(d) You have noted any data that cannot be fully preserved

Failure to respond is not excused by operational burden. Contact Legal Counsel
immediately if you believe compliance will affect production operations.
```
