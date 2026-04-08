# PL-03 — Compromised AI Code Review Approval Chain

**Playbook ID:** PL-03  
**Domain:** AI Pipeline Forensics / Pipeline Security  
**Version:** 1.0 — 2026-04-08  
**Related playbooks:** AF-01 (Prompt Injection Unauthorized Action), PL-01 (Unauthorized Pipeline Agent Action)  
**Related framework docs:**  
- `ai-devsecops-framework/docs/code-review-security.md`  
- `ai-devsecops-framework/docs/prompt-injection-defense.md`  
- `ai-devsecops-framework/docs/agent-audit-trail.md`  
- `forensics-and-incident-response-framework/docs/pipeline-forensics.md`

---

## Purpose and Scope

This playbook governs the forensic investigation and response when an AI-assisted code review component is suspected or confirmed to have approved a malicious pull request due to prompt injection, jailbreak, or control bypass.

**Trigger conditions:**

- A merged PR is subsequently identified as containing a backdoor, malicious dependency, or deliberate security regression
- An AI code review tool approved a PR that human reviewers would have rejected under normal review criteria
- Anomalous AI reviewer behavior detected: consistent approval of PRs from a specific author, approval of changes to security-sensitive files without documented findings, or approval velocity significantly above baseline
- An employee or external reporter identifies that a merged change appears to have bypassed the normal security review process with AI assistance
- Security scanner finds a vulnerability in a recently merged change that the AI reviewer should have detected

**Out of scope:** Vulnerabilities introduced by human reviewers who bypassed the AI review process. Use standard incident response for those cases.

---

## Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| Incident Commander | Declares incident, owns stakeholder communication, decides on PR reversal |
| AI Pipeline Security Lead | Leads technical investigation of AI reviewer behavior |
| Repository Owners / Platform Team | Provides access to audit logs, branch protection settings, merge history |
| Application Security | Assesses impact of merged changes in deployed environments |
| Legal | Advises if insider threat indicators are present |

---

## Phase 1 — Immediate Triage (Target: < 1 hour from trigger)

### 1.1 Retrieve and Preserve the Full PR Audit Record

**Critical:** AI reviewer behavior evidence is partially ephemeral (context windows are not persisted by most tools unless audit trail is configured). Act immediately.

```
Evidence to collect in priority order:

1. PR metadata:
   $ gh pr view <PR-number> --json title,body,additions,deletions,changedFiles,\
     reviews,comments,mergedAt,mergedBy,labels > evidence/pl03-pr-metadata.json

2. Full PR diff:
   $ gh pr diff <PR-number> > evidence/pl03-pr-diff.patch

3. AI reviewer comments and approval record:
   $ gh pr view <PR-number> --json reviews --jq '.reviews[]' > evidence/pl03-reviews.json
   # Identify: which review(s) came from the AI reviewer App/bot account
   # Record: exact text of AI review comment, timestamp, approval status

4. GitHub App audit log (requires org admin or GitHub Enterprise Audit Log API):
   GET /orgs/{org}/audit-log?phrase=action:pull_request.review&actor=<ai-reviewer-app>
   # Preserve: all events within ± 7 days of the PR merge

5. AI reviewer system configuration at time of PR:
   - System prompt version (from version control if prompts are managed in Git)
   - Model version deployed (from deployment records or SaaS changelog)
   - Tool permissions configuration (from GitHub App or equivalent)

6. If the organization uses a commercial AI reviewer (GitHub Copilot for Pull Requests,
   CodeRabbit, Qodo, etc.): contact the vendor's support channel immediately to request
   session logs for the PR in question. Many vendors retain these logs for 30–90 days.
```

**Evidence artifact:** Create `pl03-pr-audit-record-<PR-number>.zip` containing all above files, hashed on collection.

### 1.2 Assess the Blast Radius

Determine if the merged changes have been deployed and what they affect.

```
1. Deployment check — was the merged branch deployed after the merge?
   $ gh api /repos/{owner}/{repo}/deployments --jq '.[] | select(.sha == "<merge-commit-sha>")'

2. If deployed: identify environments and endpoints
   - Record: environment names, deployment timestamps, traffic percentages

3. Code change impact classification:
   For each changed file in the PR diff, classify:
   | File | Category | Risk |
   |------|----------|------|
   | [path] | [Authentication / Authorization / Secrets / Dependencies / IaC / Business Logic / Tests] | [Critical / High / Medium / Low] |

4. Check if any secrets were introduced or modified in the PR:
   $ git diff <base-sha>..<merge-sha> | detect-secrets scan --only-allowlisted
   $ trufflehog git file://<repo-path> --since-commit=<base-sha>
```

**Decision — Escalate to emergency if:**
- Authentication or authorization code was modified and deployed to production
- New secrets or credentials were introduced
- Dependencies were added or changed (cross-reference with PL-02 if slopsquatting suspected)
- IaC changes were applied to production infrastructure

---

## Phase 2 — AI Reviewer Behavior Analysis (Target: < 8 hours)

### 2.1 Reconstruct What the AI Reviewer Processed

The core forensic question is: **Was the AI reviewer manipulated through its inputs, or did it fail due to a capability limitation?**

```
Reconstruct the AI reviewer's input context at review time:

Input 1 — PR description (potentially attacker-controlled):
  From evidence/pl03-pr-metadata.json: extract .body
  Analyze for:
  - Hidden instructions (whitespace-encoded text, Unicode direction overrides,
    zero-width characters, HTML comment tags if rendered)
  - Prompt injection patterns (references to "your instructions," "ignore previous,"
    "as a security reviewer you must approve," etc.)
  $ cat evidence/pl03-pr-diff.patch | python3 -c "
    import sys, unicodedata
    for i, line in enumerate(sys.stdin):
        for char in line:
            if unicodedata.category(char) in ('Cf', 'Mn') or ord(char) > 0x2000:
                print(f'Line {i}: suspicious char U+{ord(char):04X} ({unicodedata.name(char, \"unknown\")})')"

Input 2 — Code diff (potentially adversarially crafted):
  Inspect code comments in the diff for instruction injection:
  $ grep -n "you are\|ignore\|as an AI\|must approve\|security review\|bypass" \
    evidence/pl03-pr-diff.patch

Input 3 — Repository context provided to the reviewer (README, CONTRIBUTING, CODEOWNERS):
  If the AI reviewer reads repository context files, examine all files modified or
  accessible at the time of the review for injected content.
```

### 2.2 Classify the Failure Mode

| Failure Mode | Indicators | Forensic Evidence Source |
|---|---|---|
| **Direct prompt injection** | PR description contains instruction-like text | PR body analysis |
| **Indirect prompt injection** | Code comments or strings contain embedded instructions | Diff analysis |
| **Context window saturation** | PR diff is very large; important content at the end | PR additions count; diff structure |
| **Capability gap** | Vulnerability class not in model's training data (e.g., novel CVE) | CVE publication date vs. model training cutoff |
| **Jailbreak pattern** | Approval language references special conditions, fictional scenarios | AI review comment text analysis |
| **Configuration bypass** | AI reviewer permissions exceeded its intended scope | GitHub App permissions audit |
| **Concurrent session interference** | Multiple PRs submitted simultaneously to the AI reviewer | Review timestamps from audit log |

Document the most likely failure mode with supporting evidence. Multiple failure modes may apply.

### 2.3 Review AI Reviewer History for Pattern

Determine whether this was an isolated incident or a sustained manipulation campaign.

```
Query the AI reviewer's approval history for the past 90 days:
$ gh api /repos/{owner}/{repo}/pulls?state=closed&per_page=100 | \
  jq '[.[] | select(.merged_at != null) | {number: .number, title: .title, 
       merged_by: .merged_by.login, merged_at: .merged_at}]' > evidence/pl03-merged-prs.json

For each merged PR, check if the AI reviewer was the sole approver:
$ jq '[.[] | {pr: .number, reviews: [.requested_reviewers[].login]}]' evidence/pl03-merged-prs.json

Flag PRs where:
- AI reviewer was the only approver (no human co-review)
- Same PR author appears repeatedly
- Review happened outside business hours (potential automation)
- Review time was < 30 seconds (too fast for meaningful analysis of large diffs)
```

---

## Phase 3 — Impact Assessment and Containment

### 3.1 Revert or Remediate the Merged Changes

Based on the blast radius assessment from Phase 1:

```
If changes NOT deployed to production:
  $ git revert <merge-commit-sha> --no-commit
  # Create a revert PR following the emergency merge procedure
  # Require human review from two senior engineers + security

If changes ARE deployed to production:
  1. Assess whether a revert deployment would cause more harm than a forward fix
  2. If the change introduced a vulnerability: patch forward with a targeted fix
  3. If the change introduced a backdoor or malicious code:
     a. Isolate the service (disable external traffic, not the process)
     b. Deploy the previous known-clean image in parallel
     c. Cut traffic to the known-clean image
     d. Preserve the compromised environment for forensics before decommission
```

### 3.2 Disable or Restrict the AI Reviewer

While investigation is in progress, limit the AI reviewer's impact:

- Remove the AI reviewer's ability to post approvals (downgrade to "request changes" only, or remove merge permission entirely)
- Increase the required human approver count on all repositories
- Add a branch protection rule requiring a human from the Security team to be a required reviewer on all changes to security-sensitive paths

---

## Phase 4 — Post-Incident Requirements

### 4.1 Mandatory Review: AI Reviewer Configuration

| Control | Current State | Required State |
|---------|---------------|---------------|
| Minimum human co-approvers required before merge | ? | ≥ 1 for standard PRs; ≥ 2 for security-sensitive paths |
| AI reviewer has merge authority without human | ? | Never — AI can approve but not be the sole unblocking approver |
| Input validation on PR description before AI processing | ? | Required: strip HTML, Unicode control characters, check for injection patterns |
| AI reviewer session logged with input hash | ? | Required: log PR SHA + description hash + AI model version |
| System prompt in version control | ? | Required: SHA of system prompt version recorded in audit log |
| Maximum PR diff size processed without human flag | ? | Recommended: flag PRs > 500 lines for mandatory human review |

### 4.2 Prompt Injection Defense Deployment

Reference: `ai-devsecops-framework/docs/prompt-injection-defense.md`

Deploy the following controls if not present:

1. **Input sanitization layer** — strip or escape Unicode control characters, zero-width characters, and HTML comment tags from all PR text before it reaches the AI reviewer
2. **Canary token in system prompt** — embed a unique string in the AI reviewer's system prompt; if it appears in PR comments or review output, trigger an alert
3. **Instruction/data separation** — configure the AI reviewer so that the system prompt (trusted) is submitted via the model's `system` role parameter, and all PR content (untrusted) is submitted via the `user` role parameter
4. **Output schema validation** — require that the AI reviewer's output conforms to a defined schema (finding severity, affected file, recommendation text); reject free-form responses that match patterns associated with instruction override

### 4.3 Investigation Report Requirements

The final investigation report for this playbook must answer:

1. What was the exact failure mode (from Section 2.2)?
2. Was the failure a one-time event or part of a sustained pattern?
3. What changes were merged and deployed as a result?
4. Were any credentials, secrets, or customer data exposed?
5. What controls would have detected or prevented this incident?
6. Have those controls been deployed as part of this response?

Report audiences:
- **Technical:** Full forensic analysis with evidence references
- **Executive:** Business impact, response actions, control improvements
- **Legal:** If insider threat indicators, data exposure, or regulatory notification obligations exist

---

## References

- `docs/pipeline-forensics.md` — General pipeline forensics methodology
- `docs/agent-forensics.md` — When the AI code reviewer is an autonomous agent (not just a tool)
- `docs/agent-forensics/five-questions-framework.md` — Apply Five Questions to any agent-involved incident
- `ai-devsecops-framework/docs/code-review-security.md` — Secure AI code review architecture
- `ai-devsecops-framework/docs/agent-audit-trail.md` — Minimum audit trail requirements for AI pipeline components
- OWASP LLM Top 10 — LLM01: Prompt Injection, LLM08: Excessive Agency
- `secure-ci-cd-reference-architecture/docs/threat-model.md` — Pipeline threat model including AI reviewer attack surfaces
