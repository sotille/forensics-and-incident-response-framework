# AF-06 — Model Supply Chain Tampering Detected Post-Deployment

**Playbook ID:** AF-06  
**Domain:** Agent Forensics  
**Version:** 1.0 — 2026-04-08  
**Related playbooks:** AF-03 (Artifact Unknown Provenance), AF-05 (Multi-Agent Cascade Compromise), PS-01 (AI Supply Chain Attack)  
**Related framework docs:**  
- `forensics-and-incident-response-framework/docs/agent-forensics.md`  
- `forensics-and-incident-response-framework/docs/supply-chain-forensics.md`  
- `ai-devsecops-framework/docs/model-supply-chain.md`  
- `ai-devsecops-framework/docs/threat-intelligence.md`  
- `ai-devsecops-framework/docs/threat-model.md`  
- `software-supply-chain-security-framework/docs/framework.md`

---

## Purpose and Scope

This playbook governs the forensic investigation triggered when a model serving an AI agent shows evidence of tampering — including weight poisoning, version substitution, or unauthorized fine-tuning — that was detected after the model was deployed to a production or staging environment.

**Model supply chain tampering** includes:

- **Weight poisoning:** A model file (`.safetensors`, `.pt`, `.bin`, or other format) that was modified after attestation, or whose weights were altered during the supply chain to introduce backdoor behavior triggered by specific input patterns
- **Version substitution:** A different model version than the one authorized for deployment was loaded, either through a compromised model registry, a mutable tag overwrite, or a model cache poisoning attack
- **Unauthorized fine-tuning:** The model was fine-tuned on attacker-controlled data to alter its behavior for specific inputs, and the fine-tuned version was substituted for the authorized base model
- **Deserialization code execution:** A model file using a pickle-based format (`.pt`, `.pth`, `.pkl`) contained malicious serialized code that executed when the model was loaded into the agent runtime

**Post-deployment detection** means the tampering was discovered after the model was already serving production traffic. This is a higher-severity condition than pre-deployment detection because: (1) the agent may have taken actions influenced by the tampered model, (2) any artifacts produced by the agent during the contamination window are potentially tainted, and (3) the agent's behavioral baseline data collected during the contamination window is itself unreliable.

**Trigger conditions for this playbook:**

- `cosign verify` for the model artifact fails, or the signing identity does not match the authorized model registry identity
- Model digest does not match the digest recorded at deployment time (hash mismatch on `.safetensors` or other model file)
- ModelScan or equivalent deserialization scanner detects executable code in a model file
- Behavioral anomaly detection identifies that the model's output distribution has shifted significantly from the calibration baseline for the same inputs
- An agent powered by the model produced an output consistent with a known backdoor trigger pattern
- A model version tag was silently updated in the registry without a corresponding model signing event or changelog entry
- An integrity check job (scheduled model hash verification) reports a mismatch against the expected digest

**Out of scope:** Model performance degradation without evidence of tampering (use standard model monitoring). Agent misconfigurations where the model itself is intact but the system prompt or tool policy is incorrect.

---

## Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| Incident Commander | Declares incident severity (treat as Critical); owns decision to suspend agent service |
| Agent Forensics Investigator | Leads investigation; determines contamination window and scope of tainted actions |
| AI/ML Engineering | Provides model provenance records, registry access logs, fine-tuning pipeline audit trail |
| Platform Security | Assesses model registry security; identifies how tampering occurred |
| Application Security | Catalogs all agent actions during contamination window; assesses downstream impact |
| Legal / Compliance | Assesses notification obligations; regulatory impact of compromised AI system |

---

## Critical Precondition: Suspend the Agent Service Immediately

**BEFORE any other action:** Suspend the agent that is using the suspect model. Do not attempt to "swap" the model live — the operational priority is stopping the tampered model from processing further requests.

```bash
# Kubernetes: scale down the agent deployment
kubectl scale deployment ${AGENT_DEPLOYMENT} --replicas=0 --namespace=${NAMESPACE}
# Record the exact time of suspension
echo "Agent suspended at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /tmp/af06-timeline.txt

# AWS ECS: update service desired count to 0
aws ecs update-service --cluster ${CLUSTER} \
  --service ${AGENT_SERVICE} --desired-count 0
aws ecs wait services-stable --cluster ${CLUSTER} --services ${AGENT_SERVICE}

# GitHub Actions: disable the workflow
gh workflow disable ${WORKFLOW_FILE} --repo ${ORG}/${REPO}
```

Preserve the tampered model file BEFORE any remediation:

```bash
# Record digest of the suspect model
sha256sum ${MODEL_FILE} > /tmp/af06-suspect-model-digest.txt

# Copy to forensic evidence store (do NOT use the suspect model in any other context)
aws s3 cp ${MODEL_FILE} \
  s3://${FORENSIC_BUCKET}/af06/${INCIDENT_ID}/suspect-model-$(date +%Y%m%d).safetensors \
  --sse aws:kms

# Record provenance of the forensic copy
aws s3api put-object-tagging \
  --bucket ${FORENSIC_BUCKET} \
  --key "af06/${INCIDENT_ID}/suspect-model-$(date +%Y%m%d).safetensors" \
  --tagging 'TagSet=[{Key=incident,Value=af06},{Key=handler,Value=${INVESTIGATOR}},{Key=classification,Value=forensic-hold}]'
```

Seal the audit record:

```json
{
  "event_type": "forensic_investigation_start",
  "playbook": "AF-06",
  "model": {
    "name": "<model name>",
    "version_tag": "<tag>",
    "actual_digest": "<sha256:...>",
    "expected_digest": "<sha256:...>",
    "format": "safetensors|pytorch|gguf|other"
  },
  "agent_deployment": "<deployment name>",
  "agent_suspended_at": "<ISO-8601>",
  "contamination_window_start": "<ISO-8601 — when was the last known-good model active?>",
  "contamination_window_end": "<ISO-8601 — when was the suspect model suspended?>",
  "investigator": "<name>",
  "trigger": "<describe what triggered this investigation>"
}
```

---

## Phase 1 — Determining the Contamination Window

### 1.1 Establish When the Tampered Model Was Loaded

```bash
# Find the model load event in the agent initialization log
grep -E "model.load|model.initialize|loading model" ${AGENT_LOG_FILE} | \
  grep -v "error" | tail -50

# Check model version at deployment time
kubectl get deployment ${AGENT_DEPLOYMENT} \
  -o jsonpath='{.spec.template.spec.initContainers[].env[?(@.name=="MODEL_VERSION")].value}'

# Check when the model version tag was last updated in the registry
# (HuggingFace Hub or internal registry):
curl -s "https://${REGISTRY_HOST}/api/models/${ORG}/${MODEL_NAME}/tags" | \
  jq '.[] | select(.name == "${MODEL_TAG}") | {created: .createdAt, digest: .digest}'

# Compare the tag update time to the last confirmed model digest verification
grep "model_digest_verified" ${AGENT_AUDIT_LOG} | tail -10
```

**Contamination window:** From the time the suspect model was loaded (or the last known-good digest verification) to the time of agent suspension. All agent actions within this window are potentially influenced by the tampered model.

### 1.2 Answering the Five Forensic Questions for the Contamination Window

**Q1 — What did the agent do during the contamination window?**

```bash
# Retrieve all tool calls between contamination_window_start and contamination_window_end
jq '[.[] |
  select(.timestamp >= "${WINDOW_START}" and .timestamp <= "${WINDOW_END}") |
  {session_id: .session_id, turn: .turn, tool: .tool_name,
   operation: .operation, params: .params, timestamp: .timestamp}
] | sort_by(.timestamp)' agent-tool-calls.json

# Categorize by impact tier:
# - Read-only actions (low risk)
# - Write actions in non-production scopes (medium risk — review for data exposure)
# - Write actions in production scopes (high risk — full impact assessment required)
# - Actions that cannot be reversed (Critical — rollback/remediation required)
```

**Q2 — What was the agent instructed to do (across all sessions in the window)?**

```bash
# Retrieve system prompt for each unique session in the contamination window
jq '[.[] |
  select(.event_type == "session_start") |
  select(.timestamp >= "${WINDOW_START}" and .timestamp <= "${WINDOW_END}") |
  {session_id: .session_id, system_prompt_hash: .system_prompt_sha256,
   task: .task_description, timestamp: .timestamp}
]' agent-session-events.json | sort_by(.timestamp)

# Verify system prompt integrity for each session
# If system prompt hash does not match the expected hash in git, the prompt was tampered
git show HEAD:system-prompts/${AGENT_NAME}.txt | sha256sum
```

**Q3 — What data did the agent access during the contamination window?**

```bash
# Retrieve all data sources accessed (external reads, API calls, data fetches)
jq '[.[] |
  select(.timestamp >= "${WINDOW_START}" and .timestamp <= "${WINDOW_END}") |
  select(.tool_name | test("read|fetch|get|query|search|retrieve")) |
  {session_id: .session_id, tool: .tool_name, target: .params.target,
   data_classification: .params.data_classification, timestamp: .timestamp}
]' agent-tool-calls.json

# Flag any access to sensitive data sources
# (PII, credentials, production configuration, model weights)
```

**Q4 — What tools did the agent invoke, and with what parameters?**

Focus on tool invocations that could produce persistent effects (writes, deployments, commits, pushes):

```bash
# High-impact tool invocations during contamination window
jq '[.[] |
  select(.timestamp >= "${WINDOW_START}" and .timestamp <= "${WINDOW_END}") |
  select(.tool_name | test("commit|push|deploy|apply|create|delete|modify|send|publish")) |
  {session_id: .session_id, tool: .tool_name, operation: .operation,
   target: .params, timestamp: .timestamp, outcome: .outcome}
] | sort_by(.timestamp)' agent-tool-calls.json
```

**Q5 — What was the authorization basis for each high-impact action?**

For each high-impact action identified in Q4, verify the authorization chain:
- Was there a human-initiated task in the session?
- Was the action within the tool authorization policy?
- Was there an approval gate for irreversible actions, and was it properly cleared?
- Is the action consistent with the stated task, or does it deviate in a way consistent with a backdoor trigger?

---

## Phase 2 — Model Integrity Analysis

### 2.1 Static Analysis of the Tampered Model

```bash
# For pickle-based model files (.pt, .pth, .pkl): check for executable code
# ModelScan: detects unsafe deserialization in ML models
modelscan -p ${SUSPECT_MODEL_FILE}

# Compute weight hash per layer and compare to the authorized model
# (This requires access to the authorized model for comparison)
python3 -c "
import safetensors, hashlib, json
with safetensors.safe_open('${SUSPECT_MODEL_FILE}', framework='pt') as f:
    metadata = f.metadata()
    layers = {k: hashlib.sha256(f.get_tensor(k).numpy().tobytes()).hexdigest()
              for k in f.keys()}
print(json.dumps({'metadata': metadata, 'layer_hashes': layers}, indent=2))
" > /tmp/suspect-layer-hashes.json

python3 -c "
import safetensors, hashlib, json
with safetensors.safe_open('${AUTHORIZED_MODEL_FILE}', framework='pt') as f:
    layers = {k: hashlib.sha256(f.get_tensor(k).numpy().tobytes()).hexdigest()
              for k in f.keys()}
print(json.dumps(layers, indent=2))
" > /tmp/authorized-layer-hashes.json

# Identify layers with hash mismatches
diff /tmp/authorized-layer-hashes.json /tmp/suspect-layer-hashes.json
```

### 2.2 Behavioral Analysis (Backdoor Detection)

```bash
# Run the suspect model in isolation against known trigger patterns
# (in a sandboxed, network-isolated environment — do NOT use production systems)
# Document the inputs and outputs systematically

# Test for known injection/backdoor trigger patterns:
# 1. Inputs containing the model's known training data source format
# 2. Inputs containing administrative override phrases
# 3. Inputs containing the organization's internal identifiers

# Compare outputs from the suspect model vs. the authorized model for identical inputs
# Significant output divergence for specific input patterns indicates targeted backdoor
```

### 2.3 Registry and Distribution Forensics

```bash
# Determine how the tampered model entered the model registry
# Check registry push events during the window
aws ecr describe-image-scan-findings --repository-name ${MODEL_REPO} \
  --image-id imageDigest=${SUSPECT_DIGEST}

# Identify the identity that pushed the tampered model
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time ${WINDOW_START} --end-time ${WINDOW_END}

# Check if the model tag was mutable (did the same tag point to a different digest before?)
aws ecr describe-images --repository-name ${MODEL_REPO} \
  --image-ids imageTag=${MODEL_TAG} \
  --query 'imageDetails[].{Digest:imageDigest,Pushed:imagePushedAt}'
```

---

## Phase 3 — Blast Radius Assessment

### 3.1 Tainted Action Assessment

Assess each high-impact action from Q4 against the contamination window:

| Action | Session | Time | Within Policy? | Consistent with Task? | Impact Assessment |
|--------|---------|------|---------------|----------------------|-------------------|
| (from Q4) | | | | | |

**Tainted action classification:**

- **Within policy, consistent with task:** Likely legitimate; low risk of adversarial influence
- **Within policy, inconsistent with task:** Suspect — backdoor may have influenced the agent to take a legitimate but unintended action
- **Outside policy:** Unauthorized regardless of model state; investigate as AF-01 in addition

### 3.2 Artifacts Produced During Contamination Window

List all artifacts created by the agent during the contamination window. For each:

```bash
# Find all commit and push events in the window
jq '[.[] |
  select(.timestamp >= "${WINDOW_START}" and .timestamp <= "${WINDOW_END}") |
  select(.tool_name | test("commit|push|registry.push|deploy.trigger"))] |
  .params.commit_sha // .params.artifact_digest // .params.deployment_id
' agent-tool-calls.json
```

All identified artifacts should be treated as potentially influenced by the tampered model and subjected to independent integrity review before continued use. If artifacts were deployed to production, open an AF-03 investigation for each.

---

## Phase 4 — Containment and Remediation

### 4.1 Model Replacement

```bash
# Restore the last known-good model version
# Verify the authorized model digest before restoration
AUTHORIZED_DIGEST=$(cat /tmp/af06-authorized-model-digest.txt)
cosign verify-blob \
  --signature ${MODEL_SIGNATURE_FILE} \
  --certificate ${MODEL_CERT_FILE} \
  ${AUTHORIZED_MODEL_PATH}

# Update the deployment to use the verified model
kubectl set env deployment/${AGENT_DEPLOYMENT} \
  MODEL_DIGEST=${AUTHORIZED_DIGEST}
kubectl rollout restart deployment/${AGENT_DEPLOYMENT} --namespace=${NAMESPACE}
kubectl rollout status deployment/${AGENT_DEPLOYMENT} --namespace=${NAMESPACE}
```

### 4.2 Registry Hardening

| Gap | Required Control |
|-----|-----------------|
| Mutable model tag allowed overwrite | Configure registry to require immutable tags for production model versions |
| No digest-based verification at load time | Implement model digest check in agent initialization; reject if digest != expected |
| Model file in pickle format | Migrate to SafeTensors; implement ModelScan in model ingestion pipeline |
| No model signing at publication | Implement Cosign model signing in model CI/CD pipeline |
| Missing scheduled model integrity verification | Add cron job to verify model digest against registry attestation daily |

### 4.3 Model Supply Chain Pipeline Review

Review the full model supply chain for the contamination entry point:

- Was the base model downloaded from an external source? From where? With what integrity verification?
- Was the model fine-tuned? On what data? With what pipeline controls?
- Was the model registry access limited to authorized publishing identities?
- Were mutable tags enabled?
- Was there a signature verification step at model load time?

Reference: `ai-devsecops-framework/docs/model-supply-chain.md` — complete model supply chain security guide.

---

## Investigation Closure Requirements

The investigation is closed when all of the following are documented:

- [ ] Contamination window established: start and end timestamps confirmed
- [ ] Q1–Q5 analysis complete for the contamination window
- [ ] All high-impact agent actions during the contamination window assessed for adversarial influence
- [ ] All artifacts produced during the window identified and independently reviewed
- [ ] Tampered model preserved in forensic evidence store with chain of custody record
- [ ] Model tampering mechanism determined: weight poisoning, version substitution, deserialization attack, or other
- [ ] Registry entry point for tampered model identified
- [ ] Authorized model restored and verified
- [ ] Registry hardening controls implemented or tracked with owner and deadline
- [ ] Behavioral baseline invalidated for the contamination period; recalibration scheduled with clean model
- [ ] Post-incident report completed for: Technical audience, Executive summary, Legal/Compliance (if regulated data was processed)

---

## References

- [Five Forensic Questions Framework](five-questions-framework.md)
- [Agent Forensics Readiness Guide](readiness-guide.md)
- [agent-forensics.md](../agent-forensics.md) — AF-06 inline section with investigation context
- [supply-chain-forensics.md](../supply-chain-forensics.md) — SLSA provenance and Cosign verification for artifacts
- [ai-devsecops-framework/docs/model-supply-chain.md](../../../../ai-devsecops-framework/docs/model-supply-chain.md) — ML model supply chain security: threat model, signing, registry controls, ModelScan
- [ai-devsecops-framework/docs/threat-model.md](../../../../ai-devsecops-framework/docs/threat-model.md) — STRIDE applied to LLM systems; model supply chain threat categories
- [ai-devsecops-framework/docs/threat-intelligence.md](../../../../ai-devsecops-framework/docs/threat-intelligence.md) — AI-specific threat intelligence; model supply chain threat actor profiles
- [software-supply-chain-security-framework/docs/framework.md](../../../../software-supply-chain-security-framework/docs/framework.md) — ML-SBOM and model provenance controls (ML-1, ML-2)
