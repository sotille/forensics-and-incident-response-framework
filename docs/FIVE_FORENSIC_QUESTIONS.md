# The Five Forensic Questions Framework

For post-incident investigation of AI agent behavior, this framework prescribes asking five questions in sequence. Each builds on the previous answer.

## The five questions

### Question 1 — What did the agent do?

- Retrieve the agent's decision log for the incident time window
- Identify the specific actions taken (tool calls, outputs, side effects)
- Distinguish proposed actions (Auditor approved) from executed actions
- Output: a chronological action log

### Question 2 — What did the agent see?

- Retrieve the inputs that led to the actions
- Includes: user prompts, retrieved context (RAG), tool responses, prior conversation
- Verify input provenance (signed? tamper-evident?)
- Output: input context for each action in Q1

### Question 3 — Why did the agent decide that?

- Examine the agent's reasoning chain (if Chain-of-Thought logs available)
- Identify the prompt template, tools available, and policy constraints
- Determine if the agent followed its instructions or deviated
- Output: causal explanation for each action

### Question 4 — Did the controls work as designed?

- Verify Auditor Agent decisions for each action
- Check whether deterministic input validation was applied
- Check whether runtime policy enforcement evaluated the action
- Identify any control that should have caught but did not
- Output: control performance assessment

### Question 5 — What needs to change?

Based on the answers above, identify root causes and required changes:
- Prompt engineering changes (clarify instructions, add guardrails)
- Tool authorization changes (revoke, scope down)
- Policy engine changes (add deterministic rules)
- Auditor logic changes (close gap that was exploited)
- Model changes (escalate to model provider; consider model swap)

## Investigation workflow

```
Incident reported
       ↓
Q1: What did the agent do?       (15-30 min — log retrieval)
       ↓
Q2: What did the agent see?      (30-60 min — input reconstruction)
       ↓
Q3: Why did it decide that?      (60-120 min — reasoning analysis)
       ↓
Q4: Did controls work?           (30-60 min — control verification)
       ↓
Q5: What needs to change?        (variable — root cause + remediation plan)
       ↓
Document RCA + remediation backlog
```

## Required infrastructure

For this framework to be executable, the AI system MUST provide:

- [ ] Tamper-evident decision logs (Property 3 of Auditor Agent pattern)
- [ ] Input/context capture at decision time
- [ ] Auditor decision records
- [ ] Tool authorization records (which tools were available; which were called)
- [ ] Policy evaluation records

Without these, investigation degrades to guesswork. This is exactly why the Auditor Agent pattern requires Properties 1-4 — without them, you cannot answer Q4.

## Relationship to `ai-devsecops-framework`

The Five Forensic Questions framework assumes the controls described in `ai-devsecops-framework` are in place. If they are not, the investigation will identify "no controls existed" as the answer to Q4 — and Q5 should recommend implementing the Auditor Agent pattern.

## Reference cards

For incident-response teams, print this document as a one-page reference card. Use it as a standard investigation checklist.
