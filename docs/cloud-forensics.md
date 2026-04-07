# Cloud and Container Forensics

## Table of Contents

1. [The Ephemeral Evidence Problem](#the-ephemeral-evidence-problem)
2. [Pre-Termination Evidence Capture](#pre-termination-evidence-capture)
3. [Kubernetes Forensics](#kubernetes-forensics)
4. [AWS EC2 Forensics](#aws-ec2-forensics)
5. [Container Forensics](#container-forensics)
6. [Memory Forensics in Containers](#memory-forensics-in-containers)
7. [Lambda Forensics](#lambda-forensics)
8. [Cross-Reference: Cloud IR Playbooks](#cross-reference-cloud-ir-playbooks)

---

## The Ephemeral Evidence Problem

Traditional disk forensics assumes the disk exists when the investigator arrives. In cloud and container environments, this assumption fails in several ways:

**Container termination**: A pod evicted by the Kubernetes scheduler or a container that exits after processing a request takes all in-memory state and any files written to ephemeral storage with it. The container's filesystem diff — which would show every file modified since container start — is gone.

**Spot instance termination**: AWS Spot instances receive a 2-minute termination notice before the instance terminates and the EBS root volume is deleted. If no snapshot is taken in that window, the disk is gone.

**Lambda function lifecycle**: A Lambda function that executed during the compromise window has no disk at all. The only post-execution artifacts are CloudWatch Logs, X-Ray traces, and VPC Flow Logs (if the function ran in a VPC). There is no filesystem to image.

**Auto-scaled instances**: EC2 instances that are part of an Auto Scaling group may be terminated as part of normal scale-in operations, destroying evidence of any compromise that occurred on that instance.

The response to this reality is to move evidence collection earlier — before termination, not after. This section documents what to capture from each resource type and the commands to capture it.

---

## Pre-Termination Evidence Capture

The following evidence types must be captured before any termination, eviction, or restart of a suspected compromised resource. This is the standard "preserve before remediate" checklist for cloud and container resources.

### Container / Pod (Kubernetes)

```bash
# Preserve: pod specification and metadata
kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o yaml > pod-spec.yaml

# Preserve: full namespace state
kubectl get all -n ${NAMESPACE} -o yaml > namespace-state.yaml

# Preserve: events related to the pod (includes OOMKills, evictions, restarts)
kubectl get events -n ${NAMESPACE} \
  --field-selector involvedObject.name=${POD_NAME} \
  --sort-by='.lastTimestamp' > pod-events.yaml

# Preserve: process tree inside the container
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ps auxf > container-processes.txt
# If ps is not available in the container:
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ls -la /proc \
  | awk '{print $NF}' \
  | grep '^[0-9]' \
  | xargs -I{} sh -c \
    'echo "--- PID {} ---"; cat /proc/{}/cmdline 2>/dev/null | tr "\0" " "; echo' \
  > container-processes-alt.txt

# Preserve: open network connections
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ss -tulpn > container-network.txt
# Alternative if ss not available:
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- cat /proc/net/tcp > container-tcp-connections.txt

# Preserve: environment variables (may contain secrets injected at runtime)
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- env > container-env.txt

# Preserve: mounted secrets and configmaps (list only — do not export secret values in logs)
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- mount | grep -E "secret|configmap" > container-mounts.txt

# Preserve: container filesystem diff (files added/modified vs. base image)
# Requires access to the container runtime on the node
NODE_NAME=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.spec.nodeName}')

# For Docker runtime (legacy):
ssh ${NODE_NAME} docker diff ${CONTAINER_ID} > container-filesystem-diff.txt

# For containerd (typical in modern Kubernetes):
ssh ${NODE_NAME} crictl ps --name ${POD_NAME} -o json \
  | jq -r '.containers[0].id' \
  | xargs -I{} crictl inspect {} > container-inspect.json
```

### EC2 Instance

```bash
# 1. Create EBS snapshot of the root volume BEFORE termination
INSTANCE_ID=${1}

# Get all EBS volume IDs attached to the instance
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids ${INSTANCE_ID} \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' \
  --output text)

for VOLUME_ID in ${VOLUMES}; do
  # Create snapshot
  SNAPSHOT_ID=$(aws ec2 create-snapshot \
    --volume-id ${VOLUME_ID} \
    --description "Forensics snapshot: instance ${INSTANCE_ID}, volume ${VOLUME_ID}, incident ${INCIDENT_ID}" \
    --tag-specifications "ResourceType=snapshot,Tags=[
      {Key=forensics-incident-id,Value=${INCIDENT_ID}},
      {Key=forensics-timestamp,Value=$(date +%Y%m%d%H%M%S)},
      {Key=original-instance-id,Value=${INSTANCE_ID}},
      {Key=original-volume-id,Value=${VOLUME_ID}}
    ]" \
    --query 'SnapshotId' \
    --output text)

  echo "Snapshot created: ${SNAPSHOT_ID} for volume ${VOLUME_ID}"

  # Wait for snapshot to complete before proceeding
  aws ec2 wait snapshot-completed --snapshot-ids ${SNAPSHOT_ID}
  echo "Snapshot complete: ${SNAPSHOT_ID}"
done

# 2. Export instance metadata before termination
aws ec2 describe-instances --instance-ids ${INSTANCE_ID} \
  > instance-metadata-${INSTANCE_ID}.json

# 3. Export all security group rules
aws ec2 describe-instances \
  --instance-ids ${INSTANCE_ID} \
  --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' \
  --output text \
  | xargs aws ec2 describe-security-groups --group-ids \
  > instance-security-groups.json

# 4. Export IAM role policies
ROLE_NAME=$(aws ec2 describe-instances \
  --instance-ids ${INSTANCE_ID} \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \
  --output text \
  | sed 's/.*instance-profile\///')

aws iam get-instance-profile --instance-profile-name ${ROLE_NAME} > instance-iam-profile.json

# Get all policies attached to the role
ROLE=$(aws iam get-instance-profile \
  --instance-profile-name ${ROLE_NAME} \
  --query 'InstanceProfile.Roles[0].RoleName' \
  --output text)

aws iam list-attached-role-policies --role-name ${ROLE} > instance-role-policies.json
```

---

## Kubernetes Forensics

### Reconstructing What Happened in a Pod

The Kubernetes audit log is the primary evidence source for reconstructing actions taken against or by a pod. This query retrieves all API server events related to a specific pod:

```bash
# Query Kubernetes audit log for a specific pod (from SIEM)
# Adjust the query syntax for your SIEM (Splunk, Elastic, etc.)

# Splunk query example:
# index="k8s-audit"
# objectRef.namespace="${NAMESPACE}"
# objectRef.name="${POD_NAME}"
# | table _time, user.username, verb, objectRef.resource, responseStatus.code

# Using kubectl if audit log is still accessible on the API server:
# Note: This requires direct access to the audit log file on the control plane node

# Reconstruct exec events (attacker may have exec'd into the pod)
jq --arg pod "${POD_NAME}" --arg ns "${NAMESPACE}" '
  select(
    .objectRef.resource == "pods" and
    .objectRef.subresource == "exec" and
    .objectRef.name == $pod and
    .objectRef.namespace == $ns
  ) | {
    time: .requestReceivedTimestamp,
    user: .user.username,
    groups: .user.groups,
    command: .requestObject.command,
    response_code: .responseStatus.code
  }
' /var/log/kubernetes/audit/audit.log > pod-exec-events.json

# Find all secrets accessed in a namespace (indicates lateral movement or credential harvesting)
jq --arg ns "${NAMESPACE}" '
  select(
    .objectRef.resource == "secrets" and
    .objectRef.namespace == $ns and
    (.verb == "get" or .verb == "list") and
    .responseStatus.code == 200
  ) | {
    time: .requestReceivedTimestamp,
    user: .user.username,
    secret_name: .objectRef.name,
    verb: .verb
  }
' /var/log/kubernetes/audit/audit.log > namespace-secret-access.json

# Find RBAC changes that may represent privilege escalation
jq '
  select(
    .objectRef.resource | IN("clusterroles", "clusterrolebindings", "roles", "rolebindings")
  ) | {
    time: .requestReceivedTimestamp,
    user: .user.username,
    verb: .verb,
    resource: .objectRef.resource,
    name: .objectRef.name,
    namespace: .objectRef.namespace
  }
' /var/log/kubernetes/audit/audit.log > rbac-changes.json
```

### Isolating a Compromised Pod

Before terminating a compromised pod, isolate it to prevent ongoing harm while preserving the ability to observe and collect evidence:

```yaml
# Apply a network policy that blocks all ingress and egress from the pod
# Label the pod first: kubectl label pod ${POD_NAME} -n ${NAMESPACE} forensics-isolated=true
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: forensics-isolation
  namespace: ${NAMESPACE}
spec:
  podSelector:
    matchLabels:
      forensics-isolated: "true"
  policyTypes:
    - Ingress
    - Egress
  # No ingress or egress rules = deny all
```

```bash
# Apply isolation
kubectl label pod ${POD_NAME} -n ${NAMESPACE} forensics-isolated=true
kubectl apply -f forensics-isolation-networkpolicy.yaml

# Verify isolation is in effect
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- curl -s --max-time 3 https://example.com
# Should time out or refuse connection
```

### etcd State Export

In a Kubernetes control plane compromise, the etcd datastore may contain evidence of unauthorized changes to cluster state. Export etcd state before any remediation of the control plane:

```bash
# Export etcd snapshot (on control plane node)
ETCDCTL_API=3 etcdctl snapshot save /tmp/etcd-snapshot-$(date +%Y%m%d%H%M%S).db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key

# Verify the snapshot
ETCDCTL_API=3 etcdctl snapshot status /tmp/etcd-snapshot-*.db

# Export all secrets from etcd (requires etcd access, not kubectl)
ETCDCTL_API=3 etcdctl get /registry/secrets \
  --prefix=true \
  --keys-only \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  > etcd-secret-keys.txt
```

---

## AWS EC2 Forensics

### Instance Isolation via Security Group

Before imaging an EC2 instance, isolate it by replacing its security group with a forensics-isolation group that blocks all traffic:

```bash
# Create a forensics isolation security group
ISOLATION_SG_ID=$(aws ec2 create-security-group \
  --group-name forensics-isolation \
  --description "Forensics isolation: no inbound or outbound traffic" \
  --vpc-id ${VPC_ID} \
  --query 'GroupId' \
  --output text)

# Remove all default outbound rules from the isolation group
aws ec2 revoke-security-group-egress \
  --group-id ${ISOLATION_SG_ID} \
  --protocol all \
  --cidr 0.0.0.0/0

# Apply the isolation security group to the instance
# This replaces all existing security groups
NETWORK_INTERFACE_ID=$(aws ec2 describe-instances \
  --instance-ids ${INSTANCE_ID} \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' \
  --output text)

aws ec2 modify-network-interface-attribute \
  --network-interface-id ${NETWORK_INTERFACE_ID} \
  --groups ${ISOLATION_SG_ID}

echo "Instance ${INSTANCE_ID} isolated. Security groups replaced with ${ISOLATION_SG_ID}"
```

### CloudTrail Analysis for Instance Activity

```bash
# Find all CloudTrail events where the instance's IAM role was the actor
# First, find the instance's current role ARN
ROLE_ARN=$(aws ec2 describe-instances \
  --instance-ids ${INSTANCE_ID} \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \
  --output text)

# Get the role name from the instance profile ARN
ROLE_NAME=$(aws iam get-instance-profile \
  --instance-profile-name $(basename ${ROLE_ARN}) \
  --query 'InstanceProfile.Roles[0].RoleName' \
  --output text)

# Search CloudTrail for all actions taken using this role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="${ROLE_NAME}" \
  --start-time ${INCIDENT_START} \
  --end-time ${INCIDENT_END} \
  --output json \
  | jq '[.Events[] | {
    time: .EventTime,
    event: .EventName,
    source_ip: (.CloudTrailEvent | fromjson | .sourceIPAddress),
    user_agent: (.CloudTrailEvent | fromjson | .userAgent),
    resource: .Resources[0].ResourceName
  }]' > instance-cloudtrail-events.json

# Detect IMDS credential abuse:
# IMDSv2 tokens accessed from an IP other than the instance IP indicate credential theft
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --start-time ${INCIDENT_START} \
  --output json \
  | jq --arg instance_ip "${INSTANCE_PRIVATE_IP}" \
  '[.Events[] | .CloudTrailEvent | fromjson |
    select(.sourceIPAddress != $instance_ip and
           .userIdentity.type == "AssumedRole" and
           (.userIdentity.arn | contains("${ROLE_NAME}")))]'
```

### EBS Volume Analysis

After creating a forensic snapshot, mount it on a separate forensics instance for disk analysis:

```bash
# Create a forensics instance (use an AMI with forensics tools pre-installed)
# Never mount the original volume; always work from the snapshot

# Create a volume from the forensics snapshot
FORENSICS_VOLUME_ID=$(aws ec2 create-volume \
  --snapshot-id ${FORENSICS_SNAPSHOT_ID} \
  --availability-zone ${FORENSICS_INSTANCE_AZ} \
  --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[{Key=forensics-purpose,Value=read-only-analysis}]" \
  --query 'VolumeId' \
  --output text)

# Attach the volume to the forensics instance as a secondary drive
aws ec2 attach-volume \
  --volume-id ${FORENSICS_VOLUME_ID} \
  --instance-id ${FORENSICS_INSTANCE_ID} \
  --device /dev/sdf

# On the forensics instance: mount read-only
sudo mkdir -p /mnt/evidence
sudo mount -o ro,noexec /dev/xvdf1 /mnt/evidence

# Analyze the mounted filesystem
# Find recently modified files (within the incident window)
find /mnt/evidence -newermt "${INCIDENT_START}" -not -newermt "${INCIDENT_END}" \
  -type f | head -100

# Check for cronjobs, systemd services added by attacker
ls -la /mnt/evidence/etc/cron.d/
ls -la /mnt/evidence/etc/systemd/system/
ls -la /mnt/evidence/var/spool/cron/

# Check for attacker-added SSH keys
find /mnt/evidence/home /mnt/evidence/root -name "authorized_keys" \
  -exec ls -la {} \; \
  -exec cat {} \;

# Check bash history (may be wiped, but worth checking)
find /mnt/evidence/home /mnt/evidence/root -name ".bash_history" \
  -exec cat {} \;
```

---

## Container Forensics

### Docker-Based Containers

```bash
# Export the full container filesystem as a tar archive
# This captures the current state of the overlay filesystem (base image + runtime changes)
docker export ${CONTAINER_ID} > container-filesystem-$(date +%Y%m%d%H%M%S).tar

# Compute hash for chain of custody
sha256sum container-filesystem-*.tar > container-filesystem.sha256

# Inspect the running container (environment, mounts, networks)
docker inspect ${CONTAINER_ID} > container-inspect.json

# Get container logs
docker logs ${CONTAINER_ID} --timestamps > container-logs.txt

# Get filesystem diff (files changed from base image)
docker diff ${CONTAINER_ID} > container-diff.txt
# C = Changed, A = Added, D = Deleted
# A files in /tmp, /dev/shm, /var/tmp are particularly suspicious

# Export image layers for analysis (understand what is in the base image vs. runtime)
docker image save ${IMAGE}:${TAG} -o image-layers.tar
tar -tvf image-layers.tar  # list layer contents
```

### containerd (Kubernetes Standard)

```bash
# Get container ID from Kubernetes
CONTAINER_ID=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o json \
  | jq -r '.status.containerStatuses[] | select(.name == "${CONTAINER_NAME}") | .containerID' \
  | sed 's/containerd:\/\///')

# On the node where the pod runs:
# Inspect container details
crictl inspect ${CONTAINER_ID} > crictl-inspect.json

# Get container logs
crictl logs ${CONTAINER_ID} > crictl-logs.txt

# Get the container's filesystem snapshot (requires containerd snapshotter access)
# The container filesystem is in the snapshotter directory
SNAPSHOTTER=$(crictl inspect ${CONTAINER_ID} | jq -r '.info.snapshotKey')
# Path depends on snapshotter: typically /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/

# Alternative: use kubectl cp to extract specific files from the container
kubectl cp ${NAMESPACE}/${POD_NAME}:/path/to/suspicious/file ./extracted-file
```

---

## Memory Forensics in Containers

Traditional memory forensics (using tools like Volatility against a RAM image) requires capturing the full memory of a running system. In containers, this is significantly constrained:

### What Is and Is Not Possible

| Technique | Traditional VM | Container |
|---|---|---|
| Full RAM image | Yes (stop VM, image hypervisor memory) | No — containers share the host kernel; you cannot stop a single container to image only its memory |
| Process memory dump | Yes — ptrace-based tools (gcore) | Yes — if the container has ptrace capability and the tool is available inside |
| /proc/[pid]/maps | Yes | Yes — accessible from inside the container or from the host with the container's PID namespace |
| Kernel memory (rootkits) | Yes | No — kernel is shared; no per-container kernel memory |
| Heap analysis | Yes | Yes — with process dump |

### Capturing Process Memory from a Container

```bash
# Inside the container (requires ptrace capability):
# Get the PID of the suspicious process
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ps aux | grep ${SUSPICIOUS_PROCESS}

# Generate a core dump of the process
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- gcore -o /tmp/coredump ${SUSPICIOUS_PID}

# Copy the core dump out
kubectl cp ${NAMESPACE}/${POD_NAME}:/tmp/coredump.${SUSPICIOUS_PID} ./coredump-evidence

# Hash for chain of custody
sha256sum coredump-evidence > coredump-evidence.sha256

# Analyze with strings to find network addresses, URLs, credentials
strings coredump-evidence | grep -E "(http|ftp|ssh|key|password|token|secret)" | head -50

# From the host node (requires host PID namespace access):
# Find the process on the host
HOST_PID=$(cat /proc/$(crictl inspect ${CONTAINER_ID} | jq '.info.pid')/status | grep NSpid | awk '{print $2}')
sudo gcore -o /tmp/host-coredump ${HOST_PID}
```

### /proc Filesystem Evidence

```bash
# Read process command line (including any arguments that may contain injected commands)
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- cat /proc/${PID}/cmdline | tr '\0' ' '

# Read process environment (may contain injected environment variables)
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- cat /proc/${PID}/environ | tr '\0' '\n'

# Read file descriptors (shows open files, sockets, pipes)
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- ls -la /proc/${PID}/fd

# Read memory maps (identifies loaded libraries, mapped files, heap/stack regions)
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- cat /proc/${PID}/maps

# Read network connections in the process's network namespace
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- cat /proc/net/tcp \
  | awk 'NR>1 {print $2, $3, $4}' \
  | while read local remote state; do
      # Convert hex to decimal for the port
      echo "local: ${local} remote: ${remote} state: ${state}"
    done
```

---

## Lambda Forensics

Lambda functions present the most constrained forensic environment: no persistent disk, no persistent memory, execution time bounded, and only structured logs remain after the execution completes.

### Evidence Sources for Lambda

```bash
# 1. CloudWatch Logs (primary evidence source)
# Get all log streams for the function
aws logs describe-log-streams \
  --log-group-name "/aws/lambda/${FUNCTION_NAME}" \
  --order-by LastEventTime \
  --descending \
  --limit 50 \
  > lambda-log-streams.json

# Export logs for a specific execution (use the request ID as correlation key)
REQUEST_ID=${1}  # From alert or known invocation

aws logs filter-log-events \
  --log-group-name "/aws/lambda/${FUNCTION_NAME}" \
  --filter-pattern "\"${REQUEST_ID}\"" \
  --start-time $(($(date +%s) - 86400))000 \
  > lambda-execution-log.json

# 2. X-Ray traces (if X-Ray is enabled)
# Get trace IDs for the incident window
aws xray get-trace-summaries \
  --start-time ${INCIDENT_START} \
  --end-time ${INCIDENT_END} \
  --filter-expression "service(\"${FUNCTION_NAME}\")" \
  > xray-trace-summaries.json

# Retrieve full trace details
TRACE_ID=$(jq -r '.TraceSummaries[0].Id' xray-trace-summaries.json)
aws xray batch-get-traces --trace-ids ${TRACE_ID} > xray-trace-detail.json

# 3. VPC Flow Logs (if function runs in a VPC)
# Lambda functions in a VPC get ENIs — find the ENI for the function
aws ec2 describe-network-interfaces \
  --filters "Name=description,Values=*${FUNCTION_NAME}*" \
  --query 'NetworkInterfaces[*].{ENI: NetworkInterfaceId, IP: PrivateIpAddress, AZ: AvailabilityZone}' \
  > lambda-enis.json

# Query VPC Flow Logs for these ENIs
# (assuming Flow Logs are in S3 — query with Athena or download files)
for ENI in $(jq -r '.[].ENI' lambda-enis.json); do
  aws s3 ls \
    s3://${FORENSICS_BUCKET}/vpc-flow-logs/${VPC_ID}/ \
    --recursive \
    | grep $(date +%Y/%m/%d) \
    | awk '{print $4}' \
    | xargs -I{} aws s3 cp s3://${FORENSICS_BUCKET}/{} - \
    | gunzip \
    | grep ${ENI} \
    >> lambda-vpc-flow-logs.txt
done

# 4. CloudTrail for Lambda-specific API calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=${FUNCTION_NAME} \
  --start-time ${INCIDENT_START} \
  --end-time ${INCIDENT_END} \
  --output json \
  | jq '[.Events[] | {
    time: .EventTime,
    event: .EventName,
    actor: .Username,
    source_ip: (.CloudTrailEvent | fromjson | .sourceIPAddress)
  }]' > lambda-cloudtrail-events.json

# 5. CloudWatch Metrics anomalies
# High error rate, unusual invocation count, or duration spikes
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Errors \
  --dimensions Name=FunctionName,Value=${FUNCTION_NAME} \
  --start-time ${INCIDENT_START} \
  --end-time ${INCIDENT_END} \
  --period 300 \
  --statistics Sum \
  > lambda-error-metrics.json

aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=${FUNCTION_NAME} \
  --start-time ${INCIDENT_START} \
  --end-time ${INCIDENT_END} \
  --period 300 \
  --statistics Maximum Average \
  > lambda-duration-metrics.json
```

### Lambda Forensics: Execution Context Reuse

Lambda reuses execution contexts across invocations to improve performance. This means:
- In-memory state (global variables, file descriptors, /tmp filesystem) from one invocation may persist to the next invocation running in the same execution context
- A malicious first invocation may write to /tmp and have that file read by a subsequent legitimate invocation
- An attacker who can invoke the function with a payload that writes to the execution context can potentially affect future invocations

When investigating a Lambda compromise, look for:
- Unusual writes to `/tmp` (the only writable path available)
- Unusual outbound connections in VPC Flow Logs that correlate with specific invocations
- X-Ray subsegments that show unexpected external service calls

---

## Cross-Reference: Cloud IR Playbooks

This document covers the forensic evidence collection procedures for cloud and container environments. For the broader incident response context — severity classification, escalation procedures, and cross-domain correlation — see:

- [framework.md — The Six Investigation Domains](framework.md)
- [cloud-security-devsecops/docs/incident-response-playbooks.md](../../cloud-security-devsecops/docs/incident-response-playbooks.md) — Cloud incident response procedures
- [evidence-chain-of-custody.md](evidence-chain-of-custody.md) — Evidence packaging and chain of custody for cloud evidence
