# Lab 6 - Submission

## Environment and setup

Commands run:

```bash
git switch main
git switch -c feature/lab6
test -d .venv || python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install 'checkov>=3,<4'
checkov --version
docker --version
jq --version
mkdir -p labs/lab6/results
```

Observed versions:

```text
Checkov 3.3.2
Docker version 28.3.0, build 38b7060
jq-1.7.1-apple
KICS v2.1.20
```

Note: Checkov printed a warning that it could not fetch Prisma Cloud guideline metadata because local Python certificate validation failed for `api0.prismacloud.io`. The scan still completed and wrote JSON output, but the built-in Checkov failed-check `severity` fields were `null`; the tables below keep that as `UNSPECIFIED` so they match the actual JSON.

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

Command run:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

Observed summary from `labs/lab6/results/checkov-terraform/results_json.json`:

```text
terraform: passed=49 failed=78 skipped=0 parsing_errors=0 resource_count=16
secrets:   passed=0  failed=2  skipped=0 parsing_errors=0 resource_count=2
CHECKOV_TERRAFORM_EXIT=1
```

- Terraform IaC checks: 127
- Passed: 49
- Failed: 78
- Secret findings: 2 additional Checkov secret findings

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unspecified in JSON | 78 |

Command used for the Terraform top rules:

```bash
jq '[.[] | select(.check_type=="terraform") | .results.failed_checks[].check_id] |
    group_by(.) | map({rule: .[0], count: length}) |
    sort_by(-.count) | .[:5]' \
  labs/lab6/results/checkov-terraform/results_json.json
```

### Top 5 Terraform rule IDs by frequency

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | IAM policies must not allow permissions-management or resource-exposure actions without constraints. |
| `CKV_AWS_355` | 4 | IAM policy documents must not use `Resource: *` for actions that support resource scoping. |
| `CKV_AWS_288` | 3 | IAM policies must not allow data exfiltration paths. |
| `CKV_AWS_290` | 3 | IAM policies must not allow unconstrained write access. |
| `CKV_AWS_23` | 3 | Every security group and security group rule should have a description. |

### Pulumi scan

I ran Checkov against the Pulumi directory to verify the tool behavior described in the lab. Checkov 3.3.2 did not natively evaluate the Pulumi YAML/Python IaC structure here; it only emitted a secrets scan result.

Command run:

```bash
checkov -d labs/lab6/vulnerable-iac/pulumi \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-pulumi/
```

Observed summary:

```text
secrets: passed=0 failed=1 skipped=0 parsing_errors=0 resource_count=1
CHECKOV_PULUMI_EXIT=1
```

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unspecified in JSON | 1 |

The useful Pulumi IaC scan was done with KICS in Task 2, which matches the lab note that KICS has first-class Pulumi YAML support.

### Module-leverage analysis

The highest-leverage Terraform fix is an IAM policy module refactor. The top four rules are all IAM policy scope problems (`CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, `CKV_AWS_290`) and together account for 14 failed checks. If the IAM module generated least-privilege statements by default, denied `Action: *`, denied `Resource: *` where resource scoping exists, and required condition/resource constraints for write and permissions-management actions, one module-level change would close the largest cluster of findings.

## Task 2: KICS on Ansible + Pulumi

### KICS on Ansible

Command run:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ \
       -o /path/results/kics-ansible/ \
       --report-formats json,sarif
```

Observed summary:

```text
KICS version: v2.1.20
files_scanned=3
files_parsed=3
lines_scanned=309
total findings=10
KICS_ANSIBLE_EXIT=50
```

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top KICS Ansible queries by frequency

| Query | Severity | Results |
|-------|----------|--------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

Only four KICS query names fired for Ansible, so the top-5 table is complete with four rows.

### KICS on Pulumi

Command run:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/pulumi/ \
       -o /path/results/kics-pulumi/ \
       --report-formats json,sarif
```

Observed summary:

```text
KICS version: v2.1.20
files_scanned=1
files_parsed=1
lines_scanned=280
total findings=6
KICS_PULUMI_EXIT=60
```

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top KICS Pulumi queries by frequency

| Query | Severity | Results |
|-------|----------|--------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS - when to use which?

Checkov did better for the Terraform sample because it produced a deep AWS Terraform policy set with 78 IaC failures across RDS, IAM, S3, DynamoDB, and security groups. The top-rule frequency view is especially useful for module-level triage: the IAM cluster shows that fixing policy generation once would remove many findings across several resources.

KICS did better for the Ansible sample because it understood Ansible playbooks and inventory files directly and found secrets, password-in-URL issues, and an unpinned package version from three files. Checkov did not provide equivalent Ansible coverage in this lab flow, while KICS scanned both YAML playbooks and INI inventory as part of one IaC scan.

For Pulumi, KICS caught resource-level IaC issues such as `RDS DB Instance Publicly Accessible` and `DynamoDB Table Not Encrypted` in `Pulumi-vulnerable.yaml`. Checkov only reported a secret in the Pulumi directory, which demonstrates the trade-off from the lab: Checkov is strong for Terraform in this setup, while KICS has broader native format coverage for Pulumi YAML and Ansible.

## Bonus: Custom Checkov Policy

### Policy file

File: `labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 buckets define lifecycle configuration
  category: BACKUP_AND_RECOVERY
  severity: MEDIUM
definition:
  and:
    - cond_type: filter
      attribute: resource_type
      operator: within
      value:
        - aws_s3_bucket
    - cond_type: connection
      resource_types:
        - aws_s3_bucket
      connected_resource_types:
        - aws_s3_bucket_lifecycle_configuration
      operator: exists
```

### Rule fires

Command run:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-custom/
```

Observed summary:

```text
terraform: passed=49 failed=80 skipped=0 parsing_errors=0 resource_count=16
CHECKOV_CUSTOM_EXIT=1
```

Because Checkov 3.3.2 wrote a JSON array with both `terraform` and `secrets` sections, I used this filter to select the Terraform section:

```bash
jq '.[] | select(.check_type=="terraform") |
    .results.failed_checks[] |
    select(.check_id | startswith("CKV2_CUSTOM_")) |
    {check_id, check_name, resource, file_path, file_line_range, severity}' \
  labs/lab6/results/checkov-custom/results_json.json
```

Output:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure S3 buckets define lifecycle configuration",
  "resource": "aws_s3_bucket.public_data",
  "file_path": "/main.tf",
  "file_line_range": [13, 21],
  "severity": "MEDIUM"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure S3 buckets define lifecycle configuration",
  "resource": "aws_s3_bucket.unencrypted_data",
  "file_path": "/main.tf",
  "file_line_range": [24, 33],
  "severity": "MEDIUM"
}
```

### Why this rule matters

An S3 lifecycle policy is a project-specific governance guardrail: it enforces retention, expiration, and cleanup behavior instead of leaving buckets to retain data indefinitely. This reduces breach blast radius when object storage is exposed or over-permissioned, which was a major impact amplifier in public cloud incidents such as the 2019 Capital One S3 data breach. It also supports data minimization and retention expectations in controls such as NIST SP 800-53 SI-12 and privacy/compliance programs that require stale data to be removed on schedule.
