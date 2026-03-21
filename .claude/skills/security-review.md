---
name: security-review
description: Analyze infrastructure code files in this project for cloud security issues, matching the agent's rule set and suggesting remediations.
---

Review the infrastructure code in this project for cloud security vulnerabilities.

Follow this process:

1. Identify all infrastructure/IaC files in the project (Terraform .tf, CloudFormation .json/.yaml, Kubernetes manifests, IAM policy documents, etc.). If the user specified a file or path, focus on that.

2. For each file, check for the following issues (these match the agent's rule set in `agent/rules.py`, plus common cloud security risks):

   **IAM**
   - Wildcard actions: `"Action": "*"` or `Action = "*"`
   - Wildcard resources: `"Resource": "*"`
   - Missing conditions on sensitive permissions
   - Overly permissive assume-role policies

   **S3**
   - Public ACLs: `public-read`, `public-read-write`, `acl = "public"`
   - `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets` set to false or missing
   - Server-side encryption disabled
   - Versioning disabled on buckets storing sensitive data

   **Networking**
   - Security groups open to `0.0.0.0/0` on sensitive ports (22, 3389, 5432, 3306, 27017, etc.)
   - VPCs without flow logs
   - Public subnets hosting databases or internal services

   **Secrets & Credentials**
   - Hardcoded secrets, API keys, passwords, or tokens in code
   - Unencrypted environment variables containing sensitive values

   **Encryption**
   - Unencrypted storage (EBS, RDS, S3)
   - Unencrypted data in transit (HTTP endpoints, disabled TLS)

   **Logging & Monitoring**
   - CloudTrail disabled or missing
   - Missing access logging on S3 or load balancers

3. For each finding, report:
   - **Severity**: CRITICAL / HIGH / MEDIUM / LOW
   - **Rule**: short identifier (e.g., `IAM_WILDCARD_ACTION`)
   - **File & line**: where the issue appears
   - **Why it matters**: 1-2 sentences on the security impact
   - **Remediation**: concrete fix with a code snippet if applicable

4. End with a summary table of all findings grouped by severity.

Be concise and actionable. If no issues are found, say so clearly.
