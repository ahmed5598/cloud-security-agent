# Keyless AWS Auth from GitHub Actions (OIDC → AssumeRole)

How to let a GitHub Actions pipeline assume an AWS IAM role **without any
stored access keys**, using the same OIDC mechanism as the GCP setup
(`github-actions-gcp-auth.md`). Substitute the values below.

## Values

| Placeholder | Example |
| --- | --- |
| AWS account ID | `123456789012` |
| GitHub repo | `ahmed5598/cloud-security-agent` |
| IAM role name | `github-actions-ci` |
| Region | `us-east-1` |

## How the flow works

1. GitHub mints a short-lived **OIDC JWT** for the job (claims: `sub`,
   `repository`, `ref`, `aud`, …), signed by
   `https://token.actions.githubusercontent.com`.
2. The job calls AWS STS **`AssumeRoleWithWebIdentity`**, passing the JWT
   and the ARN of the role it wants.
3. STS verifies the JWT's signature against GitHub's published public keys
   (trusted because you registered GitHub as an **OIDC identity provider**
   in IAM), then evaluates the role's **trust policy** conditions against
   the token's claims.
4. If they pass, STS returns **temporary credentials** (access key, secret
   key, session token — ~1 hour). The action exports them as env vars, so
   the AWS CLI, SDKs, and Terraform all just work.

Compared to GCP, AWS collapses two steps into one: there's no separate
"federated token then impersonate" hop — `AssumeRoleWithWebIdentity`
exchanges the JWT directly for role credentials.

### Concept mapping (GCP ↔ AWS)

| GCP | AWS |
| --- | --- |
| Workload identity pool + provider | IAM OIDC identity provider |
| Attribute condition on the provider | `Condition` block in the role's trust policy |
| Service account | IAM role |
| `roles/iam.workloadIdentityUser` binding | Trust policy `Principal: Federated` + conditions |
| SA's granted roles | Role's attached permissions policies |

## AWS-side setup (one time per account)

### 1. Register GitHub as an OIDC identity provider

```bash
aws iam create-open-id-connect-provider \
  --url "https://token.actions.githubusercontent.com" \
  --client-id-list "sts.amazonaws.com"
```

- One provider per issuer URL per account — if it already exists (another
  repo set it up), skip this step and reuse it.
- `--client-id-list` is the **audience** (`aud`) the JWT must carry.
  `sts.amazonaws.com` is what the official auth action requests.
- You may see docs mention a `--thumbprint-list`. AWS has ignored
  thumbprints for GitHub's issuer since mid-2023 (it trusts the root CA),
  so it can be omitted; some tooling still requires a dummy value.

### 2. Create the role with a trust policy

`trust.json` — this is the AWS equivalent of GCP's attribute condition
**and** the `workloadIdentityUser` binding combined:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:ahmed5598/cloud-security-agent:*"
        }
      }
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name github-actions-ci \
  --assume-role-policy-document file://trust.json
```

The `sub` condition is **the critical security control** (same role the
attribute condition played on GCP). Without it, any GitHub repo could
assume this role. The `sub` claim format:

- push to a branch → `repo:OWNER/REPO:ref:refs/heads/BRANCH`
- pull request → `repo:OWNER/REPO:pull_request`
- tag → `repo:OWNER/REPO:ref:refs/tags/TAG`

So `repo:ahmed5598/cloud-security-agent:*` allows any workflow in this
repo; tighten to `repo:...:ref:refs/heads/main` to allow only main-branch
pushes (then PR runs can't assume the role — often exactly what you want
for deploy roles).

### 3. Attach permissions

```bash
# Example: read-only, good for a first test
aws iam attach-role-policy \
  --role-name github-actions-ci \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

Same principle as GCP: the auth plumbing never changes; grow this step as
the pipeline needs real permissions (prefer a scoped inline policy over
broad managed ones).

## Workflow side

```yaml
jobs:
  aws-auth:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write        # lets the job request the OIDC token
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-ci
          aws-region: us-east-1

      - name: Prove who we are
        run: aws sts get-caller-identity
```

`get-caller-identity` should print an ARN like
`arn:aws:sts::123456789012:assumed-role/github-actions-ci/GitHubActions`
— the pipeline is the role, no key stored anywhere.

## Troubleshooting

- **`Not authorized to perform sts:AssumeRoleWithWebIdentity`** — the trust
  policy conditions didn't match. Check the `sub` pattern against how the
  workflow was triggered (PR runs have `pull_request` subs, not branch
  refs) and that `aud` is exactly `sts.amazonaws.com`.
- **`unable to get ACTIONS_ID_TOKEN_REQUEST_URL`** — missing
  `id-token: write` in the job's `permissions` (same as GCP).
- **Provider already exists** — one OIDC provider per URL per account;
  reuse it and just add more roles/conditions.
- IAM changes propagate in seconds on AWS (unlike GCP's minutes), so
  retries are rarely needed.

## Teardown

```bash
aws iam detach-role-policy --role-name github-actions-ci \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam delete-role --role-name github-actions-ci
aws iam delete-open-id-connect-provider \
  --open-id-connect-provider-arn arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
```
