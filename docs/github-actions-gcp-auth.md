# Keyless GCP Auth from GitHub Actions (Workload Identity Federation)

How this repo's pipeline authenticates to GCP **without any stored key**, by
impersonating a service account. Written as a walkthrough so it can be
reproduced on a new project/repo — substitute the values in the table below.

## Values used here

| Placeholder | Value in this setup |
|---|---|
| GCP project ID | `secret-351817` |
| GCP project **number** | `540460980762` |
| GitHub repo | `ahmed5598/cloud-security-agent` |
| Service account | `github-actions-ci@secret-351817.iam.gserviceaccount.com` |
| Pool / provider IDs | `github` / `github-provider` |

Get the project number with:
`gcloud projects describe PROJECT_ID --format='value(projectNumber)'`

## How the flow works

Every job run, in order:

1. GitHub mints a short-lived **OIDC token** for the job. It's signed by
   GitHub and contains claims about where it came from: `repository`,
   `ref` (branch), workflow name, etc.
2. The job sends that token to GCP's STS endpoint. Our **workload identity
   pool provider** is configured to trust GitHub's OIDC issuer — but only
   when the token's `repository` claim equals this repo.
3. GCP exchanges it for permission to **impersonate the service account**
   (allowed by an IAM binding on the SA), returning a ~1 hour access token.
4. The job now acts as the SA. `gcloud`, `gsutil`, Terraform, and client
   libraries all pick this up automatically via Application Default
   Credentials.

Contrast with the old approach — exporting a service account JSON key into a
GitHub secret — which leaves a long-lived, never-rotated credential sitting
in GitHub. Nothing here is stored; trust is established per-run.

## GCP-side setup (one time per project)

### 0. Enable required APIs

```bash
gcloud config set project secret-351817
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com
# Only needed because our demo step calls `gcloud projects describe`:
gcloud services enable cloudresourcemanager.googleapis.com
```

### 1. Create the service account the pipeline will impersonate

```bash
gcloud iam service-accounts create github-actions-ci --display-name="GitHub Actions CI"
```

This is the identity CI runs as. It starts with zero permissions.

### 2. Create the workload identity pool and OIDC provider

```bash
gcloud iam workload-identity-pools create github \
  --location=global --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location=global --workload-identity-pool=github \
  --display-name="GitHub OIDC" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository == 'ahmed5598/cloud-security-agent'"
```

Piece by piece:

- **Pool**: a container for external identities. One pool named `github`
  can serve many repos/providers.
- **`--issuer-uri`**: tells GCP whose token signatures to trust — GitHub's
  OIDC issuer.
- **`--attribute-mapping`**: copies claims from GitHub's token into GCP
  attributes. Mapping `assertion.repository` → `attribute.repository` is
  what lets IAM bindings and conditions refer to the repo name.
- **`--attribute-condition`**: **the critical security control.** Without
  it, *any* GitHub repository on github.com could authenticate through this
  provider. This condition rejects every token whose `repository` claim
  isn't exactly this repo. (You can restrict further, e.g.
  `assertion.ref == 'refs/heads/main'` to only allow the main branch.)

### 3. The impersonation grant

```bash
gcloud iam service-accounts add-iam-policy-binding \
  github-actions-ci@secret-351817.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/540460980762/locations/global/workloadIdentityPools/github/attribute.repository/ahmed5598/cloud-security-agent"
```

This is the binding that literally means *"identities from this pool whose
`repository` attribute is this repo may act as this service account."*
Both sides of the handshake are now in place: the provider decides which
tokens are valid, this binding decides what a valid token may impersonate.

Note the member is a `principalSet://` (a set of external identities
matching an attribute), and the path uses the project **number**, not ID.

### 4. Give the SA its actual permissions

```bash
gcloud projects add-iam-policy-binding secret-351817 \
  --member="serviceAccount:github-actions-ci@secret-351817.iam.gserviceaccount.com" \
  --role="roles/browser" --condition=None
```

`roles/browser` is a minimal read-only role, just enough for the demo step
to call `gcloud projects describe`. When the pipeline needs to do real work
(deploy, read buckets, `terraform apply`), grant those specific roles to
this SA. **The auth plumbing above never changes — only this step grows.**

## The CI file, explained

`.github/workflows/ci.yml`:

```yaml
name: CI                       # display name in the Actions tab

on:                            # triggers — when this workflow runs
  push:
    branches: [main]           # every push to main
  pull_request:                # every PR (opened/updated)

jobs:
  hello:                       # jobs run in parallel, each on a fresh VM
    runs-on: ubuntu-latest     # which VM image GitHub provisions
    steps:
      - name: Say hello
        run: echo "Hello, world!"

  gcp-auth:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write          # REQUIRED: lets this job request the OIDC
                               # token from GitHub. Forgetting this is the
                               # #1 cause of "unable to get ACTIONS_ID_TOKEN"
    steps:
      - name: Authenticate to GCP via Workload Identity Federation
        uses: google-github-actions/auth@v2
        with:
          # Full resource path of the provider — project NUMBER, not ID
          workload_identity_provider: projects/540460980762/locations/global/workloadIdentityPools/github/providers/github-provider
          # The SA to impersonate (step 3 above allows this)
          service_account: github-actions-ci@secret-351817.iam.gserviceaccount.com

      # Installs the gcloud CLI and points it at the credentials the
      # auth step wrote (Application Default Credentials)
      - uses: google-github-actions/setup-gcloud@v2

      - name: Prove who we are
        run: |
          gcloud auth list       # shows the SA as the active account
          gcloud projects describe secret-351817 --format="value(projectId,name)"
```

Things to remember about workflows generally:

- Each **job** runs on its own fresh, ephemeral VM (`runs-on` picks the
  image; containers are opt-in via `container:`). Jobs don't share state.
- The VM starts without your code — add `actions/checkout` as the first
  step in any job that needs the repo.
- The `permissions:` block scopes the job's GitHub token. Declaring it on a
  job (like here) replaces the defaults for that job, so `contents: read`
  must be restated alongside `id-token: write`.

## Troubleshooting (hit these ourselves)

- **First run fails with 403 right after setup** — IAM bindings take a
  minute or two to propagate. Just re-run the job.
- **`Cloud Resource Manager API has not been used in project ...`** — the
  API behind `gcloud projects describe` wasn't enabled. Fixed with
  `gcloud services enable cloudresourcemanager.googleapis.com`. Any GCP
  API the pipeline calls must be enabled on the project.
- **`unable to get ACTIONS_ID_TOKEN_REQUEST_URL`** — missing
  `id-token: write` in the job's `permissions`.
- **Invalid provider path** — using the project ID where the project
  number is required (provider path, `principalSet://` member).

## Teardown (undo everything)

```bash
gcloud iam service-accounts delete github-actions-ci@secret-351817.iam.gserviceaccount.com
gcloud iam workload-identity-pools delete github --location=global
```

(Deleted pools are soft-deleted for 30 days and can be restored.)
