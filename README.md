# Azure CSPM — Cloud Security Posture & Compliance Platform

A lightweight Cloud Security Posture Management (CSPM) tool for Azure. It
runs continuously and unattended in the cloud, scanning a subscription for
common misconfigurations, scoring the result against a resource-coverage-
weighted compliance model inspired by the CIS Azure Foundations Benchmark,
and tracking that score over time on a Grafana dashboard.

## Why this project

Commercial tools like Microsoft Defender for Cloud, Wiz, and Prisma Cloud
all do a version of this at enterprise scale. Building a scoped-down version
end-to-end — detection, scoring, storage, visualization, and unattended
deployment — is a concrete demonstration of the DevSecOps skill set: cloud
security fundamentals (least-privilege identities, network-restricted
access, secrets management), automation (Python, Azure SDK), and the full
DevOps toolchain (Docker, GitHub Actions, Terraform, Azure Container Apps).

It's also, honestly, a good demonstration of debugging real infrastructure
under pressure — this project's history includes working through Azure's
"Express" Container Apps tier silently dropping Job support, secret
propagation quirks in Container Apps, and CI/CD branch-trigger mismatches —
the kind of hands-on troubleshooting that a course project rarely forces you
into, but production systems always do.

## Architecture

```
 Azure subscription
        │  (read-only, Reader role)
        ▼
 Python scanner (pluggable checks) ──► Postgres Flexible Server
        │  runs continuously,               (scan_runs table,
        │  rescans every 6h                  full history)
        ▼                                        │
 CIS-style coverage score                         ▼
                                          Grafana (Azure Container App)
                                          — score trend, per-control
                                            compliance, findings detail

 GitHub Actions ──► builds + pushes both images ──► ghcr.io
 Terraform ──► provisions everything on Azure Container Apps
```

The scanner and Grafana both run as plain Azure Container Apps (not
Container App **Jobs** — this subscription's environment defaults to
Azure's "Express" tier, which doesn't support Jobs, so the scanner instead
loops and sleeps internally on a configurable interval).

## Running automatically

Once deployed, the scanner needs no manual triggering. It runs an initial
scan on startup, writes the result to Postgres, then sleeps for a
configurable interval (`SCAN_INTERVAL_SECONDS`, defaulting to 6 hours)
before scanning again — indefinitely, for as long as the Container App is
running. There's no cron job, no external scheduler, and nothing to
remember to kick off: the loop lives inside the container itself
(`LOOP_FOREVER=true`), and Azure keeps the single replica running.

To check on it without waiting for the dashboard:

```bash
az containerapp revision list --name cspm-scanner --resource-group cspm-rg -o table

CUSTOMER_ID=$(az monitor log-analytics workspace show --resource-group cspm-rg --workspace-name cspm-logs --query customerId -o tsv)
az monitor log-analytics query -w "$CUSTOMER_ID" --analytics-query "ContainerAppConsoleLogs_CL | where ContainerAppName_s == 'cspm-scanner' | order by TimeGenerated desc | take 30" -o table
```

A healthy run ends with a `Score: ...` line and a `[loop] sleeping ...`
message, with no traceback after it.

## What it checks

Six checks today, each mapped to a CIS Azure control and easy to extend —
adding a new one is a single file plus a one-line registration:

| Check | What it flags | Severity |
|---|---|---|
| `nsg-open-inbound` | NSG rules open to the internet on sensitive ports (SSH, RDP, DB ports) | Critical |
| `storage-public-access` | Storage accounts allowing public blob access or not enforcing HTTPS | High |
| `disk-encryption` | Managed disks with no encryption, or only platform-managed keys | High |
| `sql-firewall-open` | Azure SQL firewall rules allowing any IP address | Critical |
| `keyvault-public-access` | Key Vaults reachable from the public network, or without purge protection | High |
| `rbac-owner-at-subscription` | Individual users (not groups) holding Owner directly at subscription scope | High |

## Scoring methodology

Each check is treated as a **control**. A control's compliance is the
fraction of the resources it actually examined that passed:

```
compliance_i = 1 - (failed_resources_i / total_resources_i)
```

Controls are combined into a single 0-100 score, weighted by severity, so
the score reflects scale (ten broken resources score worse than one) without
falling back to an arbitrary per-finding point deduction:

```
score = 100 x sum(weight_i * compliance_i) / sum(weight_i)
```

Controls with zero applicable resources (e.g. no SQL servers in the
subscription) are excluded entirely — nothing to be compliant about. This is
the same family of method Microsoft's own Secure Score uses; it's a
resource-coverage compliance model, not a certified CIS conformance
percentage, and that distinction is worth stating plainly if you're
presenting this project.

## Tech stack

| Layer | Tool |
|---|---|
| Detection | Python, Azure SDK (`azure-identity`, `azure-mgmt-*`) |
| Storage | Azure Database for PostgreSQL – Flexible Server |
| Visualization | Grafana, provisioned as code (dashboards + datasource + alerting all baked into the image) |
| Containerization | Docker |
| CI/CD | GitHub Actions → GitHub Container Registry (GHCR) |
| Infrastructure | Terraform (`azurerm` provider) — Azure Container Apps, Postgres, identities, RBAC |
| Testing | `pytest`, `ruff` |

## Project layout

```
src/scanner/
  checks/          one file per rule, registered in checks/__init__.py
  scoring.py       resource-coverage compliance scoring
  storage.py       persists each run to Postgres
  main.py          entrypoint — loops forever on a configurable interval
tests/             pytest unit tests for scoring and check helpers
docker/            Dockerfile (scanner) and Dockerfile.grafana
grafana/
  dashboards/      the CSPM Overview dashboard, baked into the Grafana image
  provisioning/    datasource + alerting config, also baked in
terraform/         provisions everything on Azure (see below)
terraform/playground/  intentionally-insecure test resources, for validating checks safely
.github/workflows/ci.yml   lint, test, build, and push both images
```

## Running the tests

```bash
pip install ruff pytest
ruff check src tests
PYTHONPATH=src pytest -q
```

Both run in CI on every push and pull request.

## Deploying to Azure

Everything is provisioned by Terraform in `terraform/`. There's no
`terraform.tfvars.example` checked in — set these variables yourself in a
`terraform.tfvars` (already excluded from git by `.gitignore`) before
running `terraform apply`:

| Variable | Description |
|---|---|
| `subscription_id_to_scan` | The subscription the scanner reads (Reader role only) |
| `container_image` | Scanner image, e.g. `ghcr.io/<you>/azure-cspm-platform:<sha>` |
| `grafana_image` | Grafana image, e.g. `ghcr.io/<you>/azure-cspm-platform-grafana:<sha>` |
| `postgres_admin_user` | Postgres admin username (defaults to `cspmadmin`) |
| `postgres_admin_password` | Postgres admin password — **alphanumeric only**, avoid `@ : / %` and similar (they break connection-string parsing if not escaped consistently everywhere) |
| `grafana_admin_password` | Local Grafana admin password (fallback login) |
| `allowed_grafana_ip_ranges` | List of CIDRs allowed to reach Grafana at all, e.g. `["203.0.113.5/32"]` — find yours with `curl ifconfig.me`. Everything else is denied at the network level |
| `location` | Azure region (defaults to `westeurope`) — must be one your subscription is actually allowed to deploy to; check with your subscription's allowed-locations policy if you hit a `RequestDisallowedByAzure` error |
| `project_name` | Prefix for all resource names (defaults to `cspm`) |

Pin `container_image` and `grafana_image` to an exact commit SHA tag (not
`:latest`) — Azure Container Apps doesn't always re-pull an unchanged tag
string, so pinning to a SHA is the only way to guarantee Terraform's desired
state matches what's actually deployed.

```bash
cd terraform
terraform init
terraform apply
```

Outputs include `grafana_url` (only reachable from the IP ranges you
allowed) and `postgres_fqdn`.

**No existing Azure infrastructure to test the checks against?**
`terraform/playground/` provisions a small set of deliberately insecure
resources (an open NSG rule, a public storage account, an unencrypted disk)
so the checks have something real to catch. Always `terraform destroy` it
when you're done testing — never leave it running.

## Access control

- **Scanner identity**: a user-assigned managed identity with **Reader
  only** on the target subscription — a security tool should never need
  more access than it needs to read.
- **Grafana**: no public access by default. Reachable only from IP ranges
  explicitly listed in `allowed_grafana_ip_ranges`, plus a local admin
  password as a second layer. (An earlier version of this project used
  Azure AD app-based gating; that required Application Administrator rights
  in Entra ID that weren't available on this subscription's tenant, so
  network-level restriction was used instead — a reasonable real-world
  substitution when the "ideal" control isn't actually available to you.)
- **Secrets**: database credentials and registry tokens are Container App
  secrets, never plain environment values or committed files.

## Possible extensions

- Grafana alerting (Slack/Teams) on score drops or new critical findings
- Multi-subscription scanning with a per-subscription score
- Auto-remediation for a subset of checks, gated behind a dry-run flag
- A second cloud (AWS/GCP) behind the same scoring engine
