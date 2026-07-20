# provider-safe-ip

Curated, auto-updating lists of major providers' **own service IP ranges**,
meant to be consumed as **exclusions (allowlist carve-outs)** by IP blocklists
such as [`bitwire-it/ipblocklist`](https://github.com/bitwire-it/ipblocklist).

The point: a blocklist's `DROP` rules should never break legitimate provider
traffic (github.com, google.com, Microsoft 365, Apple, Zoom, …). Feed
`all-safe.txt` into your blocklist as an allowlist and those providers stay
reachable while everything else is still filtered.

> These lists are **not** a blocklist and are **not** a general allowlist for
> browsing. They are exclusion feeds: "don't ever drop these, they're the
> provider talking to you."

## The core principle: safe vs. shared

We include a range **only** if it is *exclusively the provider's own
infrastructure* — their websites, APIs, CDN front-ends for their own products,
mail servers, crawlers, webhook sources, health-checkers.

We **never** put ranges where third-party / customer workloads run into the
default list, because excluding those would blind your blocklist to real abuse:

- ❌ **No cloud customer compute** — AWS EC2, GCP compute (`cloud.json`), Azure
  customer service tags, GitHub Actions / Dependabot / Copilot runner ranges.
- ⚠️ **Shared CDN / proxy edges** (Cloudflare, Fastly, CloudFront, Zscaler)
  are a gray zone: they proxy third-party sites — including abusive ones. These
  are generated into **separate, opt-in files** and are **NOT** in
  `all-safe.txt`. Opt in only if you specifically trust that edge in front of
  your own infrastructure.

## How to consume (raw URLs)

Aggregate of all **safe** (non-CDN, non-proxy) provider ranges — this is the one
most consumers want:

```
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/all-safe.txt
```

Per-provider files (same base path, `lists/<name>.txt`):

```
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/github.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/google.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/microsoft365.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/apple.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/zoom.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/aws-r53-healthchecks.txt
```

Opt-in (shared edge / proxy — **not** in `all-safe.txt`):

```
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/cloudflare.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/fastly.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/aws-cloudfront.txt
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/zscaler.txt
```

Each file is plain text, one CIDR per line, IPv4 ranges first then IPv6,
collapsed and sorted ascending, with a trailing newline. Same source input
always produces byte-identical output, so `git` diffs are meaningful.

## Lists

### Safe — included in `all-safe.txt`

| List | Source | What it is / why it's safe |
|------|--------|----------------------------|
| `github` | [`api.github.com/meta`](https://api.github.com/meta) | GitHub's own infra: `hooks`, `web`, `api`, `git`, `pages`, `packages`, `github_enterprise_importer`, `importer`. **Excludes** `actions`, `dependabot`, `copilot` — those are customer/third-party workloads on shared Azure ranges. |
| `google` | [`goog.json`](https://www.gstatic.com/ipranges/goog.json) **minus** [`cloud.json`](https://www.gstatic.com/ipranges/cloud.json) | `goog` is everything Google announces; `cloud` is GCP customer ranges. `goog − cloud` (CIDR subtraction) leaves Google's own services — Search, Gmail front-ends, crawlers, etc. GCP customer compute stays out. |
| `microsoft365` | [`endpoints.office.com/endpoints/worldwide`](https://endpoints.office.com/endpoints/worldwide) | The `ips` arrays from Microsoft's official M365 endpoints service (Exchange Online, SharePoint, Teams, …). **Does not** ingest Azure service tags (customer ranges). |
| `apple` | ARIN WHOIS (`NET-17-0-0-0-1`) | `17.0.0.0/8`. Apple owns the entire legacy Class A block and uses it exclusively for its own services. Hardcoded — there is no per-service feed. |
| `zoom` | [`assets.zoom.us/docs/ipranges/Zoom.txt`](https://assets.zoom.us/docs/ipranges/Zoom.txt) | Zoom's published firewall list — Zoom's own meeting/media/web infrastructure, not customer compute. |
| `aws-r53-healthchecks` | [`ip-ranges.amazonaws.com/ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json), `service == "ROUTE53_HEALTHCHECKS"` | AWS's own Route 53 health-check probe sources — AWS infrastructure, not customer workloads. Safe to exclude so provider health checks aren't dropped. |

### Opt-in — separate files, **not** in `all-safe.txt`

| List | Source | Why it's opt-in |
|------|--------|-----------------|
| `cloudflare` | [`/ips-v4`](https://www.cloudflare.com/ips-v4) + [`/ips-v6`](https://www.cloudflare.com/ips-v6) | Shared CDN edge — proxies third-party (including abusive) sites. |
| `fastly` | [`api.fastly.com/public-ip-list`](https://api.fastly.com/public-ip-list) | Shared CDN edge — same gray zone as Cloudflare. |
| `aws-cloudfront` | [`ip-ranges.amazonaws.com/ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json), `service == "CLOUDFRONT"` | Shared CDN that fronts third-party customer sites. |
| `zscaler` | [`config.zscaler.com/api/zscaler.net/cenr/json`](https://config.zscaler.com/api/zscaler.net/cenr/json) | **Egress proxy.** Although the IPs are Zscaler-owned, ZEN nodes carry many organizations' outbound traffic, so abuse can egress *through* Zscaler. That is exactly the "third-party workloads" case — so it is opt-in, not safe. Opt in only if you trust Zscaler egress in your threat model. |

### Not included

- **Slack** — Slack does not publish an official machine-readable IP range feed
  for its own services (they run on cloud infra and explicitly decline to
  publish static ranges). Skipped rather than scraping unofficial gists.

## Layout

```
generators/<provider>.py   one generator per provider (standalone-runnable)
generators/_common.py      shared fetch/parse/collapse/subtract/write helpers
generators/run_all.py      runs every generator + builds all-safe.txt
lists/<provider>.txt        committed output, one per provider
lists/all-safe.txt          aggregate of the SAFE lists only
tests/test_transforms.py    synthetic-payload unit tests for every transform
.github/workflows/update.yml  6-hourly refresh + commit
```

## Design notes / guarantees

- **Python 3 standard library only** (`urllib`, `json`, `ipaddress`). No deps.
- **Fetches retry** 3× with exponential backoff and **fail loudly** — a
  silently empty exclusion feed would let blocked IPs through downstream.
- **Never writes an empty list**: a bad/partial fetch raises before write and
  the empty-list guard refuses to clobber a good committed file.
- **Dual-stack**: IPv4 and IPv6 collected and collapsed independently
  (`ipaddress.collapse_addresses` is single-family), output v4 then v6.
- **Defensive parsing**: non-IP strings (SSH keys, hostnames, coordinates,
  `null`s) are skipped via `try/except ValueError`, never regex guessing.
- **CIDR subtraction** (e.g. `goog − cloud`) uses `address_exclude` /
  `subnet_of` containment — never string comparison. Partial carves like
  `8.8.8.0/24 − 8.8.8.128/25 = 8.8.8.0/25` are exact.
- **Deterministic output**: collapsed, deduped, ascending per family — identical
  input yields byte-identical files.

## Running locally

```bash
# everything (writes lists/*.txt + all-safe.txt):
python3 generators/run_all.py

# a single provider:
python3 generators/google.py

# tests (no network needed):
python3 tests/test_transforms.py
```

## Automation

`.github/workflows/update.yml` runs every 6 hours (and on demand) on
`ubuntu-latest`, regenerates all lists, runs the unit tests, and commits changes
to `lists/*.txt` via
[`git-auto-commit-action`](https://github.com/stefanzweifel/git-auto-commit-action).
If any single provider fails, the others are still committed but the run is
marked red. A keep-alive step re-enables the schedule so GitHub doesn't
auto-disable it after 60 days of inactivity.
