# provider-safe-ip

Curated, auto-updating lists of major providers' **own service IP ranges**,
meant to be consumed as **exclusions (allowlist carve-outs)** by IP blocklists
such as [`bitwire-it/ipblocklist`](https://github.com/bitwire-it/ipblocklist).

The point: a blocklist's `DROP` rules should never break legitimate provider
traffic (github.com, google.com, Microsoft 365, Apple, Meta, Telegram, Stripe
webhooks, Okta logins, Googlebot, …). Feed `all-safe.txt` into your blocklist as
an allowlist and those providers stay reachable while everything else is still
filtered.

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
  customer service tags, GitHub Actions / Dependabot / Copilot runner ranges,
  Datadog Synthetics *private locations*, Google's App Engine-hosted fetchers.
  The one deliberate exception is a handful of `/28`s that Google publishes as
  *crawler* addresses even though they sit in `cloud.json` — Google naming them
  as its own crawler fleet is authoritative, and the carve-back is a few dozen
  addresses, not a cloud region.
- ⚠️ **Shared CDN / proxy edges** (Cloudflare, Fastly, CloudFront, bunny.net,
  Zscaler) are a gray zone: they proxy third-party sites — including abusive
  ones. These are generated into **separate, opt-in files** and are **NOT** in
  `all-safe.txt`.
- ⚠️ **Third-party-intent traffic from provider-owned IPs** is the same gray
  zone, and it is the reason the AI feeds are split. A scheduled crawler
  (GPTBot, Googlebot, PerplexityBot, bingbot) fetches on the *provider's* own
  initiative → safe. A user-triggered fetcher (ChatGPT-User, Perplexity-User)
  fetches *because an arbitrary third party asked it to* → opt-in, exactly like
  an egress proxy. Same for Atlassian, whose egress pool is shared with Forge
  apps (third-party code) and Bitbucket Pipelines.

Only sources the **provider itself publishes** are ingested. No scraping HTML
support pages, no third-party gists, no "cloud IP aggregator" sites. Where a
provider publishes nothing machine-readable, it is listed under
[Not included](#not-included) rather than guessed at.

## How to consume (raw URLs)

Aggregate of all **safe** (non-CDN, non-proxy, non-user-triggered) provider
ranges — this is the one most consumers want:

```
https://raw.githubusercontent.com/bitwire-it/provider-safe-ip/main/lists/all-safe.txt
```

Per-provider files (same base path, `lists/<name>.txt`):

```
github.txt          google.txt          google-crawlers.txt   microsoft365.txt
bingbot.txt         apple.txt           meta.txt              telegram.txt
zoom.txt            okta.txt            stripe.txt            datadog.txt
duckduckbot.txt     openai.txt          perplexity.txt        aws-r53-healthchecks.txt
```

Opt-in (shared edge / proxy / user-triggered — **not** in `all-safe.txt`):

```
cloudflare.txt      fastly.txt          aws-cloudfront.txt    bunny.txt
zscaler.txt         atlassian.txt       anthropic.txt         openai-user-fetchers.txt
perplexity-user-fetchers.txt
```

Each file is plain text, one CIDR per line, IPv4 ranges first then IPv6,
collapsed and sorted ascending, with a trailing newline. Same source input
always produces byte-identical output, so `git` diffs are meaningful.

## Lists

### Safe — included in `all-safe.txt`

| List | Source | What it is / why it's safe |
|------|--------|----------------------------|
| `github` | [`api.github.com/meta`](https://api.github.com/meta) | GitHub's own infra: `hooks`, `web`, `api`, `git`, `pages`, `packages`, `github_enterprise_importer`, `importer`. **Excludes** `actions`, `dependabot`, `copilot` — those are customer/third-party workloads on shared Azure ranges. |
| `google` | [`goog.json`](https://www.gstatic.com/ipranges/goog.json) **minus** [`cloud.json`](https://www.gstatic.com/ipranges/cloud.json) | `goog` is everything Google announces; `cloud` is GCP customer ranges. `goog − cloud` (CIDR subtraction) leaves Google's own services — Search, Gmail front-ends, YouTube, crawlers. GCP customer compute stays out. |
| `google-crawlers` | [`common-crawlers.json`](https://developers.google.com/static/crawling/ipranges/common-crawlers.json) + [`special-crawlers.json`](https://developers.google.com/static/crawling/ipranges/special-crawlers.json) | Googlebot, AdsBot, APIs-Google, Google-Safety. Google's own fleets. Mostly a subset of `google`, but not entirely: the `goog − cloud` subtraction really does carve out crawler prefixes that also appear in `cloud.json` (at the last refresh, 23 of 95 — all `/28`s, one `/27`). Publishing the crawler feeds separately puts exactly those back, so Googlebot can never end up droppable. |
| `microsoft365` | [`endpoints.office.com/endpoints/worldwide`](https://endpoints.office.com/endpoints/worldwide) | The `ips` arrays from Microsoft's official M365 endpoints service (Exchange Online, SharePoint, Teams, …). **Does not** ingest Azure service tags (customer ranges). |
| `bingbot` | [`bing.com/toolbox/bingbot.json`](https://www.bing.com/toolbox/bingbot.json) | Microsoft's search crawler fleet, published by Microsoft for bot verification. Additive: the M365 feed does not contain it. |
| `apple` | ARIN WHOIS (`NET-17-0-0-0-1`) | `17.0.0.0/8`. Apple owns the entire legacy Class A block and uses it exclusively for its own services. Hardcoded — there is no per-service feed. Applebot's published ranges live inside this /8, so no separate list is needed. |
| `meta` | `whois -h whois.radb.net -- '-i origin AS32934'`, RPKI-validated objects only | facebook.com, instagram.com, whatsapp.com, threads.net + the Facebook crawler and webhook senders. AS32934 carries Meta's own production edge; Meta sells no compute on it. See [Meta and the IRR](#meta-and-the-irr) for why only RPKI-derived route objects are kept. |
| `telegram` | [`core.telegram.org/resources/cidr.txt`](https://core.telegram.org/resources/cidr.txt) | Telegram's published firewall list: its own datacenters, the Bot API, and the servers that call your registered bot webhook. |
| `zoom` | [`assets.zoom.us/docs/ipranges/Zoom.txt`](https://assets.zoom.us/docs/ipranges/Zoom.txt) | Zoom's published firewall list — Zoom's own meeting/media/web infrastructure, not customer compute. |
| `okta` | [`okta-ip-ranges/ip_ranges.json`](https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json) | Every Okta service cell (a tenant can live in any of them). Okta's own auth and hook-sender addresses; an SSO login dropped by a blocklist locks people out of everything. |
| `stripe` | [`ips_api.json`](https://stripe.com/files/ips/ips_api.json) + [`ips_webhooks.json`](https://stripe.com/files/ips/ips_webhooks.json) | Stripe's API endpoints and webhook senders, published for firewall allowlisting. Bare IPs, read as /32s. |
| `datadog` | [`ip-ranges.datadoghq.com`](https://ip-ranges.datadoghq.com/) | Datadog's own intake, webhook and Synthetics-probe addresses. **Excludes** `synthetics-private-locations` — those workers run inside the *customer's* network, not Datadog's. |
| `duckduckbot` | [`duckduckgo.com/duckduckbot.json`](https://duckduckgo.com/duckduckbot.json) | DuckDuckGo's own crawler addresses, published for bot verification. |
| `openai` | [`gptbot.json`](https://openai.com/gptbot.json) + [`searchbot.json`](https://openai.com/searchbot.json) | GPTBot and OAI-SearchBot: scheduled crawlers OpenAI runs itself. ChatGPT-User is **not** here (see opt-in). |
| `perplexity` | [`perplexitybot.json`](https://www.perplexity.com/perplexitybot.json) | PerplexityBot, Perplexity's scheduled crawler. Perplexity-User is **not** here (see opt-in). |
| `aws-r53-healthchecks` | [`ip-ranges.amazonaws.com/ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json), `service == "ROUTE53_HEALTHCHECKS"` | AWS's own Route 53 health-check probe sources — AWS infrastructure, not customer workloads. |

### Opt-in — separate files, **not** in `all-safe.txt`

| List | Source | Why it's opt-in |
|------|--------|-----------------|
| `cloudflare` | [`/ips-v4`](https://www.cloudflare.com/ips-v4) + [`/ips-v6`](https://www.cloudflare.com/ips-v6) | Shared CDN edge — proxies third-party (including abusive) sites. |
| `fastly` | [`api.fastly.com/public-ip-list`](https://api.fastly.com/public-ip-list) | Shared CDN edge — same gray zone as Cloudflare. |
| `aws-cloudfront` | [`ip-ranges.amazonaws.com`](https://ip-ranges.amazonaws.com/ip-ranges.json), `service == "CLOUDFRONT"` | Shared CDN that fronts third-party customer sites. |
| `bunny` | [`api.bunny.net/system/edgeserverlist`](https://api.bunny.net/system/edgeserverlist) | Shared CDN edge (flat array of bare edge IPs). |
| `zscaler` | [`config.zscaler.com/…/cenr/json`](https://config.zscaler.com/api/zscaler.net/cenr/json) | **Egress proxy.** Zscaler-owned IPs, but ZEN nodes carry many organizations' outbound traffic, so abuse can egress *through* Zscaler. |
| `atlassian` | [`ip-ranges.atlassian.com`](https://ip-ranges.atlassian.com/) | Jira/Confluence/Bitbucket/Trello/Opsgenie — but the feed's own tags show one **shared egress pool**: the same prefixes are tagged `forge` (Atlassian's platform running *third-party* app code) and `bitbucket` (whose egress includes Pipelines build runners). Opt in if you need Atlassian webhooks to survive. |
| `anthropic` | [`claude.com/crawling/bots.json`](https://claude.com/crawling/bots.json) | One undifferentiated file for ClaudeBot, Claude-SearchBot **and** Claude-User. Because the scheduled crawler cannot be separated from the user-triggered fetcher, the whole list is opt-in. |
| `openai-user-fetchers` | [`chatgpt-user.json`](https://openai.com/chatgpt-user.json) | ChatGPT-User fetches a URL because an arbitrary user or agent asked it to — provider-owned IPs, third-party-chosen targets. |
| `perplexity-user-fetchers` | [`perplexity-user.json`](https://www.perplexity.com/perplexity-user.json) | Same shape as ChatGPT-User. |

### Meta and the IRR

Meta publishes no HTTPS feed. The source Meta itself documents (in the
[crawler docs](https://developers.facebook.com/docs/sharing/webmasters/crawler/))
is an IRR query: `whois -h whois.radb.net -- '-i origin AS32934'`. The generator
runs exactly that query over TCP/43 with the standard library — and then keeps
**only RPKI-derived route objects**.

That filter is the whole point. Anyone can register a plain `route:` object in
RADB for a prefix they do not hold; an attacker registering one under
`origin: AS32934` would otherwise land their own range in this exclusion feed and
whitelist themselves past every downstream blocklist. RADB also mirrors the RPKI
into route objects (`source: RPKI # Trust Anchor: <rir>`), which come from ROAs
cryptographically signed by the address holder under an RIR trust anchor and
cannot be forged by a third party. We trade a little completeness for a feed that
cannot be poisoned, and the generator refuses to write a suspiciously short
result rather than silently shrinking.

Meta's corporate ASNs (AS54115, AS63293) are deliberately excluded: they carry
office/employee egress, not the services this feed exists to keep reachable.

## Coverage of the world's most-visited sites

The checklist below walks the ~30 most-visited sites worldwide
([Similarweb](https://www.similarweb.com/top-websites/); exact ranks move month
to month) and records what each one actually publishes. Most of the world's
biggest sites publish **nothing** machine-readable — that is a finding, not an
omission, and the honest answer is a domain-based allowlist for those.

| Site | Status | Where it comes from |
|------|--------|---------------------|
| google.com, youtube.com | ✅ full | `google`, `google-crawlers` |
| facebook.com, instagram.com, whatsapp.com | ✅ full | `meta` |
| chatgpt.com | ⚠️ crawlers only | `openai` — OpenAI publishes bot ranges; chatgpt.com itself is Cloudflare-fronted (see `cloudflare`, opt-in) |
| live.com, office.com, microsoftonline.com, microsoft.com | ✅ M365 services | `microsoft365` |
| bing.com | ⚠️ crawler only | `bingbot` — Microsoft publishes no serving-IP feed for bing.com |
| apple.com | ✅ full | `apple` (all of 17.0.0.0/8) |
| telegram.org | ✅ full | `telegram` |
| duckduckgo.com | ⚠️ crawler only | `duckduckbot` |
| github.com | ✅ full | `github` |
| zoom.us | ✅ full | `zoom` |
| x.com | ❌ none | X publishes no IP feed for its services or crawler |
| reddit.com | ❌ none | Fastly-fronted; only `fastly` (opt-in) would cover it, and that edge is shared |
| wikipedia.org | ❌ none | Wikimedia documents its allocations only as wiki prose (`wikitech.wikimedia.org`) — no machine-readable feed to ingest |
| amazon.com | ❌ none | `ip-ranges.json` describes AWS customer space, not the retail site; there is no amazon.com-only feed |
| netflix.com | ❌ none | No published range list (Open Connect appliances live in ISP networks) |
| linkedin.com | ❌ none | No published IP feed; LinkedInBot is verified by reverse DNS |
| tiktok.com | ❌ none | No published IP feed |
| yandex.ru, dzen.ru | ❌ none | `yandex.com/ips` is an HTML page, not a feed — scraping it is against this project's rules; Yandex verifies its robots by reverse DNS |
| baidu.com | ❌ none | Baiduspider is verified by reverse DNS only |
| yahoo.com | ❌ none | No published IP feed |
| twitch.tv | ❌ none | Runs on AWS customer space; no service-specific feed |
| naver.com, vk.com | ❌ none | No published IP feed |
| pinterest.com | ❌ none | No published IP feed |
| temu.com, weather.com | ❌ none | No published IP feed |
| adult-video portals (pornhub.com, xvideos.com, …) | ❌ none | No published IP feeds |

### Not included

Providers evaluated and deliberately skipped, because they publish no official
machine-readable IP feed and this project will not scrape HTML support pages or
ingest third-party gists. Where a provider is reachable another way, the
recommended alternative is noted.

- **Slack** — no official machine-readable IP feed for its own services (runs on
  cloud infra, explicitly declines to publish static ranges). Allowlist by
  domain if needed.
- **Zendesk / Salesforce** — their published "IP ranges" endpoints reject
  programmatic requests (HTTP 403); the ranges exist only inside login-gated or
  bot-blocked help articles. Allowlist by domain.
- **CrowdStrike** — the canonical Falcon cloud IP list is published only *behind
  the Falcon portal login* (`falcon.<region>.crowdstrike.com/documentation/…/
  cloud-ip-addresses`). The only machine-readable copies are third-party
  community gists, which this project will not ingest. Pull the list from your
  authenticated Falcon console, or allowlist by FQDN.
- **SentinelOne** — no published static IP list. Allowlisting is **domain/FQDN
  based** (`*.sentinelone.net`, region/tenant specific) over multi-cloud + CDN
  with dynamic IPs. Allowlist by domain.
- **Blackpoint Cyber** — no public IP/firewall documentation; connectivity
  requirements are provided only during onboarding/support. Nothing to ingest.
- **Huntress** — agent-to-cloud communication has **no static IPs** (runs on
  AWS/Azure/Cloudflare, dynamic); Huntress documents allowlisting by domain
  (`agent.huntress.io`, `eetee.huntress.io`, `update.huntress.io`,
  `eetee.huntresscdn.com`, plus `*.bugsnag.com`). The only static ranges are two
  `/28`s used for Huntress → *your* PSA/SIEM outbound, published solely in a
  bot-blocked support article that is actively changing during their AWS→Azure
  migration — not a stable machine-readable feed — so they are not tracked here.
- **Google's user-triggered fetchers** — `user-triggered-fetchers.json` leaves
  from shared App Engine (`*.gae.googleusercontent.com`) space where customer
  workloads also run, so it is excluded outright rather than made opt-in.
- **Azure service tags / GCP `cloud.json` / AWS `AMAZON`,`EC2`** — customer
  compute by definition. Never ingested, in any file.

## Layout

```
generators/<provider>.py   one generator per provider (standalone-runnable)
generators/_common.py      shared fetch/whois/parse/collapse/subtract/write helpers
generators/run_all.py      runs every generator + builds all-safe.txt
lists/<provider>.txt        committed output, one per provider
lists/all-safe.txt          aggregate of the SAFE lists only
tests/test_transforms.py    synthetic-payload unit tests for every transform
.github/workflows/update.yml  6-hourly refresh + commit
```

## Design notes / guarantees

- **Python 3 standard library only** (`urllib`, `socket`, `json`, `ipaddress`).
  No deps.
- **Fetches retry** 3× with exponential backoff and **fail loudly** — a
  silently empty exclusion feed would let blocked IPs through downstream. The
  whois path (Meta) has the same policy, plus a floor on the number of validated
  routes so a truncated read can't quietly shrink the feed.
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
- **Freshness matters more than it used to.** Several providers (OpenAI, Stripe,
  Okta, Anthropic, Perplexity, DuckDuckGo) publish addresses that sit *inside*
  a public cloud. Those are theirs today; once released they can be reassigned
  to another tenant. That is precisely why nothing here is hand-maintained and
  every list is regenerated from the provider's own feed every 6 hours.

## Running locally

```bash
# everything (writes lists/*.txt + all-safe.txt):
python3 generators/run_all.py

# a single provider:
python3 generators/google.py
python3 generators/meta.py      # needs outbound TCP/43 to whois.radb.net

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
