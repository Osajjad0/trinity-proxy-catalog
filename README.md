# Trinity proxy catalog

Candidate **public-source ProxyIP catalog** scraped from the public
[NiREvil/vless](https://github.com/NiREvil/vless) repository. No endpoint is ever
connected to, probed, or DNS-resolved by this pipeline: it reads published text
files and preserves what they claim, with provenance.

## What is collected

For a single immutable snapshot of `NiREvil/vless` (one `main` → commit SHA,
then all relevant files fetched at that same SHA):

- `sub/ProxyIP-Daily.md` — source-reported daily scanner results (provider and
  country sections; bare IPs; the scanner tested them against
  `speed.cloudflare.com` with certificate validation disabled — recorded, not
  re-verified).
- `sub/country_proxies/*.txt` (all 98 two-character files), `03_proxies.txt`,
  `02_proxies.csv`, `01_last_update.txt`, `edge/assets/p-legacies.csv`.

Daily rows are bare IPs, so their port comes from the **scanner's own input
precedence** (`02_proxies.csv`, then legacy CSV, deduped IP-only, first seen
wins) exactly as `edge/proxies-main.rs` does it. A daily IP with no public
first-seen port (secret-configured domains, DNS expansion) is listed in
`catalog/unresolved.json` — never guessed, and a malformed first-seen row is
never repaired from a later source. Duplicate IP rows across the daily
markdown's DNS-derived sections are **not** evaluated as duplicates; each row's
evidence is kept.

## Files

| Path | Content |
|---|---|
| `catalog/index.json` | counts, per-source provenance (URL, revision, sha256, size), content revision |
| `catalog/countries/<CC>.json` | endpoints whose country claims all agree |
| `catalog/conflicts.json` | endpoints claimed for 2+ different countries — quarantined, not decided |
| `catalog/unassigned.json` | nonstandard labels (`T1`, `TF`, …) and the three configured dynamic hosts, country **unassigned** |
| `catalog/unresolved.json` | daily IPs with no public first-seen port |
| `catalog/rejected.json` | malformed originals, rejected verbatim, never repaired |
| `sources.json` | configuration (dynamic hostnames + explicitly configured ports) |
| `scripts/build_catalog.py` | generator/validator (Python stdlib only) |
| `tests/test_catalog.py` | unittest suite |

Every endpoint row: `endpoint`, `address`, `port`, `kind` (IPV4/IPV6/HOST),
`country_claims`, `unrecognized_labels`, full `evidence` (source path, line,
verbatim original, source label, resolved-port mapping), `runtime_health:
"unknown"`, `trinity_verified: false`. There are **zero healthy claims** in
this catalog; no per-row check timestamp exists anywhere — sources are dated
only by source-reported `feed_generated_at` / `source_updated_raw` (raw string
preserved; not parsed into a checked-time claim) and `checked_at` is always
`null`.

The three dynamic hosts `bpb.yousef.isegaro.com`, `nima.nscl.ir`,
`turk.diam4.ggff.net` are user-requested candidates with port 443 **only as
explicitly configured** in `sources.json`, not as an upstream claim, and are
not assigned any country.

## Refresh

`python scripts/build_catalog.py` resolves `main` once, verifies git blob
hashes, rebuilds, validates (schema, counts, hashes, quarantine, health
invariants) and swaps `catalog/` atomically. Any required-source failure leaves
the previous catalog byte-for-byte intact and exits nonzero. Same snapshot ⇒
identical content (only `index.json.generated_at` differs); unchanged content
revision ⇒ no write. `--validate` checks the existing catalog offline.

## Workflow

`.github/workflows/refresh.yml`: tests on push/PR; scheduled refresh daily
11:17 UTC + manual dispatch; commit restricted to `catalog/`, regular push,
repository `GITHUB_TOKEN` only, no PAT, no proxy connections. Action pins were
resolved from the public GitHub API at authoring time.

## Scanner (verified Proxy-IP feed)

`.github/workflows/scanner.yml` runs `scanner/scan.py` **once daily at 11:04 UTC**
(plus manual `workflow_dispatch`). GitHub cron is best-effort — runs may be
delayed a few minutes under load, but there is exactly one scheduled scan
opportunity per day.

The scanner tests candidates **from the GitHub Actions runner egress** in two
stages; a candidate is *verified* only with evidence from both:

- **Stage A** — TCP connect, TLS handshake with SNI `speed.cloudflare.com`,
  HTTP `/cdn-cgi/trace` via that TLS session.
- **Stage B** — same candidate IP, TLS with SNI/Host = the Trinity Worker
  hostname, `/cdn-cgi/trace` through it.

`catalog/verified/feed.json` is the **only** artifact Trinity consumes. It
carries `schema_version`, `content_revision` (deterministic sha256 over the
sorted verified set), `generated_at`, per-country metadata, and the compact
runtime map `countries: CC -> [[address, port], ...]` (IPv4 and IPv6 literals
preserved). Entries older than the freshness TTL drop out of the feed.

**source country vs observed country:** source country is what the upstream
catalog claims; observed country is what the Cloudflare trace reported. Both
are recorded; neither silently overwrites the other, and a mismatch is
penalized in quality ranking, not hidden.

**Safety:** results are validated (schema, revisions, country codes, public
IPs/v6 literals, ports, duplicates, count consistency) inside a transactional
publish; a collapsed scan (near-total loss vs the previous healthy feed) is
refused — the previous feed is retained and the run fails loudly. An invalid
scan never deletes the last-known-good feed.

**Trinity sync (automatic when secrets are configured):** the workflow compares
the feed's `content_revision` with the Trinity TEST panel's `/api/catalog-meta`.
Identical ⇒ sync skipped (idempotent — reruns cause zero writes). Changed ⇒
authenticate and `POST /api/catalog-sync`, then re-fetch metadata and require
the panel revision and country/endpoint counts to match before declaring
success; any mismatch fails the run. One-time setup (secrets, never committed):

```
gh secret set TRINITY_PANEL_URL
gh secret set TRINITY_PANEL_PASSWORD
```

**Limits (scanner):**
- Verification reflects GitHub runner egress at scan time, not Cloudflare
  Worker egress, not your client's network, and not future health.
- Verified does not mean every website works through it (no universal
  site-compatibility claim), and a country present upstream can legitimately
  have zero verified endpoints on a given day.
- Gemini/non-CF-origin architectural limits are unchanged by this feed.
- Quality ranking is deterministic (evidence-weighted with stable tie-break);
  no random ordering anywhere in publish.

## Limits

- Source-reported checks only; unauthenticated geo metadata; runtime health of
  every endpoint is unknown.
- `01_last_update.txt` is an embedded stamp, not proof each country file was
  re-checked then.
- Rate-limited API falls back to the same-SHA public codeload archive,
  selectively read in memory.
- No DNS expansion, no scanning, no tokens for upstream.
