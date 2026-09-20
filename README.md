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

## Limits

- Source-reported checks only; unauthenticated geo metadata; runtime health of
  every endpoint is unknown.
- `01_last_update.txt` is an embedded stamp, not proof each country file was
  re-checked then.
- Rate-limited API falls back to the same-SHA public codeload archive,
  selectively read in memory.
- No DNS expansion, no scanning, no tokens for upstream.
