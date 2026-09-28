# Secrets setup

There are **no secrets** in this repository, and no outbound calls to any
consumer system. The catalog pipeline (scanner + catalog build) only talks to
public sources (NiREvil/vless, IP quality providers, public DNS) and publishes
artifacts into this repo:

- `.github/workflows/scanner.yml` — scan -> validate -> publish -> commit (every 2 h)
- `.github/workflows/refresh.yml` — candidate catalog build + tests

The published feed (`catalog/verified/feed.json`) is a plain public artifact.
Consumers pull it on their own schedule, validate it, and activate it; they
never push to this repository and this repository never calls them.

History (kept for context): before the 2026-09 decoupling, this workflow
additionally pushed the feed to a consumer panel via OIDC-authenticated sync
endpoints. Those steps, the `id-token: write` permission, and all consumer
URLs/audiences were removed.
