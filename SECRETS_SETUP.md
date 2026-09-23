# Trinity sync setup (V24.7 — OIDC, nothing to configure)

There are **no secrets to set**. The `refresh-verified` workflow authenticates
to the Trinity TEST panel with its GitHub-issued OIDC identity token
(audience `trinity-catalog-sync`), which the Worker verifies against GitHub's
JWKS. No panel password ever lives in GitHub — the old
`TRINITY_PANEL_URL` / `TRINITY_PANEL_PASSWORD` secrets are gone by design.

Machine-to-machine trust chain (fail-closed, verified in `github_oidc.rs`
of the panel repo, Desktop/panel 2):

- issuer: `https://token.actions.githubusercontent.com`
- audience: `trinity-catalog-sync` (fixed on both sides)
- repo: `Osajjad0/trinity-proxy-catalog`, ref `refs/heads/main`
- workflow: `.github/workflows/scanner.yml`
- events: `schedule` + `workflow_dispatch` only

Endpoint: `POST /api/catalog-sync-github` (Bearer OIDC token). It runs the
same shared, fail-closed `catalog::sync()` as the operator route and returns
the sync report (revision + counts) the workflow re-verifies before
declaring success. A failed or refused sync leaves the previous catalog
active in Trinity.

Trigger a run manually with:

```bash
gh workflow run refresh-verified -R Osajjad0/trinity-proxy-catalog
```
