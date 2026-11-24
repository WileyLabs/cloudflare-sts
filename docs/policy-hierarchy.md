# Policy hierarchy

```text
policy/
  config.yaml · issuers.yaml · profiles.yaml · schema/
  <provider>/<account>/<resource>/policy.yaml
  <provider>/<account>/<resource>/<principal>/policy.yaml
```

| Segment | Meaning |
|---------|---------|
| **provider** | `issuers.yaml` key (`github`, `gcp`, `spiffe`, `aws`) |
| **account** | Org / GCP project / trust domain / AWS account |
| **resource** | Repo, SA name, workload class, cluster, … |
| **principal** *(optional)* | Filesystem slug (Environment, ref, …). Prefer one identity per file. |

Path slug is organizational only. The rule’s `principal` field is the JWT identity that must match.

## Rule shape

| Provider | JWT claim for `principal` |
|----------|---------------------------|
| github | `sub` |
| gcp | `email` |
| spiffe / aws | `sub` |

```yaml
rules:
  - id: my-rule
    principal: repo:example/example:ref:refs/heads/main   # or a list (OR)
    claims:                                               # optional extras
      job_workflow_ref: example/example/.github/workflows/x.yml@refs/heads/main
    max_ttl_seconds: 600
    grants:
      - profile: dns-read
        zones: [example.com]
```

`issuer` defaults to the path provider. **No cross-file merge** — put each caller identity in its own path/rule.

**Grants / profiles / permissions / zones / narrowing:** [grants.md](./grants.md).

## Build / verify

```bash
npm run build:policy              # → gitignored policy.bundle.json
npm run build:policy -- --check   # local: on-disk artifact matches rebuild
npm run verify:policy             # YAML + schema + path + validatePolicy()
```

CI: `.github/workflows/verify-policy.yml` builds the bundle; it is **not** committed.
