# Docs

How cf-sts is set up today (principal-based YAML policy, multi-issuer Worker).

| Doc | |
|-----|--|
| [policy-hierarchy.md](./policy-hierarchy.md) | Path layout, rule shape, build/verify |
| [grants.md](./grants.md) | Profiles, permissions, zones, narrowing |
| [issuers/](./issuers/) | github · gcp · spiffe · aws |
| [api.md](./api.md) | `/token`, `/revoke`, dashboard, errors |
| [ci.md](./ci.md) | Reference GHA workflows (disabled upstream); local checks |
| [examples/](./examples/) | Sample YAML + curl exchange |

Operator overview: [../README.md](../README.md).
