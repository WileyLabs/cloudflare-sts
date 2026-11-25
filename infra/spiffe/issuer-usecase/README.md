# SPIFFE / SPIRE issuer usecase (infra) — EXAMPLE

Identity for the `spiffe` issuer of cf-sts. A workload gets a JWT-SVID from the local SPIRE agent
(audience `cf-sts.example.com`) and exchanges it directly at cf-sts. Nothing is provisioned by Terraform here;
SPIRE owns identity issuance.

| Path | What |
|---|---|
| `spire/server-oidc-discovery.conf` | SPIRE OIDC discovery provider config publishing JWKS (`/keys`) at the cf-sts `iss` |
| `spire/registration-entry.sh` | Registers an example workload with JWT-SVID audience |

Requirements: the OIDC discovery URL is the cf-sts `spiffe` issuer (`https://oidc-discovery.example.com`) and
the SPIRE server `jwt_issuer` matches it. Policy: `docs/examples/policy/spiffe/example.com/...`.
Docs: [docs/issuers/spiffe.md](../../../docs/issuers/spiffe.md).
To reach GCP with the same SVID use `infra/gcp/issuer-usecase` (`enable_spiffe`); the WIF provider audience
must be in the SVID's `aud` (request a second audience or a separate SVID).

```bash
spire-agent api fetch jwt -audience cf-sts.example.com -socketPath /run/spire/sockets/agent.sock
```
