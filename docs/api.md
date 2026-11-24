# API

Base: `https://cf-sts.example.com`

## `POST /token`

`Authorization: Bearer <OIDC JWT>`  
Body (optional): `{ "ttl_seconds": 60–86400, "permissions": ["…"] }`  
→ `{ id, token, expires_on, rule }`  

Optional `permissions` **narrows** the matched rule’s grants (subset only). See [grants.md](./grants.md).

JWT is single-use (`jti`, or `sha256(header.payload)` when `jti` is absent).

## `POST /revoke`

Fresh JWT + `{ "token_id": "<id>" }` → `{ revoked: true, id }`  

Ownership: token name embeds `sha(iss:sub)`. Same issuer+subject that minted may revoke. GitHub still accepts legacy names that used `sha(sub)` only.

## Dashboard

`GET /`, `GET /api/mints|stats|policy|denials`  
Optional Access: `ACCESS_TEAM_DOMAIN` + `ACCESS_AUD` (bypass `/token` and `/revoke`).

## Errors

`{ "error": "<code>" }`

| HTTP | codes |
|------|--------|
| 400 | `invalid_json`, `invalid_request`, `invalid_ttl`, `invalid_permissions`, `narrowing_unsupported` |
| 401 | `token_invalid`, `token_replayed`, `unknown_issuer`, `auth_header_missing`, `access_required` |
| 403 | `no_matching_rule`, `forbidden`, `permission_not_allowed` |
| 404 | `not_found`, `token_not_found` |
| 413 / 429 / 502 | body too large / `rate_limited` / `cloudflare_error` |
