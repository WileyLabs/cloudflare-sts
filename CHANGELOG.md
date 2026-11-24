# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open-source release of cloudflare-sts (OIDC → short-lived Cloudflare API token broker).
- `worker-deploy-account` includes Connectivity Directory Admin (Workers VPC / tunnel bindings).

### Changed
- Slim example `policy/` (one demo per issuer + self rules); removed org-specific examples and Vault-migration profiles.
- Docs: Actions disabled on upstream; workflows kept as fork reference.
