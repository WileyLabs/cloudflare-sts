# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2026-11-24

### Added
- Initial open-source release of cloudflare-sts (OIDC → short-lived Cloudflare API token broker).
- Cloudflare Worker with `/token` and `/revoke`, D1 audit/replay, rate limits, and dashboard UI.
- GitHub Action that mints a scoped token for a job and revokes it when the job ends.
- Issuers: GitHub Actions OIDC, GCP, SPIFFE, AWS IAM outbound identity federation.
- Policy-as-code under `policy/` with profiles `dns-read`, `worker-deploy-account` (includes Connectivity Directory Admin for Workers VPC bindings), and `worker-deploy-zone`.
- Reference GitHub Actions workflows under `.github/workflows/` for forks (disabled on upstream).

[0.0.1]: https://github.com/WileyLabs/cloudflare-sts/releases/tag/v0.0.1
