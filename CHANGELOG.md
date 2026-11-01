# Changelog

All notable changes are recorded here. This project follows Semantic Versioning.
Earlier releases are recorded in their release tags.

## [2.0.1] - 2026-11-01

_Enforce patched dependencies and describe the current provider operations._

### Security

- Enforce the patched dependency minima in published package requirements, including ordinary pip upgrades (#43).
- Address token-signature, nonce, audience and scope validation bypasses, unsafe authorization-request URL fetches and registration-token binding guidance by updating Authlib to 1.9.1 (GHSA-8m4g-j4wp-wgcg, GHSA-7vr2-2fgp-9w7p, GHSA-6v38-4h7w-rj9h, GHSA-c5mf-xmp2-59rc, GHSA-fch4-3c6x-j4gc, GHSA-q686-2qmg-hqc7, GHSA-x4rv-c3wx-4cr8, GHSA-c73q-w75p-j82v; a9635d9).
- Prevent unauthorized access to transformed components and potential OAuth client-secret disclosure in affected MCP client wrappers by updating FastMCP to 4.1.2 (GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4; a9635d9).
- Reject oversized signed tokens before allocating their segments to prevent memory exhaustion by updating joserfc to 1.7.6 (GHSA-9pg5-8c7x-5hfx; a9635d9).
- Avoid excessive CPU use while parsing untrusted DNS names by updating dnspython to 2.9.0 (GHSA-45c3-73f7-pv4m; a9635d9).

### Fixed

- Describe only the current provider operations in MCP initialization instructions (#43).

### Upgrade

- Action required: none when upgrading from 2.0.0. Local Python/CLI users upgrading from 1.x must select the `local` extra, as described in 2.0.0.
- Rollback: compatible with 2.0.0 state; preserve current sharing records and native authority. The older package requirements do not enforce these security minima.

[2.0.1]: https://github.com/benjamin-di/newsclip-mcp/releases/tag/v2.0.1

## [2.0.0] - 2026-11-01

### Changed

- **Breaking:** the base installation is now the lightweight remote client. Local
  retrieval, browser sign-in and publisher acquisition require `newsclip[local]`.
  Full server installations use `newsclip[local,mcp,signin]`; supplied image and
  development paths already select the complete runtime.
- Preserve the validated public error envelope on remote exceptions, including
  typed retry/defer actions and retry delays.
- Remote CLI help, search, read, archive and Connections commands work without
  browser or publisher-acquisition dependencies.

### Upgrade

- Action required: local Python/CLI users must install the `local` extra. Remote users need no
  additional dependencies. No database or session migration is performed.
- Rollback: state remains compatible with 1.0.1; retain current sharing and
  authority records. Restore the former dependency selection when downgrading.

## [1.0.1] - 2026-11-01

_Security: upgrade from 1.0.0 for patched authentication, MCP and DNS dependencies._

### Security

- Address token-signature, nonce, audience and scope validation bypasses, unsafe authorization-request URL fetches and registration-token binding guidance by updating Authlib to 1.9.1 (GHSA-8m4g-j4wp-wgcg, GHSA-7vr2-2fgp-9w7p, GHSA-6v38-4h7w-rj9h, GHSA-c5mf-xmp2-59rc, GHSA-fch4-3c6x-j4gc, GHSA-q686-2qmg-hqc7, GHSA-x4rv-c3wx-4cr8, GHSA-c73q-w75p-j82v; a9635d9).
- Prevent unauthorized access to transformed components and potential OAuth client-secret disclosure in affected MCP client wrappers by updating FastMCP to 4.1.2 (GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4; a9635d9).
- Reject oversized signed tokens before allocating their segments to prevent memory exhaustion by updating joserfc to 1.7.6 (GHSA-9pg5-8c7x-5hfx; a9635d9).
- Avoid excessive CPU use while parsing untrusted DNS names by updating dnspython to 2.9.0 (GHSA-45c3-73f7-pv4m; a9635d9).

### Fixed

- Preserve healthy federated search results when another source has unreadable containment state, retaining existing typed errors and article verification checks (86ade41).

### Upgrade

- Action required: none.
- Rollback: compatible with 1.0.0; older dependencies retain the security advisories. Preserve current sharing records and native authority.

[1.0.1]: https://github.com/benjamin-di/newsclip-mcp/releases/tag/v1.0.1

## [1.0.0] - 2026-10-31

### Changed

- **Breaking:** Upgrade typed clients with the server for the additional `provider_defense` search source reason; older strict clients cannot parse this value (083baa7).
- **Breaking:** Adopt durable per-publisher subscription choices in hosted mode; upgrade hosted readers and writers together and preserve the sharing records (#41).
- Use the selected owner's sessions, profiles, native barriers, account limits and search-refusal cooldowns while keeping archives, exports and request diagnostics private to the requester (#41).
- Revalidate selected access and native session generations before serving protected search continuations; retain requester-owned evidence while a shared defense episode remains unresolved (#41).

### Added

- Let owners offer publisher subscriptions to registered users, with explicit recipient selection independently for each publisher (#41).
- Reuse `account-connections` for offers, grants, selection and native form controls (#41).

### Fixed

- Preserve recognized publisher defenses in federated search source reports and CLI output (083baa7).
- Distinguish Reuters sitemap challenges, rate limits, publisher refusals and response-contract failures before XML parsing (083baa7).
- Show the current maintenance hold, source incident and canary eligibility separately from historical completed article recovery without changing budgets or FULL-content checks (083baa7).

### Upgrade

- Action required: upgrade CLI/Python typed clients with the server for the new `provider_defense` source reason; quiesce hosted traffic, back up archives consistently and replace all hosted readers and writers together. Preserve the new subscription-access records and adoption marker with existing native state. See [sharing storage and recovery](docs/SHARING.md#storage-and-recovery).
- Rollback: incompatible with 0.9.x after sharing is used; retain current grants, revocations, credentials and archives, and recover forward. Adding publisher namespaces after adoption requires an explicit reviewed migration. Local single-user CLI/Python behavior is unchanged.

[1.0.0]: https://github.com/benjamin-di/newsclip-mcp/releases/tag/v1.0.0