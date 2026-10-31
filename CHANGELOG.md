# Changelog

All notable changes are recorded here. This project follows Semantic Versioning.
Earlier releases are recorded in their release tags.

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
