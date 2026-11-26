# Changelog

All notable changes are recorded here. This project follows Semantic Versioning.
Earlier releases are recorded in their release tags.

## [2.2.3] - 2026-11-27

### Changed

- Remove custom 5-minute freshness gates on Connections `share` and `disconnect` so ordinary valid browser sessions (>300s) can share and disconnect without `?reauth=1` step-up while preserving ordinary OIDC login, 401 expired-POST refusal without callback replay, Origin, revision, admission, and disconnect barriers.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.2.2, 2.2.1, and 2.2.0; no storage or configuration changes.

## [2.2.2] - 2026-11-26

### Fixed

- Remove the duplicate `"Disconnected."` prefix from the disconnected card callout on `/connections/` so the status pill carries the single `"Disconnected"` label and Playwright strict-mode acceptance locators match uniquely.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.2.1, 2.2.0, and 2.1.7; no storage or configuration changes.

## [2.2.1] - 2026-11-26

### Fixed

- Guard `_owner_access_summary` and `sharing_body` in `Connections` when called directly without initialized `adapters`/`controls` or derived `access_label`/`access_tone` fields, keeping direct unit callers compatible.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.2.0 and 2.1.7; no storage or configuration changes.

## [2.2.0] - 2026-11-26

### Added

- Surface real derived subscription access health (`Working`, `Needs check`, `Degraded`, `Action needed`, `Paused`, `Checking…`, `Not connected`, `Disconnected`) on `/connections/` and `/connections/status`, folding in keeper renewal outcomes, recovery state, and shared-owner access health without exposing private incident or diagnostic identifiers.
- Add live `Check access` (`POST /connections/check`) and `Check all` (`POST /connections/check-all`) actions that run bounded background `session_checkpoint` verification, refresh `verified_at` on disk when access succeeds, and update the page automatically via `signin-window` polling.
- Redesign `/connections/` with a modern, accessible light/dark UI featuring an at-a-glance access health overview strip, publisher monograms, color-coded status pills and callouts, relative + UTC verification timestamps, and structured sharing and account selection cards.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.7; session files, connection controls, sharing records, and archive formats are unchanged.

## [2.1.7] - 2026-11-24

### Changed

- Upgrade `signin-window` from 0.8.4 to 0.10.0 for mobile/desktop remote viewer improvements (scrollable noVNC container, Restart button, passkey notice, keyboard/paste/zoom ergonomics, and non-blocking sign-in completion handoff).
- Show the active view layout (`mobile view` / `desktop view`) on `/connections/` and offer `Start new sign-in` alongside `Continue sign-in`, with fenced replacement teardown, saving-state protection, and `429` active-window preservation.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.6; `signin-window` 0.10.0 adds `revocations` and `session_families` tables to the OIDC `connections-browser` SQLite store while preserving `sessions`, publisher controls, and saved session records (`make rollback-check`).

## [2.1.6] - 2026-11-24

### Fixed

- Honor `NEWSCLIP_CHALLENGE_MODE` (`detect-only` by default) across direct CLI `auth login` and fallback session acquisition, including child display-launcher processes (#52).

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.5 and 2.1.4; saved sessions, connection controls and archive formats are unchanged.

## [2.1.5] - 2026-11-24

### Fixed

- Pass the selected `--user` explicitly to maintenance-cycle and fallback login child processes and strip ambient `NEWSCLIP_USER` overrides.
- Enforce active connection controls and verified session generation under the acquired profile lease for serving reads, warm-ups, authenticated browser search, and published-profile verification, and drain expected missing profile leases during disconnect.
- Treat identity mismatch as terminal in native extraction across serving, archive re-extraction, and drift checks while preserving verified-session teaser-DOM promotion.
- Preserve committed browser profiles if sign-in finalization fails after session replacement, and initialize sign-in cleanup state before browser setup.
- Enforce a 16 MiB response size ceiling on HTTP fetches (via `curl_cffi` `content_callback`, preserving total timeouts and connection reuse) and atomic UTF-8 byte-bounded browser DOM captures.
- Serialize SQLite archive initialization across processes, validate extraction assessment identity and canonical URL consistency, and stream raw snapshots during drift checks.
- Reuse in-flight futures on timed-out federated search batches and terminate per-watcher recovery child process groups cleanly on shutdown.
- Keep revision-fenced Disconnect available when a subscription needs sign-in, isolate damaged provider cards on Connections, validate actions per provider, serialize Start requests and return HTTP 429 on link quota limits, check link expiry before offering Continue, and offload Connections index/sharing reads and ops secret resolution off the ASGI event loop.
- Separate subscription-access historical enrollment and grant bounds from the 100 active-user limit and validate serialized record sizes before writing.
- Fail closed on unstructured non-zero ops CLI exits, map HTTP 400/413/422 responses to non-retryable usage errors in `NewsclipClient`, and reject remote mode on local-only guard and health CLI commands.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.4; saved sessions, connection controls and archive formats are unchanged.

## [2.1.4] - 2026-11-15

### Fixed

- Use the compact mobile sign-in viewer with native keyboard input, Paste and Zoom (586df79)
- Preserve editor focus while allowing touch controls to activate on WebKit (586df79)

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.3; saved sessions, connection controls and storage formats are unchanged.

## [2.1.3] - 2026-11-14

### Fixed

- Require signin-window 0.8.2 for package installations, so an existing 0.8.1 installation cannot miss the mobile remote-input fix.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.2; saved sessions, account controls and storage formats are unchanged.

## [2.1.2] - 2026-11-14

### Fixed

- Use signin-window 0.8.2 so phone users can open a keyboard in remote sign-in and edits remain bound to their original viewer.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.1; saved sessions, connection controls and account state are unchanged.

## [2.1.1] - 2026-11-12

_Publishes the 2.1.0 changes, which the public mirror did not receive; the package is unchanged from 2.1.0._

### Upgrade

- Action required: none.
- Rollback: compatible with 2.1.0.

## [2.1.0] - 2026-11-12

### Added

- Embed the application version, full source revision and a bounded source fingerprint in release images and distributions; runtime reads do not trust environment overrides or invoke Git (#48)
- Attribute retained application, MCP, timing and browser diagnostics to their producing build and process, preserving legacy records and log suppression (#48)
- Forward the host build identity to the signin-window Connections, browser authentication, relay and direct viewer pages, using signin-window 0.8 (#48)

### Fixed

- Check installed identity in publisher acceptance; source Compose builds require the selected product version and full revision, and live qualification refuses when selected-source dirtiness conflicts with the artifact stamp (#48)
- Preserve enclosing Rich console capture and recording while attributing diagnostics, and retain native sink-error handling and terminal rendering (#48)

### Upgrade

- Action required: none for images. Source Compose builds must pass the product version and full source revision.
- Rollback: persisted timing, incident and provider-hold records written by 2.1.x use the new `packaged` / `unstamped_development` provenance enum values, which 2.0.3 does not recognize. Rollback within 2.1.x is compatible; rolling back to 2.0.3 requires clearing or archiving 2.1.x timing/incident/hold files that carry those provenance values.

## [2.0.3] - 2026-11-03

### Fixed

- Use signin-window 0.7.1 for consistent mobile action widths, readable long labels and accessible checkbox touch targets.

### Upgrade

- Action required: none.
- Rollback: compatible with 2.0.2; preserve current credentials, connection controls and owner bindings.

[2.0.3]: https://github.com/benjamin-di/newsclip-mcp/releases/tag/v2.0.3

## [2.0.2] - 2026-11-02

### Fixed

- Answer a stale Share or Disconnect on the Connections page with a "Confirm it's you" page that starts the step-up by navigation, instead of refusing it (signin-window-private#4).
- Explain refused Connections requests: an ended sign-in gets a 401 page with a sign-in link, and a cross-site or unauthorized request gets a 403 page saying nothing changed (signin-window-private#4).
- Keep the person signed in when a step-up is abandoned or cancelled, by updating signin-window to 0.6.0; a sign-in in progress during the upgrade must be started again (signin-window-private#4).

### Upgrade

- Action required: none.
- Rollback: compatible with 2.0.1.

[2.0.2]: https://github.com/benjamin-di/newsclip-mcp/releases/tag/v2.0.2


[2.0.2]: https://github.com/benjamin-di/newsclip-mcp/releases/tag/v2.0.2

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

- Address token-signature, nonce, audience and scope validation bypasses, unsafe authorization-request URL fetches and registration-token binding guidance by updating Authlib to 1.9.1 (GHSA-8m4g-j4wp-wgcg, GHSA-7vr2-2fgp-9w7p, GHSA-6v38-4h7w-rj9h, GHSA-c5mf-xmp2-59rc, GHSA-fch4-3c6x-j4gc, GHSA-q686-2qmg-hqc7, GHSA-x4rv-c3wx-4cr8, GHSA-c73q-w75p-j82v); prevent unauthorized access to transformed components and potential OAuth client-secret disclosure in affected MCP client wrappers by updating FastMCP to 4.1.2 (GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4); reject oversized signed tokens before allocating their segments to prevent memory exhaustion by updating joserfc to 1.7.6 (GHSA-9pg5-8c7x-5hfx); avoid excessive CPU use while parsing untrusted DNS names by updating dnspython to 2.9.0 (GHSA-45c3-73f7-pv4m) (a9635d9).

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
