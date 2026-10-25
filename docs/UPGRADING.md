# Upgrading

## 0.9: supported maintenance integrations

Install signin-window 0.4.4 or newer within its 0.4 compatibility range. The
public maintenance-cycle command replaces installation-specific provider loops.
Credential-reader factories are optional; existing 1Password configuration stays
valid. Profiles, archives, session records, holds, budgets and check reservations
retain their formats and locations. No state migration or acknowledgment is needed.


## 0.8

Human sign-in, native bearer users, archive schemas and published session formats
remain compatible. The minimum signin-window version is now 0.4.2. Install from
the release package or pinned image rather than mixing application and library
source trees.

Optional credential upkeep is configured explicitly per account; see
[Maintenance](MAINTENANCE.md). No credential adapter, model account or scheduler
is enabled by installing the package. The public server and browser images
contain the same application; credentials and operator routes belong only in
separately configured worker/operator containers. Keep reader processes free of
secret-store grants.

A proxy-only registry entry uses `"token_sha256": null`. Existing hashed native
tokens continue working. Register proxy identities with `users add-proxy`, supply
an authenticated identity header and the dedicated proxy credential, and strip
client-supplied identity headers at the edge. Public URLs may include a simple
proxy prefix; forward connection links with their independent authority.

`health --json` and the operator health tool now report news providers only.
Consumers should read `providers`; the former empty `identities` field is
removed. Account maintenance for another application belongs to that application.

State roots remain scoped by user. Every actor sharing a profile must use the
same absolute container path and lease directory. Stop old writers before
changing mounts. Preserve current attempt ledgers, holds, cooldowns and generation
watermarks during an upgrade or rollback; never copy an active Chromium profile
or restore older accounting. Keep a consistent SQLite backup for archive work.
