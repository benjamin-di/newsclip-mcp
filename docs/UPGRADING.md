# Upgrading

## Current: mandatory browser permissions

Use published signin-window `>=0.4.7,<0.5` or the accepted release images.
Every remote Connections action and viewer admission requires OIDC mapped to
the registered owner. Reader tokens, proxy credentials and copied viewer URLs
are not management authority. There is no link-only fallback or opt-in
migration mode. Read [Authentication](AUTHENTICATION.md) before changing groups,
bindings, gateway grants or credentials.

Configure identity first and upgrade reader/browser together. Preserve current
connection revisions, browser state, profile leases, budgets and journals;
older images that ignore disconnect barriers are not safe rollback targets.
Existing archives are independent of subscription connection state. Upgrade
remote clients for nullable `connect.expires_at`; requesting the permanent
Connections page never starts or replaces a sign-in.

Gateway admission remains separate: browser authentication does not issue an
agent grant, and changing audience/scope/group ceilings does not delete stored
publisher credentials. Check the [remaining acceptance plan](../ROADMAP.md)
before declaring a release adopted.

## 0.9: supported maintenance integrations

The public maintenance-cycle command replaces installation-specific provider loops.
Credential-reader factories are optional; existing 1Password configuration stays
valid. Profiles, archives, session records, holds, budgets and check reservations
retain their formats and locations. No state migration or acknowledgment is needed.


## Historical 0.8 state compatibility

Human sign-in, native bearer users, archive schemas and published session formats
retain their formats. That release used signin-window 0.4.2; the current minimum
and required browser policy above apply to current installations. Install from
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
proxy prefix. Current viewer routes still require the mapped owner's OIDC
session; a link identifier is never independent authority.

`health --json` and the operator health tool now report news providers only.
Consumers should read `providers`; the former empty `identities` field is
removed. Account maintenance for another application belongs to that application.

State roots remain scoped by user. Every actor sharing a profile must use the
same absolute container path and lease directory. Stop old writers before
changing mounts. Preserve current attempt ledgers, holds, cooldowns and generation
watermarks during an upgrade or rollback; never copy an active Chromium profile
or restore older accounting. Keep a consistent SQLite backup for archive work.
