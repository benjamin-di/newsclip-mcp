# Roadmap and remaining permission workplan

This is the project's implementation and release-acceptance plan. Each operator
keeps live identities, gateway grants, credential references and rollout evidence
in a private deployment repository. The [permissions model](docs/AUTHENTICATION.md)
is required for every remote human connection; there is no anonymous migration
mode or optional browser-authentication switch.

## Implemented in source

- Standard OIDC browser identity, a required group and an explicit registered-user binding.
- Inert CLI/MCP connection requests; only the mapped owner starts or changes an attempt.
- Separate API/browser admission and owner checks on viewer HTTP and WebSocket admission.
- Isolated user state and archives, provider verification and atomic session/profile publication.
- Durable revisions, generation fences, profile leases and disconnect barriers across readers,
  human windows, maintenance, cancellation, stale actions and restart recovery.
- Generic identity, viewer and browser primitives supplied by published signin-window;
  Newsclip retains provider entitlement and user/account policy.
- Explicitly configured, bounded operator maintenance, separate from reader and browser authority.

No further authorization switch is planned for this candidate. If acceptance
finds a defect, add a scoped reproducer and fix it before marking the affected
item complete; do not qualify a weaker permission model.

## Remaining release acceptance

- [ ] Pass CI on the final integrated source and run the documented gates:
  `make check`, `make check-mcp` and `make check-standalone` after
  `uv sync --locked --extra mcp --extra signin`.
- [ ] Complete the maintained source release, review the clean public export,
  and pass the exported-tree privacy, package-content and normal project gates.
- [ ] Qualify the public candidate images with their managed browser policy,
  offline publisher fixtures and checksum-verified disposable OIDC provider.
  A local unmanaged browser check does not replace image acceptance.
- [ ] Verify two identities, cross-user denial, copied-link/MCP-token denial,
  API/browser origin separation, native viewer input and explicit owner actions.
- [ ] Verify fresh-profile connection, independently assessed full-content proof,
  atomic publication, restart reuse, cancellation, stale-generation rejection,
  incomplete disconnect cleanup and preservation of unrelated users/archives.
- [ ] Verify public source/revision/version labels, immutable image digests and
  tested wheel/source assets. Check the configured package-index channel and a
  fresh client installation before advertising that version there.
- [ ] Validate each deployment's separate audience/scope/grant/group-ceiling
  matrix and revocation lifetimes. Connecting a provider must grant no API
  delegation; revoking an agent grant must not change another user's session.
- [ ] Upgrade reader and browser together with current controls and compatible
  rollback state, then verify the admitted artifacts and changed behavior.

See [development](docs/DEVELOPMENT.md), [deployment](docs/DEPLOYMENT.md) and
[upgrading](docs/UPGRADING.md). Preserve failed release tags and use a new patch
for a fix. Real provider/account acceptance is an explicit private operator
action; public tests and examples remain synthetic.

## Future provider and platform work

Additional architectures and provider-specific usability improvements require
their own reproductions and browser/image acceptance. Publisher behavior can
change independently; the [provider matrix](docs/PROVIDERS.md) records limits
rather than promising universal entitlement. These future enhancements do not
defer mandatory identity and account-isolation controls.

Out of scope: purchasing subscriptions, public article redistribution,
reader-triggered credential entry, credential submission without separate
operator permission, device-bound passkeys in the remote viewer, and arbitrary
browser navigation through a connection URL.
