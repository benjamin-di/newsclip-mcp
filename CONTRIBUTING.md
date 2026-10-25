# Contributing

Newsclip welcomes focused bug reports, synthetic regression cases, provider
improvements and documentation fixes. Read [the architecture](ARCHITECTURE.md)
and [development guide](docs/DEVELOPMENT.md) before changing provider behavior.

Never include credentials, cookies, browser profiles, account details, real
article bodies, screenshots of signed-in pages, or deployment information in an
issue, pull request, test fixture or log attachment. Use invented data and
example domains. Share security reports privately; see [SECURITY.md](SECURITY.md).

## How changes land

This repository is a release mirror of the maintained source. Pull requests are
reviewed here and re-applied to the maintained source; they are not merged into
the mirror. Accepted changes arrive in a subsequent release, with contributor
credit in its release notes. This keeps every public release reproducible from
the same source without maintaining a separate implementation.

Explain the problem, expected behavior and a minimal reproducer. Run `make check`
and, for protocol changes, `make check-mcp`. Public tests use synthetic data and
must work without publisher accounts or private services. Provider-specific
selectors and access checks belong in that provider's adapter or definition.

Contributions are accepted under the MIT license. Preserve third-party notices.
