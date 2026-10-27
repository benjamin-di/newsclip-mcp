# Development and validation

Use Python 3.12+ and uv. Install with `uv sync --locked --extra mcp --extra
signin`, then `uv run patchright install chromium`. Linux is required for the
browser sign-in service and POSIX profile locks.

`make check` runs lint, formatting, typing, the offline tests and whitespace
checks. `make check-mcp` exercises protocol contracts. Tests marked `live` never
run implicitly. Public CI requires no account, publisher or private service.

## Validation matrix

| Change | Required evidence |
|---|---|
| Documentation | Whitespace, links and documented command checks |
| Pure article logic | Focused synthetic regression plus offline gate |
| Provider retrieval/assessment | Synthetic positive and negative cases; explicit private warm acceptance for changed live behavior |
| User routing or storage | Cross-user denial, archive/profile isolation, malformed requests and token lifecycle |
| Sign-in/publication | Browser path, success, failure, cancellation, stale-generation protection and restart reuse |
| Browser/image dependencies | Real Chromium launch in the shipped image and affected browser paths |
| MCP/HTTP/CLI | Actual wire/CLI requests through the shared service and stable error contracts |

Never weaken negative-content checks to make a fixture pass. A regression
should model the defect with invented content. Keep publisher-specific behavior
in its adapter or TOML definition. Shared changes need evidence across each
distinct affected execution path.

Test browser identity, delegated API admission and provider authority as separate
boundaries. A valid browser owner must not acquire reader/agent permission by
signing in, and a reader/proxy token must not start or manage a human attempt.
The application's synthetic tests cannot certify an operator's gateway grant,
audience or group-ceiling configuration; that integration needs separate private
acceptance. The [remaining workplan](../ROADMAP.md) lists release obligations.

## Public releases

Public CI and release workflows are self-contained. Container images and release
archives are built only from exported public source, under distinct public image
names. Workflows never receive account/session fixtures. A release must pass the
privacy scan, a manual export review, the exported-tree gate and image acceptance
before its artifacts are promoted.
