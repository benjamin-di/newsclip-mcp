# Working on Newsclip

Newsclip searches, retrieves and privately archives news through CLI, Python and
MCP interfaces. Only identity-matched, independently assessed FULL content may
be returned as an article or enter the SQLite archive.

Read README.md, ARCHITECTURE.md and docs/DEVELOPMENT.md. AGENTS.md is the only
agent instruction file; do not add CLAUDE.md or GEMINI.md.

## Boundaries

- This source is published. Never write personal, account, household, host or
  network details into public code, comments, docs, fixtures or artifacts.
- Use synthetic fixtures and example domains. Never copy real article bodies,
  cookies, screenshots, incidents or profiles into a test or issue.
- Preserve complete user isolation across authorization, sessions, profiles,
  archive, exports, diagnostics and asynchronous callbacks.
- Human sign-in uses signin-window and never automates credential submission.
  Reader tools cannot collect credentials. Optional operator maintenance uses
  explicit account-scoped references, bounded budgets and separate credentials.
  Generic session/challenge mechanics belong in signin-window; news entitlement
  and recovery policy belong here.
- A successful sign-in is not proof of entitlement to an arbitrary article.
  Preserve provider assessment and atomic verified-session publication.
- Keep provider drift local. Shared fixes require a shared reproducer.
- SQLite is archive authority. Use consistent backup/restore operations.

## Verify and contribute

Use `uv sync --locked --extra mcp --extra signin`, install the Patchright
Chromium, then run `make check` and `make check-mcp`. Add synthetic browser and
user-isolation acceptance for changes to those paths. Live checks are explicit
private operator actions; never put credentials or live content in public CI.

Follow CONTRIBUTING.md: changes land in the maintained source and are exported
as releases. Never rewrite a public release tag or merge directly into a release
mirror. Preserve the MIT license and third-party notices.
