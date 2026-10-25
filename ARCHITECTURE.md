# Architecture

All interfaces use one synchronous `NewsclipService`. Providers own publisher
URL identity, discovery, assessment and extraction details. Shared code owns
network budgets, browser leases, session storage and the SQLite archive.

```text
CLI / Python client / MCP
          |
authenticated user application
          |
    NewsclipService
     |     |     |
 providers |   SQLite archive
       verified session + retained browser profile
```

## User boundary

The standalone server loads a bounded user registry containing token hashes.
Each registered user has an independent mounted application at `/users/USER`.
Authentication checks that application's user token; a path or request field
cannot select another user's authority. Token rotation is checked on subsequent
requests. New users require a restart to create their mounted application.

Composition resolves every user's data and state roots independently, without
changing process-wide environment variables. Sessions, profiles, leases,
incidents, search cursors, archives and server exports use those roots.
Callbacks preserve the construction user's context when invoked from a worker.
The host administrator remains trusted.

## Human sign-in

The authenticated `connect` operation creates a short-lived relay link for one
provider and user. A separate private browser service validates the target and
opens a restricted signin-window. The person drives the publisher's page.
Top-level navigation is limited to the provider and required identity hosts;
resource requests and DNS resolution have explicit allowlists. Browser policy
blocks local files, downloads, password storage and general browser controls.

After the person signs in, Newsclip visits the configured verification article
and applies the provider's existing full-content checks. It closes Chromium
before publishing the new profile-bound session. Publication is atomic and
compares the generation present when the window opened, so an obsolete window
cannot overwrite a newer session. Failed candidates are discarded without
replacing existing verified authority.

Retained browser state and portable session authority are distinct. A profile
alone is not permission to read an article. Browser readers use the profile
associated with the active verified session and serialize access with leases.

## Retrieval and persistence

An owned URL is fetched with the applicable user's session, extracted, and
assessed. Requested, final, canonical and extracted article identity must agree.
Negative authentication, challenge and paywall signals take precedence over
plausible prose. Only independently accepted FULL content becomes an Article.
A verified session does not establish entitlement to every article.

`get` returns accepted content transiently. `save` commits immutable raw-fetch
evidence and an extraction revision in SQLite; Markdown is a derived export.
Re-extraction reads stored bytes, and archive search does not contact providers.
Backups use SQLite's consistent backup path rather than copying live WAL files.

## Installation-specific integrations

The core has a small optional integration boundary for installations maintaining
additional operator capabilities. The standalone distribution contains no such
integration, deployment accounts or credential automation. Provider session
verification remains usable without an automated acquisition adapter.
