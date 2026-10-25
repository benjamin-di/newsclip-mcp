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

## Optional account maintenance

The public package contains provider session maintenance and recovery policy.
`newsclip maintenance-cycle` coordinates bounded `auth keep` or scheduled
`provider-guard` work and returns a versioned, closed result. Each provider
retains its existing attempt budgets and holds. The provider-check reservation
is persisted before requests and survives restarts. A failed provider does not
prevent checking the others. Callers supply scheduling and notification delivery.

Generic browser, challenge and durable-state mechanisms come from signin-window.
Applications use its supported public APIs. Human windows remain independent of
credential automation. Readers have no maintenance authority simply because the
code is installed; the operator must separately supply credentials and grants.

The default credential adapter is 1Password. `NEWSCLIP_CREDENTIAL_READER` can
explicitly select an operator-installed `module:factory` implementing
signin-window's `CredentialReader`. References are opaque to Newsclip. A selected
backend failure never falls back to ambient 1Password credentials. The configured
planner factory is an independent integration point. Site identity, entitlement,
FULL article assessment and atomic session publication remain Newsclip policy.

Account references, credentials, runtime profiles, schedules, alert destinations
and installation-specific planner transports stay outside the public release.
Private deployments consume the accepted public images without a product fork.
