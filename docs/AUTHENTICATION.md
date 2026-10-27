# Authentication and user isolation

The standalone server uses [signin-window](https://github.com/benjamin-di/signin-window)
to let a person sign in on a publisher's actual page from a phone or browser.
The browser itself runs on the server. Passwords, verification codes and
interactive challenges are entered by the person; the assistant receives only
a link and session status.

1. Authenticate to your own user URL and request `auth connect PROVIDER` or the
   MCP `connect` tool.
2. Open the Connections link, authenticate with the installation's OIDC identity
   provider, and complete the publisher's sign-in. Pocket ID is supported through
   standard OIDC; Newsclip also works with other compatible providers. Choose
   Connect or Reconnect to open an expiring sign-in window. A phone layout and
   paste support are available in the viewer.
3. Newsclip opens the provider's configured verification article and applies its
   normal identity and full-content checks. A cookie alone is insufficient.
4. After verification, the viewer closes, Chromium shuts down, and Newsclip
   atomically activates the new session and retained profile.
5. Check `auth status PROVIDER`, then repeat the requested retrieval. A verified
   subscription may still exclude a particular article.

A cancelled, expired, blocked or inconclusive connection does not replace a
previously verified session. A window opened before another session was
activated cannot overwrite that newer session. Retained profiles use unique
identifiers and the same profile locks as the reader.

## Permission boundaries

| Boundary | Authority it supplies | Authority it does not supply |
| --- | --- | --- |
| Human OAuth/OIDC through Pocket ID or another issuer | Verified browser identity, required group and a binding to a registered Newsclip user | Agent delegation, API permission or proof of publisher entitlement |
| Agentgateway or another API admission gateway | The caller, intended audience, permitted scopes/tools, explicit agent grant and deployment group ceiling | Browser management or ownership of publisher credentials |
| Native user token or trusted proxy credential plus user header | Admission to the selected user's application and isolated storage | OAuth scope validation, access to another user or permission to mint credentials |
| Browser owner binding | Starting, cancelling and disconnecting the mapped user's provider connections | New agent grants or automatic proof of the publisher account's identity |
| Independently verified publisher session | Provider access for that user, subject to each article's identity and full-content checks | Entitlement to arbitrary content, shared access to another user or broader gateway permissions |
| Separate operator configuration and credential grants | Bounded maintenance for the explicitly selected account | Reader-triggered credential entry or an exemption from connection barriers |

An agent's effective access is the intersection of its explicit grant, requested
scope, token audience, group ceiling and the application's own checks. The
gateway owns delegated admission; Newsclip's backend tokens do not parse those
OAuth policies. Keep the backend private wherever gateway policy is required,
strip client-supplied identity headers, and use the dedicated proxy credential
only between the trusted gateway and backend. Do not interchange human tokens,
workload grants, proxy credentials, native user tokens or publisher cookies.

The current Connections UI manages a user's default account for each provider.
A user URL or a provider parameter cannot select another user's authority.
Publisher verification proves access to the configured article, not the
person's identity at that publisher. The owner chooses the intended account in
the remote window. See [deployment configuration](DEPLOYMENT.md) for the user
registry and explicit identity bindings.

## Required Connections authentication

Requesting a link through CLI or MCP changes no connection state. Only an
authenticated owner's Connect action can pause maintenance, open a browser or
replace a pending attempt. The API's `expires_at` is nullable: the permanent
Connections page returns `null`, while expiring links may still return a date.
Upgrade remote CLI/Python clients together with the server; older clients that
require a non-null date cannot parse the new response.

Open `/connections/` to see your subscriptions, reconnect, cancel a pending
attempt or disconnect. The browser identity must belong to the required group
and map to a registered Newsclip user through a signed claim or an
issuer-and-subject binding. A user URL, copied viewer link or MCP token never
grants browser management access. This is required for every remote sign-in.

Connecting a publisher establishes access only for that user's selected
subscription. It does not grant an assistant permission to call Newsclip; the
client's API access remains a separate boundary. Publisher verification proves
access to the configured article, not the person's identity at the publisher.
Choose the intended publisher account in the sign-in window.

Disconnect requires a fresh identity-provider login. A durable per-user,
per-provider, per-account barrier blocks readers, maintenance and the final
session writer before cleanup starts. Newsclip drains retained browsers and
removes the active session and profiles. If cleanup cannot finish, the
subscription stays blocked until recovery succeeds. Restarting either service
does not restore access. An explicit new verified connection is required.
Disconnect keeps private archives, exports and maintenance budgets intact.

Reloading or closing a viewer preserves an active attempt while it remains
valid. Use Cancel to stop it. Cancellation prevents late publication while
preserving the previously accepted session. An interrupted attempt can be
cancelled or replaced from Connections; pending attempts expire after ten
minutes. Background maintenance pauses during human sign-in and stays blocked
after disconnect.

Cancel and Disconnect apply to the connection shown on that page. Repeating an
old action cannot cancel or remove a newer connection. Overlapping disconnect
retries keep access blocked until the current cleanup finishes.

## Revocation and recovery

| Change | Effect and limit |
| --- | --- |
| Sign out of Connections | Removes this browser session. It does not cancel an active provider attempt, revoke agent grants or remove accepted publisher sessions. |
| Change identity groups | New authentication must satisfy the updated verified claims. Existing browser sessions contain prior claims and expire within 15 minutes; issuer membership is not polled on every request. |
| Change a subject/claim binding | Reload the affected service configuration. Removing a user registration is checked on subsequent browser/API authorization checks. Do not transfer subscriptions by reassigning an alias. |
| Withdraw an allowed audience, scope or agent grant | The gateway applies its token, refresh and cache rules. The owner's publisher connection and unrelated admitted callers remain independent. |
| Rotate or remove a native user token | The registry is read for subsequent authenticated requests. Existing requests may finish; new user applications still require a restart. |
| Cancel an attempt | Its revision cannot publish late; the previously accepted session remains intact. |
| Disconnect a provider | Blocks readers, maintenance and final publication, then drains leases and removes local session/profile authority. Archives and gateway grants remain separate. |

Already admitted work or viewer streams can continue until closed or expired.
Do not claim that a group edit instantly closes every channel. For immediate
containment, deny the affected route/grant and stop or drain the relevant
application workers through the deployment's administrative controls. Preserve
connection barriers, budgets and journals. Revoke publisher-side sessions
separately when required; local Disconnect is not a global publisher sign-out.
The browser's required group and the gateway's group ceiling are separate
checks, even with the same issuer. Gateway membership/ceiling changes follow
gateway token/cache lifetimes; the browser's 15-minute bound does not define them.

Recover through the mapped owner's explicit Connect action. A fresh window must
independently verify the intended subscription, close its browser and publish
under the current session generation, profile lease and connection revision.
Retry incomplete disconnect cleanup while access remains blocked. Do not copy
an old profile into active storage, remove controls, or restore stale accounting
to make recovery appear successful. Restoring a connection never reissues a
gateway grant.

## Shared library and project policy

signin-window provides reusable OIDC validation, opaque browser sessions,
fresh-authentication mechanics, viewer lifecycle and generic browser/attempt
primitives. Newsclip owns user bindings, provider verification, article
entitlement, archives and atomic session/profile publication. Memberships,
gateway grants and installation-specific credential references belong to the
operator's deployment configuration; they do not belong in the generic library.

The [remaining project workplan](../ROADMAP.md) separates implemented controls
from release and deployment acceptance still required for a candidate.

## Storage and tokens

The user registry contains token hashes, not bearer tokens. The setup command
writes generated tokens into private files; it does not print them. Each user's
state and data live below `users/USER/` in the configured state and data roots.
Requests cannot supply a filesystem path, user override, or browser profile.
Article archives and search cursors are isolated alongside subscription state.

New users require a server restart. Token rotation is checked on subsequent
authenticated requests. Rotate with `newsclip users add USER --rotate --config
local/config/users.json --token-file local/tokens/USER-new.token`, then distribute
the new file privately. Keep the original token file until clients have moved;
its contents no longer authorize new requests.

## Limitations

The remote window cannot use a passkey stored on the person's own device. Use a
publisher-supported password/code flow. A publisher may refuse a server's
network or browser, impose additional checks, or change its pages. Newsclip
reports these conditions without treating a partial page as a full article.

The public product does not automate credential entry or purchase subscriptions.
Accounts and API access must already have the permissions the requested content
requires. Diagnostics can contain sensitive browser content and remain private.
