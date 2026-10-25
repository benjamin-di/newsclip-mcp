# Authentication and user isolation

The standalone server uses [signin-window](https://github.com/benjamin-di/signin-window)
to let a person sign in on a publisher's actual page from a phone or browser.
The browser itself runs on the server. Passwords, verification codes and
interactive challenges are entered by the person; the assistant receives only
a link and session status.

1. Authenticate to your own user URL and request `auth connect PROVIDER` or the
   MCP `connect` tool.
2. Open the expiring link and complete the publisher's sign-in. A phone layout
   and paste support are available in the viewer.
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
