# Optional session maintenance

Human sign-in is the default. `connect` opens the provider's real page through
signin-window. Reader APIs cannot submit credentials. Importing a session, or
successfully signing in, never proves that an arbitrary article is available:
Newsclip independently checks its identity, access state and completeness.

Operators can also run bounded maintenance for accounts they control. The same
public package contains the provider drivers, session keeper and recovery policy.
The shared signin-window library owns durable attempt accounting, profile process
ownership, native pointer input and bounded CAPTCHA mechanics. Applications keep
their own site verification and snapshot formats.

## Configuration and authority

Set `NEWSCLIP_CONFIG_HOME` to a private configuration directory. Local unscoped
commands read `maintenance.json` there. Commands using `--user alice` read
`users/alice/maintenance.json` instead. A missing file disables credential
acquisition for that account. There is no fallback to another user's settings.

```json
{
  "version": 1,
  "providers": {
    "ft": {"credential_reference": "op://Example/Subscription"},
    "guardian": {"api_key_reference": "op://Example/Search/credential"}
  }
}
```

References are configuration, never repository content. Keep their real account
names and identifiers private. The worker resolves only the explicitly supplied
1Password service identity; a failed read never obtains a different identity.
Grant access only to the selected account's credentials. Environment API keys,
including `NEWSCLIP_SEARCH_API_KEY_GUARDIAN`, remain available for deployments
whose reader should have no secret-store authority.

The server and browser must see the same canonical paths for shared profiles,
state and locks. A worker selecting `--user alice` uses `/state/users/alice` when
`NEWSCLIP_STATE_HOME=/state`; the reader and human sign-in browser use that same
path. Run one maintenance owner for each account. Do not copy a live profile or
restore older attempt budgets, holds or recovery state during rollback.

## Bounded worker

The `newsclip-login-browser` image also supports a separately launched maintenance
worker. It contains the same product, Chromium, Xvfb and native input library. It also has an SSH client for
operator-supplied planner transports. It contains no credentials, model grants,
private configuration or scheduler. Install a supported secret-store CLI
separately and mount its verified executable read-only into the worker (for
1Password, `/usr/local/bin/op`). The proprietary executable is not redistributed
in the MIT public images; obtain it under its own vendor terms.

Run the CLI with an external scheduler, selecting the account explicitly:

```sh
newsclip --user alice auth keep ft --json --allow-credential-mint
```

Reuse and verification come first. A credential attempt requires explicit
permission, configured references, readiness, an available durable budget and no
blocking hold or cooldown. Failed or interrupted attempts remain counted. A
challenge, outage or incomplete article is not automatically proof that a person
must sign in again. The existing verification, recovery and escalation limits
apply to both scheduled and manual maintenance.

Keep the worker on a private network, with no published port. Mount only its
account's required state/configuration and supply its narrowly scoped secret
identity. Third parties can use the Python provider/secret-filler contracts with
other secret stores. Do not pass credentials through MCP tools.

## Optional visual planning

`NEWSCLIP_CHALLENGE_MODE` defaults to `detect-only`. Set it to `auto` only for a
process authorized to act on the provider's approved challenge surfaces.
`NEWSCLIP_VISION_PLANNER` selects an additional visual planner explicitly:

- Unset: retain detection and require human action for image challenges.
- `local`: use an installed and authenticated local model CLI with restricted
  child environment, image-only access, a bounded deadline and validated plans.
- `example_backend:build_planner`: import an operator-installed zero-argument
  factory returning signin-window's `VisionPlanner` contract.

The factory is trusted operator code. It belongs in an installed integration or
private deployment configuration. No planner is discovered automatically.
A planner sees only the captured task and instruction; it does not need account
credentials or access to the browser profile. Preserve the exact task binding,
geometry validation, deadlines and provider acceptance checks. Model output alone
never establishes challenge acceptance.

## Operator API

`NEWSCLIP_MCP_OPS=1` selects a separate operator surface. Supply a dedicated
`NEWSCLIP_OPS_BEARER_TOKEN`, distinct from every reader/proxy credential. Bind it
to the private network and restrict the external route to operators. The token
alone grants repair authority; ordinary reader authorization must not admit it.

Set `NEWSCLIP_USER=alice` on an operator instance to select the same account for
stored health and its CLI children. Stored health, guarded provider checks and
credential-free recovery do not need a secret-store identity. Credential minting
still checks readiness and requires its explicit permission and budget. Do not
supply secret-store access to an instance that only needs stored health.

## Trusted reverse proxies

Native users authenticate at `/users/USER/mcp` or `/users/USER/api/...` with their
own token. A trusted proxy can instead use `/mcp` and `/api/...` by supplying both
`NEWSCLIP_TRUSTED_PROXY_TOKEN` and the selected user's header. Configure the
header name with `NEWSCLIP_TRUSTED_USER_HEADER` (default
`X-Authenticated-User`). The user must exist in the private user registry.
Use `newsclip users add-proxy alice --config /private/users.json` when the
proxy handles authentication. This creates no additional bearer credential;
native-token users can coexist in the same registry.

Strip client-supplied copies at the edge, authenticate the person there, then
inject the dedicated backend credential and identity. Deny direct backend access
from other callers. Missing, duplicate, unknown or mismatched identities fail
closed; a native user token cannot authorize the proxy header.

`NEWSCLIP_PUBLIC_URL` supports a simple prefix, for example
`https://reader.example.com/newsclip`. The proxy strips that prefix before
forwarding. Generated connection URLs retain it; browser Origin checks use the
bare HTTPS origin. Forward only the exact one-time connection routes and assets
without edge authentication, and never inject a backend bearer into those links.
The relay validates their independent, expiring authority.


The optional recovery watcher is a separately supervised process. Set
`NEWSCLIP_USER` to the same account selected by its keeper and operator service;
its recovery store and CLI children use that account's scope. Configure
`NEWSCLIP_KEEPER_PROVIDERS`, credential permission and timeouts explicitly before
running `python -m newsclip.recovery_watch`. Its polling reads local recovery
records; a healthy provider causes no watcher-initiated request.
