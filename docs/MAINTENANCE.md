# Optional session maintenance

Human sign-in uses mandatory owner OIDC authentication. `connect` returns the
owner's Connections page without starting a window; only the mapped owner's
explicit action opens the provider's page through signin-window. Reader APIs
cannot submit credentials. Importing a session, or
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
authenticates that separate surface; it does not select another user's account
or by itself permit credential minting. Account configuration, credential-store
grants, explicit permission, readiness and budgets still apply. Gateway reader
grants and browser sign-in never admit an agent to this operator surface.

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
inject the dedicated backend credential and identity only after API admission.
For Agentgateway, validate the intended audience, requested scopes, explicit
agent grant and group ceiling before choosing the registered backend user.
Newsclip does not derive those policies from the proxy token. Deny direct backend access
from other callers. Missing, duplicate, unknown or mismatched identities fail
closed; a native user token cannot authorize the proxy header.

`NEWSCLIP_PUBLIC_URL` supports a simple prefix, for example
`https://reader.example.com/newsclip`. The proxy strips that prefix before
forwarding. Generated connection URLs retain it; browser Origin checks use the
bare HTTPS origin. Forward only the documented Connections/viewer routes and
assets to their mandatory OIDC checks, without injecting a backend bearer.
The browser identity must map to the same registered user on every new viewer
admission. Link identifiers are attempt selectors, not independent credentials.
See [Authentication](AUTHENTICATION.md) for revocation, cleanup and recovery;
optional maintenance never makes that browser policy optional.


The optional recovery watcher is a separately supervised process. Set
`NEWSCLIP_USER` to the same account selected by its keeper and operator service;
its recovery store and CLI children use that account's scope. Configure
`NEWSCLIP_KEEPER_PROVIDERS`, credential permission and timeouts explicitly before
running `python -m newsclip.recovery_watch`. Its polling reads local recovery
records; a healthy provider causes no watcher-initiated request.

## Bounded maintenance cycles

Run one account-scoped cycle with the public command:

```sh
newsclip --user alice maintenance-cycle --providers 'ft wsj' --json
newsclip --user alice maintenance-cycle --mode check --providers 'ft wsj guardian' --json
```

Credential submission remains disabled unless `--allow-credential-mint` is given.
Each child has a timeout; provider failures do not skip the next provider. The
JSON document has `schema_version`, `mode`, `ran`, `needs_attention` and `results`.
An active check reservation returns `ran: false` without contacting a provider.
The existing `provider-monitor-next-run-at` ASCII file is retained unchanged;
malformed or unreadable scheduling state fails closed. A cycle lease passes to
child processes, so an interrupted caller cannot overlap a surviving child.

Python supervisors may call `maintenance_cycle.run_maintenance_cycle` and provide
an `on_start` callback for their own notification transport. The result separates
automatic waiting from operator attention. Alert destinations and escalation
preferences belong to the deployment.

## Credential backends

Set `NEWSCLIP_CREDENTIAL_READER=example_backend:create_reader` to select an
explicit trusted backend implementing signin-window's `CredentialReader`
(`available: bool`, `read_field(reference, *, field) -> str`). The factory and
availability check must be inert: they do not fetch credentials or contact a
publisher. Put an opaque reference in the existing per-user maintenance file.
The backend resolves only the requested username, password or generated TOTP.
Without this setting, existing `op://` references use 1Password unchanged.
A custom backend does not require the `op` executable or service-account token.
Origin checks and error redaction apply to every backend, and a failed selected
backend never falls back to another credential identity.


Keeper JSON and account-scoped health inspection expose `current_hold` separately
from `recovery`, which can describe an older completed article recovery. The
projection identifies the exact hold and its source incident, failure class,
creation time and held operation (`provider_check`, the scheduled search/retrieval
sequence). `last_canary_at` records the last incident-canary reservation, including
an interrupted attempt; it does not certify a completed check. For an incident
review hold, `next_eligible_canary_at` is the earliest permitted time (the inspection
time if already eligible); other holds have no permitted canary. This is advisory:
normal scheduling and the guard's locked budget/barrier checks still govern
actual dispatch and evidence-driven clearing. Inspecting these fields makes no
publisher request and does not change holds, journals or budgets. Hold and incident
references remain private to their account and are excluded from another user's
subscription diagnostics.
