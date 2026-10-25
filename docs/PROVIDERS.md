# Provider support

Providers are explicit built-in adapters, not a universal crawler. All ten are
registered; use `NEWSCLIP_PROVIDER_ALLOWLIST` or repeated CLI `--source` flags to
select a subset. Site changes, account entitlements and network reputation can
affect a provider independently of the installed software version.

| Provider | Discovery | Retrieval | Required access |
|---|---|---|---|
| Financial Times (`ft`) | Public HTML search | HTTP | Existing subscription session |
| Wall Street Journal (`wsj`) | Public browser search | Retained browser | Existing subscription session |
| Bloomberg (`bloomberg`) | Session-backed search API | Retained browser | Existing subscription session |
| CNBC (`cnbc`) | Public API | HTTP | Public access |
| Reuters (`reuters`) | Rolling news sitemap | HTTP with bounded browser fallback | Public access |
| The Economist (`economist`) | Session-backed HTML search | Retained browser | Existing subscription session |
| New York Times (`nyt`) | Public browser search | Retained browser | Verified subscription session for full-content acceptance |
| The Guardian (`guardian`) | Open Platform API | Open Platform API | Operator's registered API key and permissions |
| AP News (`ap`) | Rolling news sitemap | HTTP | Public access |
| Axios (`axios`) | Rolling news sitemap | HTTP with bounded browser fallback | Public national/Local articles; gated Pro routes unsupported |

Rolling sitemaps cover a moving window rather than a publisher's historical
archive. Source status reports `coverage_start`; no matches do not establish
that a publisher has never covered the subject. Search dates can be missing;
under date bounds, undated results are withheld and counted. `newest` sorts
only the returned bounded page, not a global publisher corpus.

## Adding or fixing a provider

Definitions in `src/newsclip/provider_definitions` describe URL ownership,
search endpoints, article signals, negative gates, rate budgets and session
verification. The explicit registry in `providers/builtins.py` joins each
definition to an adapter. Provider-specific code belongs in that adapter.

Use synthetic examples for full content, teasers, authentication walls,
challenges, wrong identities and incomplete pages. A provider requiring a
session needs an access verifier; it does not need a credential-entry adapter.
Choose an owned verification article that demonstrates the intended access.
Manual sign-in resource hosts belong in `signin.py` and must be justified by
that provider's actual flow. Never allow arbitrary user-supplied hosts or URLs
inside a sign-in window.

Run offline checks and explicit private provider acceptance for changed live
behavior. Public CI never needs publisher credentials or paid article bodies.
