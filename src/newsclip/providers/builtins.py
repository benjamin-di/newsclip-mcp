"""Single explicit map joining each built-in provider's local factories."""

from __future__ import annotations

from dataclasses import replace
from functools import partial

from ..challenges import ChallengeVendor
from ..credential_readiness import check_credential_readiness
from .ap import build_ap_provider
from .axios import build_axios_provider
from .bloomberg import build_bloomberg_provider
from .bloomberg_auth import build_bloomberg_auth_adapter
from .cnbc import build_cnbc_provider
from .economist import build_economist_provider
from .economist_auth import build_economist_auth_adapter
from .ft import build_ft_provider
from .ft_auth import build_ft_auth_adapter
from .guardian import build_guardian_provider
from .nyt import build_nyt_provider
from .nyt_auth import build_nyt_auth_adapter
from .registration import AuthAdapterFactory, BuiltinProviderRegistration
from .reuters import build_reuters_provider
from .wsj import build_wsj_provider
from .wsj_auth import build_wsj_auth_adapter

BUILTIN_PROVIDER_REGISTRATIONS = {
    "ft": BuiltinProviderRegistration(
        build_provider=build_ft_provider,
        approved_challenge_vendors=frozenset({ChallengeVendor.HCAPTCHA}),
    ),
    "wsj": BuiltinProviderRegistration(
        build_provider=build_wsj_provider,
        approved_challenge_vendors=frozenset({ChallengeVendor.DATADOME}),
    ),
    "bloomberg": BuiltinProviderRegistration(
        build_provider=build_bloomberg_provider,
        approved_challenge_vendors=frozenset({ChallengeVendor.PERIMETERX}),
    ),
    "cnbc": BuiltinProviderRegistration(
        build_provider=build_cnbc_provider,
        approved_challenge_vendors=frozenset(),
    ),
    "reuters": BuiltinProviderRegistration(
        build_provider=build_reuters_provider,
        # Passage only: DataDome's Device Check clears itself for a browser it
        # accepts; the slider captcha is never attempted (2026-10-12).
        approved_challenge_vendors=frozenset({ChallengeVendor.DATADOME}),
        passive_challenge_vendors=frozenset({ChallengeVendor.DATADOME}),
    ),
    "economist": BuiltinProviderRegistration(
        build_provider=build_economist_provider,
        approved_challenge_vendors=frozenset(
            {ChallengeVendor.CLOUDFLARE_INTERSTITIAL, ChallengeVendor.DATADOME}
        ),
    ),
    "nyt": BuiltinProviderRegistration(
        build_provider=build_nyt_provider,
        approved_challenge_vendors=frozenset({ChallengeVendor.DATADOME}),
    ),
    "guardian": BuiltinProviderRegistration(
        build_provider=build_guardian_provider,
        approved_challenge_vendors=frozenset(),
    ),
    "ap": BuiltinProviderRegistration(
        build_provider=build_ap_provider,
        approved_challenge_vendors=frozenset({ChallengeVendor.CLOUDFLARE_INTERSTITIAL}),
    ),
    "axios": BuiltinProviderRegistration(
        build_provider=build_axios_provider,
        approved_challenge_vendors=frozenset({ChallengeVendor.CLOUDFLARE_INTERSTITIAL}),
    ),
}


# Registration is inert. Only the credential-bearing maintenance composition
# constructs these adapters; reader services cannot dispatch acquisition.
_AUTH_FACTORIES: dict[str, AuthAdapterFactory] = {
    "ft": build_ft_auth_adapter,
    "wsj": build_wsj_auth_adapter,
    "bloomberg": build_bloomberg_auth_adapter,
    "economist": build_economist_auth_adapter,
    "nyt": build_nyt_auth_adapter,
}
for _key, _factory in _AUTH_FACTORIES.items():
    BUILTIN_PROVIDER_REGISTRATIONS[_key] = replace(
        BUILTIN_PROVIDER_REGISTRATIONS[_key],
        build_auth_adapter=_factory,
        check_credential_readiness=partial(
            check_credential_readiness,
            _key,
            require_vision=_key == "ft",
            require_native_input=_key == "bloomberg",
        ),
    )

BUILTIN_PROVIDER_KEYS = tuple(BUILTIN_PROVIDER_REGISTRATIONS)
BUILTIN_PROVIDER_KEYS_CSV = ", ".join(BUILTIN_PROVIDER_KEYS)
BUILTIN_PROVIDER_KEYS_PROSE = (
    f"{', '.join(BUILTIN_PROVIDER_KEYS[:-1])}, and {BUILTIN_PROVIDER_KEYS[-1]}"
)

__all__ = [
    "BUILTIN_PROVIDER_KEYS",
    "BUILTIN_PROVIDER_KEYS_CSV",
    "BUILTIN_PROVIDER_KEYS_PROSE",
    "BUILTIN_PROVIDER_REGISTRATIONS",
]
