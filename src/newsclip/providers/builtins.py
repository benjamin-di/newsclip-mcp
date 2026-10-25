"""Single explicit map joining each built-in provider's local factories."""

from __future__ import annotations

from ..challenges import ChallengeVendor
from ..extensions import local_extensions
from .ap import build_ap_provider
from .axios import build_axios_provider
from .bloomberg import build_bloomberg_provider
from .cnbc import build_cnbc_provider
from .economist import build_economist_provider
from .ft import build_ft_provider
from .guardian import build_guardian_provider
from .nyt import build_nyt_provider
from .registration import BuiltinProviderRegistration
from .reuters import build_reuters_provider
from .wsj import build_wsj_provider

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


_extension = local_extensions()
if _extension is not None:
    BUILTIN_PROVIDER_REGISTRATIONS = _extension.configure_providers(
        BUILTIN_PROVIDER_REGISTRATIONS
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
