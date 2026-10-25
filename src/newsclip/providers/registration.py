"""Explicit construction contract for one built-in provider."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ..challenge_resolver import ChallengeResolver
from ..challenges import ChallengeVendor
from ..contracts import LoginRecipe, SessionAcquisitionAdapter
from ..models import ProviderReadiness
from ..provider_config import ProviderSpec
from .base import Provider

type ProviderFactory = Callable[[ProviderSpec, str | None], Provider]
type AuthAdapterFactory = Callable[
    [LoginRecipe, ProviderSpec, ChallengeResolver],
    SessionAcquisitionAdapter,
]
type CredentialReadinessProbe = Callable[[], ProviderReadiness]


@dataclass(frozen=True, slots=True)
class BuiltinProviderRegistration:
    build_provider: ProviderFactory
    approved_challenge_vendors: frozenset[ChallengeVendor]
    build_auth_adapter: AuthAdapterFactory | None = None
    check_credential_readiness: CredentialReadinessProbe | None = None
    #: Approved vendors whose surface this provider may only wait out, never
    #: act on. A subset of ``approved_challenge_vendors``.
    passive_challenge_vendors: frozenset[ChallengeVendor] = frozenset()


def validate_builtin_registrations(
    specs: Sequence[ProviderSpec],
    registrations: Mapping[str, BuiltinProviderRegistration],
) -> None:
    """Fail before construction if definitions and registrations diverge."""

    definition_keys = {spec.key for spec in specs}
    registration_keys = set(registrations)
    if definition_keys != registration_keys:
        missing = sorted(definition_keys - registration_keys)
        unknown = sorted(registration_keys - definition_keys)
        raise RuntimeError(
            f"provider registration mismatch (missing={missing}, unknown={unknown})"
        )
    for spec in specs:
        registration = registrations[spec.key]
        if not (
            registration.passive_challenge_vendors
            <= registration.approved_challenge_vendors
        ):
            raise RuntimeError(
                f"provider registration passive challenge vendor unapproved: {spec.key}"
            )
        session_backed = spec.capabilities.session_kind != "none"
        if not session_backed and registration.build_auth_adapter is not None:
            raise RuntimeError(
                f"provider registration auth capability mismatch: {spec.key}"
            )
        if (registration.build_auth_adapter is not None) != (
            registration.check_credential_readiness is not None
        ):
            raise RuntimeError(
                "provider registration credential-readiness capability mismatch: "
                f"{spec.key}"
            )


__all__ = [
    "AuthAdapterFactory",
    "BuiltinProviderRegistration",
    "CredentialReadinessProbe",
    "ProviderFactory",
    "validate_builtin_registrations",
]
