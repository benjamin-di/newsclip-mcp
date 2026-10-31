"""Explicit product composition without import-time I/O."""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import (
    ExitStack,
    contextmanager,
    nullcontext,
    suppress,
)
from contextvars import copy_context
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from curl_cffi.requests import BrowserTypeLiteral

from .acquisition import CandidateVerificationMode
from .api_keys import ConfiguredSecretReader, SecretResolutionError
from .archive import ArchiveStore
from .browser_profiles import BrowserProfileManager
from .browser_readiness import readiness_coverage_bucket
from .browser_retrieval import (
    BrowserReadinessEvaluator,
    BrowserReadinessObservation,
    PatchrightBrowserRetriever,
    SingleNavigationBrowserClient,
)
from .browser_runtime import (
    BrowserLaunchConfig,
    HttpOperationRole,
    LeaseManager,
    PatchrightRuntime,
    RuntimeTrace,
)
from .challenge_catalog import build_challenge_resolver
from .challenge_detection import detect_challenge_for_reads
from .challenge_transport import ChallengeAwareHttpClient
from .challenges import ChallengeMode
from .connection_controls import ConnectionControls
from .contracts import HttpClient, LoginRecipe, SessionAcquisitionAdapter
from .defense import DefenseState
from .errors import (
    OperatorActionRequiredError,
    PersistenceError,
    ProviderTransportError,
    UsageError,
)
from .extraction import TrafilaturaExtractor
from .http import CurlCffiHttpClient
from .http_challenges import HttpChallengeStore
from .incidents import IncidentStore
from .keeper_outcomes import KeeperOutcomeStore
from .models import (
    DEFAULT_HTTP_IMPERSONATION,
    HTTP_IMPERSONATION_PROFILES,
    AccessState,
    PortableCookie,
    ProviderReadiness,
    RawFetch,
    SessionArtifact,
    SessionVerification,
)
from .network import ProviderNetworkPolicy
from .provenance import resolve_build_identity
from .provider_config import (
    AdapterSearchSpec,
    ProviderSpec,
    load_builtin_provider_specs,
)
from .provider_guard import ProviderGuard, ProviderGuardStore
from .providers.base import (
    BrowserPaidProofCompleteness,
    BrowserSnapshotCompleteness,
    Provider,
)
from .providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS
from .providers.registration import (
    CredentialReadinessProbe,
    validate_builtin_registrations,
)
from .providers.registry import ProviderRegistry
from .recovery import RecoveryStore
from .service import NewsclipService
from .session_keeper import CredentialBudget, KeeperPolicy, SessionKeeper
from .sessions import ServingSessions, SessionStore
from .tenancy import (
    application_root,
    current_user,
    require_user,
    scope_path,
    user_scope,
)
from .timing import (
    TimingRecorder,
    TimingRunMode,
    current_timing_invocation_id,
)
from .trace_retention import prune_runtime_traces
from .transport_pins import TransportDrip, TransportPinResolver, TransportPinStore

_PROVIDER_ALLOWLIST_ENVIRONMENT = "NEWSCLIP_PROVIDER_ALLOWLIST"


def build_registry() -> ProviderRegistry:
    """Register the promoted product providers in configured order."""

    specs = load_builtin_provider_specs()
    validate_builtin_registrations(specs, BUILTIN_PROVIDER_REGISTRATIONS)
    allowlist = _provider_allowlist(specs)
    selected_specs = (
        specs
        if allowlist is None
        else tuple({spec.key: spec for spec in specs}[key] for key in allowlist)
    )
    providers = []
    for spec in selected_specs:
        if allowlist is None and not _provider_enabled(spec):
            continue
        verification_url = _verification_url(spec) if spec.session is not None else None
        provider = BUILTIN_PROVIDER_REGISTRATIONS[spec.key].build_provider(
            spec, verification_url
        )
        if not isinstance(provider, Provider):
            raise RuntimeError(f"provider factory contract incomplete: {spec.key}")
        if provider.key != spec.key or provider.capabilities != spec.capabilities:
            raise RuntimeError(f"provider factory contract mismatch: {spec.key}")
        recipe = provider.login_recipe
        session_backed = spec.capabilities.session_kind == "cookie"
        if session_backed != (recipe is not None) or (
            recipe is not None and recipe.provider != spec.key
        ):
            raise RuntimeError(f"provider factory login contract mismatch: {spec.key}")
        providers.append(provider)
    return ProviderRegistry(tuple(providers))


def build_service() -> NewsclipService:
    """Construct the local application only when an operation is invoked."""

    return _build_service(
        include_archive=True, retain_browser_profile=True, include_acquisition=True
    )


def build_mcp_service(*, user: str | None = None) -> NewsclipService:
    """Construct the long-lived MCP service with request-scoped browser leases."""

    with user_scope(user) if user is not None else nullcontext():
        return _build_service(
            include_archive=True,
            retain_browser_profile=False,
            include_acquisition=False,
        )


def build_connection_reader(
    *, requester: str, owner: str, budget_owner: ProviderNetworkPolicy
) -> NewsclipService:
    """An internal reader with owner-native authority and requester-private output.

    The host must authorize a specific publisher before admitting an operation.
    This constructor supplies no acquisition collaborators or sharing authority.
    """
    from .tenancy import require_user

    require_user(requester)
    require_user(owner)
    with user_scope(owner):
        return _build_service(
            include_archive=True,
            retain_browser_profile=False,
            include_acquisition=False,
            requester=requester,
            network_budget_owner=budget_owner,
        )


def build_auth_service(*, user: str | None = None) -> NewsclipService:
    """Construct authentication capabilities without opening the archive."""

    with user_scope(user) if user is not None else nullcontext():
        return _build_service(
            include_archive=False, retain_browser_profile=True, include_acquisition=True
        )


def build_provider_guard() -> ProviderGuard:
    """Construct the private scheduled-check guard without provider I/O."""

    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
    build_identity = resolve_build_identity(Path(__file__).resolve().parents[2])
    return ProviderGuard(
        registry=build_registry(),
        store=ProviderGuardStore(
            state_root / "provider-guard",
            build_identity=build_identity,
            diagnostic_id=current_timing_invocation_id(),
            incident_root=state_root / "incidents",
        ),
    )


def build_session_keeper(
    sessions: NewsclipService,
    *,
    policy: KeeperPolicy | None = None,
) -> SessionKeeper:
    """Construct the scheduled keeper over an already-built session service."""

    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")

    def utc_now() -> datetime:
        return datetime.now(UTC)

    def readiness_probe(provider: str) -> ProviderReadiness | None:
        registration = BUILTIN_PROVIDER_REGISTRATIONS.get(provider)
        if registration is None or registration.check_credential_readiness is None:
            return None
        return registration.check_credential_readiness()

    declared_profiles = {
        spec.key: spec.capabilities.http_impersonate
        for spec in load_builtin_provider_specs()
        if spec.capabilities.retrieval_challenge_escalation == "browser"
    }
    return SessionKeeper(
        guard=build_provider_guard(),
        sessions=sessions,
        budget=CredentialBudget(
            state_root / "session-keeper",
            utc_now=utc_now,
        ),
        readiness_probe=readiness_probe,
        policy=policy or KeeperPolicy(),
        utc_now=utc_now,
        diagnostic_id=current_timing_invocation_id(),
        outcomes=build_keeper_outcome_store(),
        recovery_store=RecoveryStore(state_root / "recovery"),
        challenge_mode=_read_path_challenge_mode(),
        # The slow-drip re-pin rides the cycle that already runs (R8). Its
        # probe is the exempt diagnostic seam: no defense gate, no arm, no
        # capsule, no observation.
        transport_pins=TransportDrip(
            build_transport_pin_store(),
            declared_profiles=declared_profiles,
            probe=sessions.probe_transport_candidate,
        ),
        http_challenges=build_http_challenge_store(),
    )


def build_defense_state(
    *, incident_root: Path | None = None, incident_owner: str | None = None
) -> DefenseState:
    """The shared per-provider defense containment store."""

    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
    return DefenseState(
        state_root / "provider-defense",
        incident_root=incident_root
        if incident_root is not None
        else state_root / "incidents",
        incident_owner=incident_owner,
    )


def build_transport_pin_store() -> TransportPinStore:
    """The shared runtime transport-pin store (R8)."""

    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
    return TransportPinStore(state_root / "transport-pins")


def build_http_challenge_store() -> HttpChallengeStore:
    """The shared log of HTTP legs refused while the browser served."""

    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
    return HttpChallengeStore(state_root / "http-challenges")


def _session_evidence_target(provider: str) -> str | None:
    try:
        return build_provider_guard().session_evidence_target(provider)
    except PersistenceError:
        # Missing targeting evidence grants no authority to clear a hold.
        return None


def _clear_session_evidence_hold(provider: str, hold_id: str) -> None:
    """Clear a session-evidence hold after a positive live verification."""

    try:
        build_provider_guard().clear_session_evidence(provider, hold_id=hold_id)
    except PersistenceError:
        return


def build_keeper_outcome_store() -> KeeperOutcomeStore:
    """The durable keeper-verdict store `session_status` derives health from."""

    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
    return KeeperOutcomeStore(
        state_root / "session-keeper", incident_root=state_root / "incidents"
    )


def _build_service(
    *,
    include_archive: bool,
    retain_browser_profile: bool,
    include_acquisition: bool,
    requester: str | None = None,
    network_budget_owner: ProviderNetworkPolicy | None = None,
) -> NewsclipService:
    with ExitStack() as rollback:
        service = _compose_service(
            include_archive=include_archive,
            retain_browser_profile=retain_browser_profile,
            include_acquisition=include_acquisition,
            rollback=rollback,
            requester=requester,
            network_budget_owner=network_budget_owner,
        )
        # The completed service owns its transports from this point onward.
        rollback.pop_all()
        return service


def _close_after_build_failure(close: Callable[[], None]) -> None:
    # Attempt all cleanup without replacing the original construction failure.
    with suppress(Exception):
        close()


def _compose_service(
    *,
    include_archive: bool,
    retain_browser_profile: bool,
    include_acquisition: bool,
    rollback: ExitStack,
    requester: str | None = None,
    network_budget_owner: ProviderNetworkPolicy | None = None,
) -> NewsclipService:
    registry = build_registry()
    enabled_keys = set(registry.keys())
    specs = {
        spec.key: spec
        for spec in load_builtin_provider_specs()
        if spec.key in enabled_keys
    }
    extractor = TrafilaturaExtractor()
    state_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
    with user_scope(requester) if requester is not None else nullcontext():
        request_root = _application_root("NEWSCLIP_STATE_HOME", ".local/state")
        timing_root = _timing_root(request_root)
        trace_root = _trace_root(request_root)
        data_root = _application_root("NEWSCLIP_DATA_HOME", ".local/share")
        request_actor = current_user()
    with user_scope(None):
        user_state_root = (
            _application_root("NEWSCLIP_STATE_HOME", ".local/state") / "users"
        )
    build_identity = resolve_build_identity(Path(__file__).resolve().parents[2])
    # Every process using the configured state tree must share one lease
    # authority. In production the MCP and maintenance processes mount the
    # same /state directory but have intentionally-isolated home directories.
    lease_manager = LeaseManager(state_root / "locks")
    run_id = f"browser-{uuid4().hex[:16]}"
    runtime_trace = RuntimeTrace(
        trace_root / f"{run_id}.jsonl",
        run_id=run_id,
        # The outer gate can fail after a successful login (JSON contract,
        # retrieval, archive); it owns cleanup once the whole provider passes.
        retain_success_artifacts=os.environ.get("NEWSCLIP_LIVE_MODE")
        in {"warm", "cold"},
    )
    if os.environ.get("NEWSCLIP_LIVE_MODE") not in {"warm", "cold"}:
        # Live gates own their per-invocation trace root until the verdict.
        prune_runtime_traces(trace_root, current_run_id=run_id)
    pin_store = TransportPinStore(state_root / "transport-pins")
    # Read per fetch, not per process: the keeper promotes a pin from a
    # different container over the shared state mount, and this process may
    # run for days (R8).
    pin_resolver = TransportPinResolver(
        pin_store,
        providers_by_host=_pinnable_hosts(specs.values()),
    )
    http = CurlCffiHttpClient(
        impersonate_by_host=_http_impersonation_by_host(specs.values()),
        runtime_impersonate_by_host=pin_resolver.for_host,
        headers_by_host=_http_headers_by_host(specs.values()),
        trace=runtime_trace,
    )
    rollback.callback(_close_after_build_failure, http.close)
    runtime = PatchrightRuntime(trace=runtime_trace)
    cookie_recipes: dict[str, LoginRecipe] = {}
    for provider in registry:
        recipe = provider.login_recipe
        if recipe is not None and provider.capabilities.session_kind == "cookie":
            cookie_recipes[provider.key] = recipe
    challenge_resolvers = {
        provider.key: build_challenge_resolver(
            BUILTIN_PROVIDER_REGISTRATIONS[provider.key].approved_challenge_vendors,
            passive_vendors=BUILTIN_PROVIDER_REGISTRATIONS[
                provider.key
            ].passive_challenge_vendors,
        )
        for provider in registry
    }
    browser_providers = {
        provider.key: provider
        for provider in registry
        if (
            provider.capabilities.retrieval_transport == "browser"
            or provider.capabilities.search_transport == "browser"
            or provider.capabilities.retrieval_challenge_escalation == "browser"
            or bool(challenge_resolvers[provider.key].supported_vendors)
        )
    }
    profile_keys = set(cookie_recipes) | set(browser_providers)
    profile_launch_configs = {
        key: _browser_launch_config(specs[key]) for key in profile_keys
    }
    profiles = BrowserProfileManager(
        state_root / "browser-profiles",
        runtime=runtime,
        launch_configs=profile_launch_configs,
    )
    # One network policy for the whole process: retrieval, read-path probes,
    # and SessionStore verification all draw from the same per-provider token
    # bucket, so no store traffic is unmetered.
    connection_controls = ConnectionControls(state_root)

    def authorize_session(artifact: SessionArtifact) -> None:
        connection_controls.require_active(artifact.provider, artifact.account_key)

    network = ProviderNetworkPolicy(
        http, authorize_session=authorize_session, budget_owner=network_budget_owner
    )
    budgets = {provider.key: provider.rate_budget() for provider in registry}
    browser_retriever: PatchrightBrowserRetriever | None = None
    if browser_providers:
        browser_retriever = PatchrightBrowserRetriever(
            lease_manager=lease_manager,
            runtime=runtime,
            profile_resolver=profiles.path,
            authorize_session=authorize_session,
            policies={key: specs[key].browser_retrieval for key in browser_providers},
            readiness_evaluators={
                key: _browser_readiness_evaluator(browser_providers[key], extractor)
                for key in browser_providers
            },
            verification_readiness_evaluators={
                key: _browser_readiness_evaluator(
                    browser_providers[key], extractor, verification=True
                )
                for key, provider in browser_providers.items()
                if isinstance(provider, BrowserPaidProofCompleteness)
            },
            launch_configs={
                key: profile_launch_configs[key] for key in browser_providers
            },
            # Read-path resolvers classify identically but prefilter the
            # native shadow-root sweep, which otherwise queues dozens of
            # driver roundtrips behind a just-navigated busy main thread.
            # Acquisition adapters keep the unfiltered detector above.
            challenge_resolvers={
                key: build_challenge_resolver(
                    BUILTIN_PROVIDER_REGISTRATIONS[key].approved_challenge_vendors,
                    passive_vendors=BUILTIN_PROVIDER_REGISTRATIONS[
                        key
                    ].passive_challenge_vendors,
                    detector=detect_challenge_for_reads,
                )
                for key in browser_providers
            },
            challenge_mode=_read_path_challenge_mode(),
            require_virtual_display=True,
            retain_profile=retain_browser_profile,
            session_cookie_domains={
                key: recipe.allowed_cookie_domains
                for key, recipe in cookie_recipes.items()
            },
        )
        rollback.callback(_close_after_build_failure, browser_retriever.close)
    adapters: dict[str, SessionAcquisitionAdapter] = {}
    credential_readiness_probes: dict[str, CredentialReadinessProbe] = {}
    for key, recipe in cookie_recipes.items() if include_acquisition else ():
        spec = specs[key]
        if spec.auth is None:  # pragma: no cover - schema invariant
            raise RuntimeError("authenticated provider has no auth configuration")
        factory = BUILTIN_PROVIDER_REGISTRATIONS[key].build_auth_adapter
        if factory is None or not recipe.secret_ref:
            continue
        adapter = factory(recipe, spec, challenge_resolvers[key])
        if not isinstance(adapter, SessionAcquisitionAdapter):
            raise RuntimeError(f"provider auth factory contract incomplete: {key}")
        if adapter.provider != key:
            raise RuntimeError(f"provider auth factory contract mismatch: {key}")
        adapters[key] = adapter
        readiness_probe = BUILTIN_PROVIDER_REGISTRATIONS[key].check_credential_readiness
        if readiness_probe is None:  # pragma: no cover - registration invariant
            raise RuntimeError(
                "authenticated provider has no credential-readiness probe"
            )
        credential_readiness_probes[key] = readiness_probe

    @contextmanager
    def verification_client_with_attempts(
        key: str,
        *,
        max_attempts: Literal[1, 2],
        published_profile: bool = False,
    ) -> Iterator[HttpClient]:
        provider = registry.get(key)
        if provider.capabilities.retrieval_transport == "browser":
            if browser_retriever is None:
                raise RuntimeError("browser verification transport is unavailable")
            if published_profile:
                # Read-path proof uses the already bound profile, whose cookie
                # jar can change during browsing. Only explicit acquisition
                # publishes its exported authority; imports stay strict below.
                browser, _ = browser_retriever.profile_verification_client(key)
                max_attempts = 1
            else:
                browser = browser_retriever.for_provider(
                    key,
                    role=HttpOperationRole.VERIFICATION,
                )
            browser_http: HttpClient = browser
            if max_attempts == 1:
                browser_http = SingleNavigationBrowserClient(browser)
            try:
                yield network.for_provider(
                    key,
                    budgets[key],
                    browser_http,
                    retry_response=getattr(provider, "retry_response", None),
                    role=HttpOperationRole.VERIFICATION,
                    max_attempts=max_attempts,
                )
            except BaseException:
                # Verification can run immediately before a session-store write.
                # Release the long-lived profile lease before any lower-ranked
                # session/attempt lease is acquired. Cleanup must not replace a
                # primary provider/transport failure.
                with suppress(Exception):
                    browser_retriever.release()
                raise
            else:
                # A successful verification must close its profile before
                # publication. Cleanup failure cannot certify a candidate.
                browser_retriever.release()
            return
        with CurlCffiHttpClient(trace=runtime_trace) as verification_http:
            primary = network.for_provider(
                key,
                budgets[key],
                verification_http,
                retry_response=getattr(provider, "retry_response", None),
                role=HttpOperationRole.VERIFICATION,
                max_attempts=max_attempts,
            )
            fallback = None
            if browser_retriever is not None and (
                provider.capabilities.retrieval_challenge_escalation == "browser"
                or browser_retriever.allows_http_fallback(key)
            ):
                if published_profile:
                    fallback_browser, _ = browser_retriever.profile_verification_client(
                        key
                    )
                else:
                    fallback_browser = browser_retriever.for_provider(
                        key,
                        role=HttpOperationRole.VERIFICATION,
                    )
                fallback_http: HttpClient = fallback_browser
                if max_attempts == 1 or published_profile:
                    fallback_http = SingleNavigationBrowserClient(fallback_browser)
                fallback = network.for_provider(
                    key,
                    budgets[key],
                    fallback_http,
                    role=HttpOperationRole.VERIFICATION,
                    max_attempts=1,
                )
            client = ChallengeAwareHttpClient(
                key,
                primary,
                is_challenge=provider.is_interactive_challenge,
                browser_fallback=fallback,
            )
            try:
                yield client
            finally:
                if fallback is not None and browser_retriever is not None:
                    with suppress(Exception):
                        browser_retriever.release()

    @contextmanager
    def verification_client(key: str) -> Iterator[HttpClient]:
        with verification_client_with_attempts(key, max_attempts=2) as client:
            yield client

    @contextmanager
    def read_verification_client(key: str) -> Iterator[HttpClient]:
        with verification_client_with_attempts(
            key, max_attempts=2, published_profile=True
        ) as client:
            yield client

    @contextmanager
    def provider_check_verification_client(key: str) -> Iterator[HttpClient]:
        with verification_client_with_attempts(
            key, max_attempts=1, published_profile=True
        ) as client:
            yield client

    def verification_requires_browser(key: str) -> bool:
        # Prepare for browser-paid acquisition before taking session locks.
        # The scoped existing-artifact verifier below chooses the provider's
        # serving transport; candidate/import proof keeps the recipe's policy.
        provider = registry.get(key)
        recipe = provider.login_recipe
        return provider.capabilities.retrieval_transport == "browser" or (
            recipe is not None
            and recipe.candidate_verification_mode
            is CandidateVerificationMode.BROWSER_PAID_PROBE
        )

    def verify_profile(
        recipe: LoginRecipe, artifact: SessionArtifact
    ) -> tuple[SessionVerification, tuple[PortableCookie, ...]]:
        key = recipe.provider
        provider = registry.get(key)
        if provider.capabilities.retrieval_transport == "http":
            # Existing portable authority must prove the transport it serves.
            # FT's browser-paid policy remains mandatory for minted/imported
            # candidates; it must not turn warm HTTP proof into an extra,
            # independently defended browser request or publish browser cookies.
            # Preserve the serving connection and response-cookie affinity;
            # recreating a client here discards state established by reads.
            # Apply the same bounded HTTP policy, including the provider's
            # exact non-interactive response retry fingerprint.
            primary = network.for_provider(
                key,
                budgets[key],
                http,
                retry_response=getattr(provider, "retry_response", None),
                role=HttpOperationRole.VERIFICATION,
                max_attempts=2,
            )
            warm_http = ChallengeAwareHttpClient(
                key,
                primary,
                is_challenge=provider.is_interactive_challenge,
                browser_fallback=None,
            )
            return recipe.verify(warm_http, artifact), artifact.cookies
        if browser_retriever is None:
            raise ProviderTransportError(
                "browser verification transport is unavailable"
            )
        browser, capture = browser_retriever.profile_verification_client(key)
        client = network.for_provider(
            key,
            budgets[key],
            SingleNavigationBrowserClient(browser),
            role=HttpOperationRole.VERIFICATION,
            max_attempts=1,
        )
        try:
            verification = recipe.verify(client, artifact)
        except BaseException:
            with suppress(Exception):
                browser_retriever.release()
            raise
        else:
            browser_retriever.release()
        if capture.cookies is None:
            raise ProviderTransportError("browser verification exported no authority")
        return verification, capture.cookies

    sessions = SessionStore(
        state_root,
        recipes=cookie_recipes,
        adapters=adapters,
        credential_readiness_probes=credential_readiness_probes,
        http=http,
        client_factory=verification_client,
        lease_manager=lease_manager,
        profile_access=profiles,
        verification_requires_browser=verification_requires_browser,
        diagnostic_trace=runtime_trace,
        profile_verifier=verify_profile,
    )
    archive = None
    if include_archive:
        archive = ArchiveStore(
            data_root / "archive.sqlite3", registry=registry, extractor=extractor
        )
    construction_context = copy_context()
    service = NewsclipService(
        registry,
        http,
        extractor,
        sessions=sessions if include_acquisition else ServingSessions(sessions),
        archive=archive,
        browser_retriever=browser_retriever,
        network=network,
        verification_client_factory=read_verification_client,
        provider_check_verification_client_factory=(provider_check_verification_client),
        timing=TimingRecorder(
            timing_root,
            run_mode=_timing_run_mode(),
            build_identity=build_identity,
        ),
        incidents=IncidentStore(
            request_root / "incidents",
            build_identity=build_identity,
            protected_incidents=lambda provider: (
                _protected_incidents(request_root, provider, build_identity)
                | (
                    _shared_defense_incidents(user_state_root, provider, request_actor)
                    if request_actor is not None
                    else frozenset()
                )
            ),
            evidence_root=(
                trace_root / "incidents"
                if os.environ.get("NEWSCLIP_INVOCATION_ID")
                else None
            ),
        ),
        keeper_outcomes=KeeperOutcomeStore(
            state_root / "session-keeper", incident_root=state_root / "incidents"
        ),
        recovery_store=RecoveryStore(state_root / "recovery")
        if requester is None
        else None,
        defense=build_defense_state(
            incident_root=request_root / "incidents", incident_owner=requester
        ),
        # Session-evidence holds clear on the verification event itself
        # (ARCHITECTURE, "Session upkeep"). Guard construction is deferred to the rare
        # verification moment rather than paid on every service build.
        on_session_verified=lambda provider, hold_id: construction_context.copy().run(
            _clear_session_evidence_hold, provider, hold_id
        ),
        session_evidence_target=lambda provider: construction_context.copy().run(
            _session_evidence_target, provider
        ),
        on_challenge_escalation_served=_escalation_recorder(
            _transport_rot_recorder(state_root, specs),
            _http_challenge_recorder(state_root, specs),
        ),
        transport_browser_first=pin_resolver.browser_first,
    )
    return service


def _pinnable_hosts(specs: Iterable[ProviderSpec]) -> dict[str, str]:
    """Map every host whose provider may carry a runtime pin to that provider.

    Only providers that declare the escalation participate: the runtime pin
    exists to heal a rot signal, and only a declared escalation can record
    one. Session providers are excluded by the same schema rule that already
    forbids them a per-host profile.
    """

    return {
        host: spec.key
        for spec in specs
        if spec.capabilities.retrieval_challenge_escalation == "browser"
        for host in spec.identity.allowed_hosts
    }


def _transport_rot_recorder(
    state_root: Path,
    specs: Mapping[str, ProviderSpec],
) -> Callable[[str, str | None], None]:
    """Record fingerprint rot when an escalation served (R8).

    Only providers with a *declared* escalation record rot: a resolver-based
    escalation (Economist's interstitial passage) is a challenge being
    resolved, not a fingerprint being refused. The write must never break
    the retrieval it rides on, so every failure is swallowed — the signal
    is redundant with the next escalated fetch anyway.

    The profile comes from the refused fetch, not the definition: once a
    runtime pin is promoted the two differ, and naming the declaration
    would record rot against a profile that never served.
    """

    store = TransportPinStore(state_root / "transport-pins")

    def record(provider_key: str, served_by: str | None) -> None:
        spec = specs.get(provider_key)
        if (
            spec is None
            or spec.capabilities.retrieval_challenge_escalation != "browser"
        ):
            return
        profile = (
            served_by
            if served_by in HTTP_IMPERSONATION_PROFILES
            else spec.capabilities.http_impersonate
        )
        with suppress(Exception):
            store.record_rot(provider_key, profile=profile)

    return record


def _http_challenge_recorder(
    state_root: Path,
    specs: Mapping[str, ProviderSpec],
) -> Callable[[str, str | None], None]:
    """Log an HTTP leg a session provider's edge refused while the browser served.

    Only session providers that retrieve over HTTP participate (FT): their
    routes cannot be re-pinned, so this is the one place an aging default
    fingerprint becomes visible before it fails a renewal. Observability
    only, and like the rot recorder it must never break the read it rides on.
    """

    store = HttpChallengeStore(state_root / "http-challenges")

    def record(provider_key: str, served_by: str | None) -> None:
        spec = specs.get(provider_key)
        if (
            spec is None
            or spec.capabilities.session_kind == "none"
            or spec.capabilities.retrieval_transport != "http"
        ):
            return
        profile = served_by if served_by in HTTP_IMPERSONATION_PROFILES else None
        with suppress(Exception):
            store.record(provider_key, profile=profile)

    return record


def _escalation_recorder(
    *recorders: Callable[[str, str | None], None],
) -> Callable[[str, str | None], None]:
    def record(provider_key: str, served_by: str | None) -> None:
        for recorder in recorders:
            with suppress(Exception):
                recorder(provider_key, served_by)

    return record


def _application_root(environment_name: str, fallback: str) -> Path:
    return application_root(environment_name, fallback)


def _read_path_challenge_mode() -> ChallengeMode:
    default = ChallengeMode.DETECT_ONLY
    configured = os.environ.get("NEWSCLIP_CHALLENGE_MODE", default.value)
    try:
        return ChallengeMode(configured)
    except ValueError:
        raise UsageError(
            "NEWSCLIP_CHALLENGE_MODE must be 'auto' or 'detect-only'"
        ) from None


def _browser_launch_config(spec: ProviderSpec) -> BrowserLaunchConfig:
    auth = spec.auth
    if auth is None:
        return BrowserLaunchConfig()
    return BrowserLaunchConfig(
        locale=auth.launch.locale,
        timezone_id=auth.launch.timezone_id,
        accept_language=auth.launch.accept_language,
        args=auth.launch.args,
    )


def _shared_defense_incidents(
    user_state_root: Path, provider: str, requester: str
) -> frozenset[str]:
    """Retain this requester's evidence through any native incident-store instance.

    Discovery only prevents deletion; it never authorizes access. Retained users
    count too, so removing application membership cannot discard open evidence.
    Unreadable records stop pruning through IncidentStore's existing boundary.
    """
    if not user_state_root.exists():
        return frozenset()
    protected = set()
    for owner_root in user_state_root.iterdir():
        require_user(owner_root.name)
        if owner_root.is_symlink() or not owner_root.is_dir():
            raise ValueError("unexpected user state directory")
        record = DefenseState(
            owner_root / "provider-defense", incident_owner=requester
        ).status(provider)
        if record and record.incident_id:
            protected.add(record.incident_id)
    return frozenset(protected)


def _protected_incidents(state_root: Path, provider: str, identity) -> frozenset[str]:
    # These are atomic read-only snapshots used to refuse pruning, never to
    # authorize provider I/O. Do not acquire the guard lock: a guarded check
    # may already own it while committing its incident.
    hold = ProviderGuardStore(
        state_root / "provider-guard", build_identity=identity
    ).load_locked(provider)
    defense = DefenseState(state_root / "provider-defense").status(provider)
    recovery = RecoveryStore(state_root / "recovery").load(provider)
    renewal = KeeperOutcomeStore(state_root / "session-keeper").load(provider)
    if recovery is not None and recovery.health.status == "succeeded":
        recovery = None
    return frozenset(
        item.incident_id
        for item in (hold, defense, recovery, renewal)
        if item is not None and item.incident_id is not None
    )


def _browser_readiness_evaluator(
    provider: Provider,
    extractor: TrafilaturaExtractor,
    *,
    verification: bool = False,
) -> BrowserReadinessEvaluator:
    """Evaluate provisional DOM snapshots with the final product contracts."""

    def evaluate(fetch: RawFetch) -> BrowserReadinessObservation:
        extraction = extractor.extract(fetch, scope_xpath=provider.extraction_scope)
        assessment = provider.assess(str(fetch.requested_url), fetch, extraction)
        ready = assessment.promotable
        coverage = None
        if verification and isinstance(provider, BrowserPaidProofCompleteness):
            completeness = provider.browser_paid_proof_complete(
                fetch, extraction, assessment
            )
            ready = (
                completeness.complete
                or assessment.access_state is AccessState.AUTH_REQUIRED
            )
            coverage = completeness.coverage
        elif isinstance(provider, BrowserSnapshotCompleteness):
            completeness = provider.browser_snapshot_complete(
                fetch,
                extraction,
                assessment,
            )
            ready = completeness.complete
            coverage = completeness.coverage
        # Authentication and challenge verdicts cannot become promotable by
        # rendering more of the same document; once stable they end sampling.
        # A teaser keeps sampling because entitlement can resolve late.
        settled = not ready and assessment.access_state in {
            AccessState.AUTH_REQUIRED,
            AccessState.BLOCKED,
        }
        fingerprint_body = extraction.body_markdown
        if verification or settled:
            fingerprint_body = assessment.access_state.value + "\0" + fingerprint_body
        fingerprint = hashlib.sha256(fingerprint_body.encode("utf-8")).hexdigest()
        return BrowserReadinessObservation(
            ready=ready,
            assessment_promotable=assessment.promotable,
            content_fingerprint=fingerprint,
            word_count=assessment.word_count,
            coverage_bucket=readiness_coverage_bucket(coverage),
            settled=settled,
        )

    return evaluate


def _timing_root(state_root: Path) -> Path:
    configured = os.environ.get("NEWSCLIP_TIMING_HOME")
    return (
        scope_path(Path(configured).expanduser())
        if configured
        else state_root / "timings"
    )


def _trace_root(state_root: Path) -> Path:
    configured = os.environ.get("NEWSCLIP_TRACE_HOME")
    return (
        scope_path(Path(configured).expanduser())
        if configured
        else state_root / "traces"
    )


def _timing_run_mode() -> TimingRunMode:
    try:
        return TimingRunMode(
            os.environ.get("NEWSCLIP_TIMING_RUN_MODE", TimingRunMode.PRODUCT.value)
        )
    except ValueError:
        return TimingRunMode.PRODUCT


def _provider_enabled(spec: ProviderSpec) -> bool:
    return spec.enabled_by_default or bool(
        spec.enable_environment and os.environ.get(spec.enable_environment) == "1"
    )


def _provider_allowlist(
    specs: Iterable[ProviderSpec],
) -> tuple[str, ...] | None:
    raw = os.environ.get(_PROVIDER_ALLOWLIST_ENVIRONMENT)
    if raw is None:
        return None
    values = tuple(item.strip() for item in raw.split(","))
    if not values or any(not item for item in values):
        raise UsageError(
            f"{_PROVIDER_ALLOWLIST_ENVIRONMENT} must contain provider keys"
        )
    if len(set(values)) != len(values):
        raise UsageError(
            f"{_PROVIDER_ALLOWLIST_ENVIRONMENT} contains duplicate provider keys"
        )
    known = {spec.key for spec in specs}
    unknown = set(values) - known
    if unknown:
        raise UsageError(
            f"{_PROVIDER_ALLOWLIST_ENVIRONMENT} contains unknown provider keys"
        )
    return values


def _http_headers_by_host(
    specs: Iterable[ProviderSpec],
    *,
    secret_reader: ConfiguredSecretReader | None = None,
) -> dict[str, Callable[[], Mapping[str, str]]]:
    """Attach a declared adapter-search API key as a host-scoped header.

    The key is resolved lazily on the first request to the host and cached for
    the process, so composition never touches ``op`` and a missing credential
    surfaces as one provider's typed operator-action failure, not a startup
    error.

    ``NEWSCLIP_SEARCH_API_KEY_<PROVIDER>`` supplies the key directly and is
    consulted before ``op``. A serving deployment that deliberately holds no
    1Password authority can be handed the one static key it needs without
    gaining the vault; the environment value must be the bare key itself.
    """

    configured: dict[str, Callable[[], Mapping[str, str]]] = {}
    for spec in specs:
        search = spec.search
        if not isinstance(search, AdapterSearchSpec) or (
            search.api_key_ref is None and spec.key != "guardian"
        ):
            continue
        host = (urlsplit(str(search.endpoint)).hostname or "").lower()
        if not host:
            raise RuntimeError(f"invalid adapter search endpoint host: {spec.key}")
        if host in configured:
            raise RuntimeError(f"conflicting search API key headers for {host}")
        configured[host] = _lazy_api_key_headers(
            spec.key,
            search.api_key_ref or "",
            secret_reader=secret_reader,
        )
    return configured


def _search_api_key_environment(provider_key: str) -> str:
    return f"NEWSCLIP_SEARCH_API_KEY_{provider_key.upper().replace('-', '_')}"


def _lazy_api_key_headers(
    provider_key: str,
    reference: str,
    *,
    secret_reader: ConfiguredSecretReader | None = None,
) -> Callable[[], Mapping[str, str]]:
    reader = secret_reader or ConfiguredSecretReader()
    lock = threading.Lock()
    cache: dict[str, str] = {}

    def resolve() -> Mapping[str, str]:
        with lock:
            value = cache.get("key")
            if value is None:
                environment_value = os.environ.get(
                    _search_api_key_environment(provider_key)
                )
                if environment_value:
                    # A key can never carry header-terminating bytes; refusing
                    # here keeps a mis-rendered deployment value out of every
                    # request instead of injecting it into one.
                    if any(marker in environment_value for marker in ("\r", "\n")):
                        raise OperatorActionRequiredError(
                            f"{provider_key} search API key is unavailable",
                            provider=provider_key,
                            reason_code="api_key_unresolvable",
                        )
                    value = environment_value
                else:
                    try:
                        value = reader.read(reference)
                    except SecretResolutionError as error:
                        raise OperatorActionRequiredError(
                            f"{provider_key} search API key is unavailable",
                            provider=provider_key,
                            reason_code="api_key_unresolvable",
                        ) from error
                cache["key"] = value
        return {"api-key": value}

    return resolve


def _http_impersonation_by_host(
    specs: Iterable[ProviderSpec],
) -> dict[str, BrowserTypeLiteral]:
    configured: dict[str, BrowserTypeLiteral] = {}
    for spec in specs:
        impersonate = spec.capabilities.http_impersonate
        for host in spec.identity.allowed_hosts:
            previous = configured.get(host)
            if previous is not None and previous != impersonate:
                raise RuntimeError(f"conflicting HTTP impersonation for {host}")
            configured[host] = impersonate
    return {
        host: impersonate
        for host, impersonate in configured.items()
        if impersonate != DEFAULT_HTTP_IMPERSONATION
    }


def _verification_url(spec: ProviderSpec) -> str:
    session = spec.session
    if session is None:
        raise RuntimeError("anonymous provider has no verification URL")
    if session.default_verification_url is not None:
        return str(session.default_verification_url)
    environment_name = session.verification_url_environment
    if environment_name is None:  # pragma: no cover - schema invariant
        raise RuntimeError("provider verification URL source is not configured")
    value = os.environ.get(environment_name, "").strip()
    if value:
        return value
    enablement = spec.enable_environment or f"the {spec.key} provider"
    raise UsageError(f"{environment_name} must be set when {enablement}=1")
