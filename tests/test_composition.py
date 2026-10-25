"""Composition root for the default product providers."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lxml import html

import newsclip.composition as composition
from newsclip.browser_profiles import BrowserProfileManager
from newsclip.browser_readiness import ReadinessCoverageBucket
from newsclip.browser_runtime import BrowserLaunchConfig
from newsclip.challenge_catalog import build_challenge_resolver
from newsclip.challenge_detection import detect_challenge, detect_challenge_for_reads
from newsclip.challenges import ChallengeMode, ChallengeVendor
from newsclip.composition import (
    _http_headers_by_host,
    build_auth_service,
    build_mcp_service,
    build_registry,
    build_service,
)
from newsclip.configured_provider import ConfiguredProvider
from newsclip.errors import OperatorActionRequiredError, PersistenceError, UsageError
from newsclip.models import RawFetch
from newsclip.provenance import BuildIdentitySource
from newsclip.provider_config import load_builtin_provider_specs
from newsclip.provider_guard import ProviderGuardBusyError
from newsclip.providers.ap import ApProvider
from newsclip.providers.axios import AxiosProvider
from newsclip.providers.bloomberg import BloombergProvider
from newsclip.providers.bloomberg_auth import BloombergAcquisitionAdapter
from newsclip.providers.builtins import (
    BUILTIN_PROVIDER_KEYS,
    BUILTIN_PROVIDER_KEYS_CSV,
    BUILTIN_PROVIDER_KEYS_PROSE,
    BUILTIN_PROVIDER_REGISTRATIONS,
)
from newsclip.providers.cnbc import CNBCProvider
from newsclip.providers.economist import EconomistLoginRecipe, EconomistProvider
from newsclip.providers.economist_auth import EconomistAcquisitionAdapter
from newsclip.providers.guardian import GuardianProvider
from newsclip.providers.nyt import NYTProvider
from newsclip.providers.registration import validate_builtin_registrations
from newsclip.providers.reuters import ReutersProvider
from newsclip.providers.wsj import WSJLoginRecipe, WSJProvider
from newsclip.secret_reference import SecretResolutionError
from newsclip.sessions import SessionStore

WSJ_URL = "https://www.wsj.com/finance/banks-rally-capital-1a2b3c4d"
BLOOMBERG_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-17/"
    "wheat-eases-as-traders-lock-in-gains-assess-black-sea-threats"
)
BLOOMBERG_FIXTURE_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-16/"
    "fixture-chipmaker-beats-estimates"
)


@pytest.fixture(autouse=True)
def _private_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_CHALLENGE_MODE", "auto")


def test_default_registry_contains_all_promoted_providers() -> None:
    providers = tuple(build_registry())

    assert [provider.key for provider in providers] == [
        "ft",
        "wsj",
        "bloomberg",
        "cnbc",
        "reuters",
        "economist",
        "nyt",
        "guardian",
        "ap",
        "axios",
    ]
    assert all(isinstance(provider, ConfiguredProvider) for provider in providers)
    assert isinstance(providers[1], WSJProvider)
    assert isinstance(providers[2], BloombergProvider)
    assert isinstance(providers[3], CNBCProvider)
    assert isinstance(providers[4], ReutersProvider)
    assert isinstance(providers[5], EconomistProvider)
    assert isinstance(providers[6], NYTProvider)
    assert isinstance(providers[7], GuardianProvider)
    assert isinstance(providers[8], ApProvider)
    assert isinstance(providers[9], AxiosProvider)


@pytest.mark.parametrize(
    "error",
    [
        ProviderGuardBusyError("provider guard is busy"),
        PersistenceError("provider guard persistence failed"),
    ],
)
def test_verified_session_hold_clear_is_best_effort_for_persistence_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: PersistenceError,
) -> None:
    cleared: list[str] = []

    class _FailingGuard:
        def clear_session_evidence(self, provider: str, *, hold_id: str) -> None:
            assert hold_id == "guard-" + "a" * 32
            cleared.append(provider)
            raise error

    monkeypatch.setattr(
        composition,
        "build_provider_guard",
        lambda: _FailingGuard(),
    )
    service = build_auth_service()

    service._session_evidence_verified("ft", hold_id="guard-" + "a" * 32)

    assert cleared == ["ft"]


def test_verified_session_hold_clear_propagates_unexpected_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenGuard:
        def clear_session_evidence(self, provider: str, *, hold_id: str) -> None:
            del provider
            raise RuntimeError("unexpected guard failure")

    monkeypatch.setattr(composition, "build_provider_guard", lambda: _BrokenGuard())
    service = build_auth_service()

    with pytest.raises(RuntimeError, match="unexpected guard failure"):
        service._session_evidence_verified("ft", hold_id="guard-" + "a" * 32)


def test_provider_allowlist_selects_an_ordered_production_subset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "NEWSCLIP_PROVIDER_ALLOWLIST",
        "cnbc,ft,economist,wsj,reuters",
    )

    assert build_registry().keys() == (
        "cnbc",
        "ft",
        "economist",
        "wsj",
        "reuters",
    )


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "must contain provider keys"),
        ("ft,,wsj", "must contain provider keys"),
        ("ft,ft", "duplicate provider keys"),
        ("ft,unknown", "unknown provider keys"),
    ],
)
def test_provider_allowlist_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    message: str,
) -> None:
    monkeypatch.setenv("NEWSCLIP_PROVIDER_ALLOWLIST", value)

    with pytest.raises(UsageError, match=message):
        build_registry()


def test_builtin_registration_keys_and_auth_capabilities_fail_closed() -> None:
    specs = load_builtin_provider_specs()
    validate_builtin_registrations(specs, BUILTIN_PROVIDER_REGISTRATIONS)

    missing = dict(BUILTIN_PROVIDER_REGISTRATIONS)
    missing.pop("ft")
    with pytest.raises(RuntimeError, match="registration mismatch"):
        validate_builtin_registrations(specs, missing)

    invalid = dict(BUILTIN_PROVIDER_REGISTRATIONS)
    invalid["cnbc"] = replace(
        invalid["cnbc"],
        build_auth_adapter=BUILTIN_PROVIDER_REGISTRATIONS["ft"].build_auth_adapter,
    )
    with pytest.raises(RuntimeError, match="auth capability mismatch: cnbc"):
        validate_builtin_registrations(specs, invalid)

    invalid = dict(BUILTIN_PROVIDER_REGISTRATIONS)
    invalid["ft"] = replace(invalid["ft"], check_credential_readiness=None)
    with pytest.raises(
        RuntimeError,
        match="credential-readiness capability mismatch: ft",
    ):
        validate_builtin_registrations(specs, invalid)


def test_builtin_catalog_text_is_derived_from_registration_order() -> None:
    assert tuple(BUILTIN_PROVIDER_REGISTRATIONS) == BUILTIN_PROVIDER_KEYS
    assert ", ".join(BUILTIN_PROVIDER_REGISTRATIONS) == BUILTIN_PROVIDER_KEYS_CSV
    assert (
        f"{', '.join(BUILTIN_PROVIDER_KEYS[:-1])}, and {BUILTIN_PROVIDER_KEYS[-1]}"
        == BUILTIN_PROVIDER_KEYS_PROSE
    )
    assert {
        key: registration.approved_challenge_vendors
        for key, registration in BUILTIN_PROVIDER_REGISTRATIONS.items()
    } == {
        "ft": frozenset({ChallengeVendor.HCAPTCHA}),
        "wsj": frozenset({ChallengeVendor.DATADOME}),
        "bloomberg": frozenset({ChallengeVendor.PERIMETERX}),
        "cnbc": frozenset(),
        "reuters": frozenset({ChallengeVendor.DATADOME}),
        "economist": frozenset(
            {ChallengeVendor.CLOUDFLARE_INTERSTITIAL, ChallengeVendor.DATADOME}
        ),
        "nyt": frozenset({ChallengeVendor.DATADOME}),
        "guardian": frozenset(),
        "ap": frozenset({ChallengeVendor.CLOUDFLARE_INTERSTITIAL}),
        "axios": frozenset({ChallengeVendor.CLOUDFLARE_INTERSTITIAL}),
    }


def test_importing_builtin_registrations_does_not_load_provider_definitions() -> None:
    program = """
import newsclip.provider_config as provider_config

def reject_load(key):
    raise AssertionError(f"provider definition loaded during import: {key}")

provider_config.load_provider_spec = reject_load
import newsclip.providers.builtins
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_composition_injects_specs_without_compatibility_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_load(key: str) -> None:
        raise AssertionError(f"compatibility definition load during composition: {key}")

    for registration in BUILTIN_PROVIDER_REGISTRATIONS.values():
        provider_module = sys.modules[registration.build_provider.__module__]
        monkeypatch.setattr(provider_module, "load_provider_spec", reject_load)
        if registration.build_auth_adapter is not None:
            auth_module = sys.modules[registration.build_auth_adapter.__module__]
            monkeypatch.setattr(auth_module, "load_provider_spec", reject_load)

    providers = tuple(build_registry())
    specs = {spec.key: spec for spec in load_builtin_provider_specs()}

    assert tuple(provider.key for provider in providers) == BUILTIN_PROVIDER_KEYS
    for provider in providers:
        registration = BUILTIN_PROVIDER_REGISTRATIONS[provider.key]
        if registration.build_auth_adapter is None:
            continue
        assert provider.login_recipe is not None
        resolver = build_challenge_resolver(registration.approved_challenge_vendors)
        adapter = registration.build_auth_adapter(
            provider.login_recipe,
            specs[provider.key],
            resolver,
        )
        assert adapter.provider == provider.key
        assert adapter._challenge_resolver is resolver


def test_provider_factory_returning_the_wrong_identity_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = BUILTIN_PROVIDER_REGISTRATIONS["ft"]
    monkeypatch.setitem(
        BUILTIN_PROVIDER_REGISTRATIONS,
        "ft",
        replace(registration, build_provider=lambda _spec, _url: CNBCProvider()),
    )

    with pytest.raises(RuntimeError, match="factory contract mismatch: ft"):
        build_registry()


def test_provider_factory_missing_paged_search_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = BUILTIN_PROVIDER_REGISTRATIONS["ft"]

    def incomplete_provider(spec, verification_url):  # noqa: ANN001
        provider = registration.build_provider(spec, verification_url)
        provider.search_page = None  # type: ignore[method-assign]
        return provider

    monkeypatch.setitem(
        BUILTIN_PROVIDER_REGISTRATIONS,
        "ft",
        replace(registration, build_provider=incomplete_provider),
    )

    with pytest.raises(RuntimeError, match="factory contract incomplete: ft"):
        build_registry()


def test_provider_factory_missing_session_recipe_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = BUILTIN_PROVIDER_REGISTRATIONS["ft"]

    def incomplete_provider(spec, verification_url):  # noqa: ANN001
        provider = registration.build_provider(spec, verification_url)
        provider.login_recipe = None
        return provider

    monkeypatch.setitem(
        BUILTIN_PROVIDER_REGISTRATIONS,
        "ft",
        replace(registration, build_provider=incomplete_provider),
    )

    with pytest.raises(RuntimeError, match="factory login contract mismatch: ft"):
        build_registry()


def test_auth_factory_returning_an_incomplete_adapter_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = BUILTIN_PROVIDER_REGISTRATIONS["ft"]
    monkeypatch.setitem(
        BUILTIN_PROVIDER_REGISTRATIONS,
        "ft",
        replace(
            registration,
            build_auth_adapter=lambda _recipe, _spec, _resolver: object(),
        ),
    )

    with pytest.raises(RuntimeError, match="auth factory contract incomplete: ft"):
        build_auth_service()


def test_auth_factory_returning_the_wrong_identity_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = BUILTIN_PROVIDER_REGISTRATIONS["ft"]
    recipe = build_registry().get("ft").login_recipe
    assert recipe is not None
    spec = next(spec for spec in load_builtin_provider_specs() if spec.key == "ft")
    resolver = build_challenge_resolver(registration.approved_challenge_vendors)
    adapter = registration.build_auth_adapter(recipe, spec, resolver)
    assert adapter is not None
    adapter.provider = "wsj"
    monkeypatch.setitem(
        BUILTIN_PROVIDER_REGISTRATIONS,
        "ft",
        replace(
            registration,
            build_auth_adapter=lambda _recipe, _spec, _resolver: adapter,
        ),
    )

    with pytest.raises(RuntimeError, match="auth factory contract mismatch: ft"):
        build_auth_service()


def test_browser_search_provider_is_wired_to_the_browser_plane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = load_builtin_provider_specs()
    ft = next(spec for spec in specs if spec.key == "ft")
    browser_search_ft = ft.model_copy(
        update={
            "capabilities": ft.capabilities.model_copy(
                update={"search_transport": "browser"}
            )
        }
    )
    selected = tuple(browser_search_ft if spec.key == "ft" else spec for spec in specs)
    monkeypatch.setattr(
        "newsclip.composition.load_builtin_provider_specs",
        lambda: selected,
    )

    service = build_service()

    assert service._browser_retriever is not None
    assert "ft" in service._browser_retriever._policies
    assert "ft" in service._browser_retriever._launch_configs


def test_default_service_wires_cookie_store_and_bloomberg_browser_plane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NEWSCLIP_BUILD_REVISION", raising=False)
    monkeypatch.delenv("NEWSCLIP_BUILD_DIRTY", raising=False)
    monkeypatch.delenv("NEWSCLIP_BUILD_SOURCE_FINGERPRINT", raising=False)
    service = build_service()

    assert isinstance(service._sessions, SessionStore)
    assert service._timing is not None
    assert service._timing.build_identity_source is BuildIdentitySource.LOCAL_CHECKOUT
    assert service._timing.build_source_fingerprint is not None
    assert service._browser_retriever is not None
    assert not (service._sessions.root / "traces").exists()
    assert set(service._sessions._adapters) == {
        "ft",
        "wsj",
        "bloomberg",
        "economist",
        "nyt",
    }
    # Reuters' verified transport fingerprint remains host-local; every other
    # provider keeps the global desktop Chrome default.
    assert service._http._impersonate_by_host == {
        "reuters.com": "safari2601",
        "www.reuters.com": "safari2601",
    }
    for key in ("ft", "wsj", "bloomberg", "economist", "nyt"):
        assert (
            service._sessions._adapters[key]._recipe is service._sessions._recipes[key]
        )
    # The read plane classifies with the prefiltered detector while
    # acquisition keeps the unfiltered sweep; both planes must still expose
    # exactly the provider-approved mechanics.
    for key in ("wsj", "bloomberg", "economist", "nyt"):
        read_resolver = service._browser_retriever._challenge_resolvers[key]
        auth_resolver = service._sessions._adapters[key]._challenge_resolver
        assert read_resolver.supported_vendors == auth_resolver.supported_vendors
        assert read_resolver._detector is detect_challenge_for_reads
        assert auth_resolver._detector is detect_challenge


def test_mcp_service_uses_request_scoped_browser_profiles() -> None:
    product = build_service()
    mcp = build_mcp_service()
    try:
        assert product._browser_retriever is not None
        assert mcp._browser_retriever is not None
        assert product._browser_retriever._retain_profile is True
        assert mcp._browser_retriever._retain_profile is False
    finally:
        mcp.close()
        product.close()


def test_mcp_construction_omits_credential_collaborators(monkeypatch) -> None:
    from newsclip.contracts import SessionManager, SessionSource

    def forbidden(*args, **kwargs):
        pytest.fail("serving attempted to construct credential authority")

    for key, registration in BUILTIN_PROVIDER_REGISTRATIONS.items():
        if registration.build_auth_adapter is not None:
            monkeypatch.setitem(
                BUILTIN_PROVIDER_REGISTRATIONS,
                key,
                replace(
                    registration,
                    build_auth_adapter=forbidden,
                    check_credential_readiness=forbidden,
                ),
            )
    monkeypatch.setattr("newsclip.login.OpSecretFiller.__init__", forbidden)
    service = build_mcp_service()
    try:
        assert isinstance(service._sessions, SessionSource)
        assert not isinstance(service._sessions, SessionManager)
        assert service.session_status("ft").status.value == "required"
    finally:
        service.close()


@pytest.mark.parametrize(
    "operation",
    [
        "login",
        "import_cookies",
        "session_reset",
        "session_clear",
        "session_acknowledge",
        "browser_profile_reset",
    ],
)
def test_mcp_service_refuses_direct_operator_calls(monkeypatch, operation) -> None:
    from newsclip.contracts import SessionManager

    service = build_mcp_service()
    try:
        assert not isinstance(service._sessions, SessionManager)
        with pytest.raises(PersistenceError, match="session manager is not configured"):
            if operation == "import_cookies":
                service.login("ft", cookie_payload=[])
            else:
                getattr(service, operation)("ft")
    finally:
        service.close()


def test_read_path_challenge_mode_has_one_composition_kill_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = build_service()
    assert service._browser_retriever._challenge_mode is ChallengeMode.AUTO
    service.close()

    monkeypatch.setenv("NEWSCLIP_CHALLENGE_MODE", "detect-only")
    supervised = build_service()
    assert supervised._browser_retriever._challenge_mode is ChallengeMode.DETECT_ONLY
    supervised.close()

    monkeypatch.setenv("NEWSCLIP_CHALLENGE_MODE", "invalid")
    with pytest.raises(UsageError, match="NEWSCLIP_CHALLENGE_MODE"):
        build_service()


def test_auth_service_reuses_session_composition_without_opening_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "newsclip.composition.ArchiveStore",
        lambda *args, **kwargs: pytest.fail("auth composition must not open archive"),
    )

    service = build_auth_service()

    assert service._archive is None
    assert isinstance(service._sessions, SessionStore)
    assert service._browser_retriever is not None
    assert set(service._sessions._adapters) == {
        "ft",
        "wsj",
        "bloomberg",
        "economist",
        "nyt",
    }


def test_browser_trace_root_can_be_relocated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace_root = tmp_path / "durable-browser-traces"
    monkeypatch.setenv("NEWSCLIP_TRACE_HOME", str(trace_root))

    service = build_service()
    profiles = service._sessions._profiles
    assert isinstance(profiles, BrowserProfileManager)
    runtime = profiles._runtime

    assert runtime._trace is not None
    assert runtime._trace._path.parent == trace_root


def test_bloomberg_default_wires_the_browser_plane() -> None:
    service = build_service()

    assert isinstance(service._sessions, SessionStore)
    assert service._browser_retriever is not None
    assert set(service._browser_retriever._readiness_evaluators) == {
        "ap",
        "axios",
        "bloomberg",
        "economist",
        "ft",
        "nyt",
        "reuters",
        "wsj",
    }
    assert set(service._browser_retriever._verification_readiness_evaluators) == {
        "bloomberg"
    }
    # Every browser plane can capture a rejected response; only the providers
    # with explicit stabilization policy change how long readiness waits.
    assert {
        key
        for key, policy in service._browser_retriever._policies.items()
        if policy.semantic_readiness is not None
    } == {"bloomberg", "nyt", "wsj"}
    assert isinstance(
        service._sessions._adapters["bloomberg"], BloombergAcquisitionAdapter
    )
    adapter = service._sessions._adapters["bloomberg"]
    mechanic = adapter._challenge_resolver._mechanics[ChallengeVendor.PERIMETERX]
    assert mechanic._hold_seconds == 12


def test_bloomberg_readiness_uses_the_production_assessment_contract() -> None:
    service = build_service()
    retriever = service._browser_retriever
    assert retriever is not None
    evaluator = retriever._readiness_evaluators["bloomberg"]
    fixture_root = Path(__file__).parent / "fixtures" / "bloomberg"

    def evaluate_raw(raw_html: bytes):
        return evaluator(
            RawFetch(
                requested_url=BLOOMBERG_FIXTURE_URL,
                final_url=BLOOMBERG_FIXTURE_URL,
                http_status=200,
                content_type="text/html",
                retrieved_at=datetime(2026, 7, 17, tzinfo=UTC),
                session_cookie_present=True,
                raw_html=raw_html,
            )
        )

    def evaluate(name: str):
        return evaluate_raw((fixture_root / name).read_bytes())

    full_html = (fixture_root / "full.html").read_bytes()
    document = html.fromstring(full_html)
    paragraphs = document.xpath("//article/p")
    values = [" ".join(paragraph.text_content().split()) for paragraph in paragraphs]
    payload = {
        "props": {
            "pageProps": {
                "story": {
                    "seoCanonical": BLOOMBERG_FIXTURE_URL,
                    "headline": "Fixture Chipmaker Beats Estimates",
                    "body": {
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "value": value}],
                            }
                            for value in values
                        ],
                    },
                }
            }
        }
    }
    script = html.Element("script", id="__NEXT_DATA__", type="application/json")
    script.text = json.dumps(payload)
    document.xpath("//head")[0].append(script)
    paragraphs[-1].text = paragraphs[-2].text

    incremental = evaluate("incremental-four-paragraphs.html")
    partial = evaluate_raw(html.tostring(document))
    full = evaluate("full.html")

    assert incremental.ready is False
    assert incremental.assessment_promotable is False
    assert partial.ready is True
    assert partial.assessment_promotable is True
    assert partial.coverage_bucket is ReadinessCoverageBucket.FROM_75_TO_89
    assert full.ready is True
    assert full.assessment_promotable is True
    assert full.coverage_bucket is ReadinessCoverageBucket.UNAVAILABLE
    assert full.word_count > 250
    assert incremental.content_fingerprint != full.content_fingerprint


def test_economist_default_wires_detect_only_salesforce_acquisition() -> None:
    service = build_service()

    adapter = service._sessions._adapters["economist"]
    assert isinstance(adapter, EconomistAcquisitionAdapter)
    assert "strategy" not in type(adapter._auth).model_fields
    assert isinstance(service._sessions._recipes["economist"], EconomistLoginRecipe)


def test_bloomberg_configured_launch_is_shared_by_login_and_retrieval() -> None:
    service = build_service()
    adapter = service._sessions._adapters["bloomberg"]
    retrieval = service._browser_retriever
    profiles = service._sessions._profiles
    assert retrieval is not None
    assert isinstance(profiles, BrowserProfileManager)
    expected = retrieval._launch_configs["bloomberg"]

    assert profiles._launch_configs["bloomberg"] == expected
    assert retrieval._profile_resolver("bloomberg", "default") == profiles.path(
        "bloomberg", "default"
    )
    assert expected == BrowserLaunchConfig(
        locale=adapter._auth.launch.locale,
        timezone_id=adapter._auth.launch.timezone_id,
        accept_language=adapter._auth.launch.accept_language,
        args=adapter._auth.launch.args,
    )


def test_enabled_adapters_receive_their_loaded_provider_definition() -> None:
    service = build_service()
    specs = {spec.key: spec for spec in load_builtin_provider_specs()}

    for key, adapter in service._sessions._adapters.items():
        assert adapter._auth is specs[key].auth


def test_default_wsj_stays_on_the_cookie_plane() -> None:
    service = build_service()

    # The portable jar remains session authority while WSJ article retrieval
    # uses the retained profile; public search remains HTTP/anonymous.
    assert isinstance(service._sessions, SessionStore)
    assert service._browser_retriever is not None
    # Reuters joins the plane for its declared challenge escalation (R8);
    # its primary retrieval stays HTTP.
    assert set(service._browser_retriever._policies) == {
        "ap",
        "axios",
        "ft",
        "wsj",
        "bloomberg",
        "economist",
        "nyt",
        "reuters",
    }
    assert service._registry.get("wsj").capabilities.retrieval_transport == "browser"
    assert isinstance(service._sessions._recipes["wsj"], WSJLoginRecipe)
    assert (
        service.requires_browser_for_url(
            "https://www.ft.com/content/01234567-89ab-cdef-0123-456789abcdef"
        )
        is True
    )
    assert service.requires_browser_for_search(("ft",)) is True
    assert service.requires_browser_for_search(("economist",)) is True
    assert service._browser_retriever.allows_http_fallback("economist") is True
    # The Reuters escalation is declared; its passage-only DataDome approval
    # also satisfies the retriever-level predicate, which changes nothing
    # because every caller already honors the declaration.
    assert service._browser_retriever.allows_http_fallback("reuters") is True
    assert (
        service._allows_http_challenge_fallback(service._registry.get("reuters"))
        is True
    )
    assert (
        service._registry.get("reuters").capabilities.retrieval_challenge_escalation
        == "browser"
    )
    # A Reuters retrieval may now escalate to the browser when challenged, so
    # display preparation must happen ahead of it (R8) — the primary transport
    # is still HTTP, but "requires" answers for the worst case the fetch can
    # legitimately reach.
    assert (
        service.requires_browser_for_url(
            "https://www.reuters.com/world/example-story-2026-07-24/"
        )
        is True
    )


def test_http_verification_clients_are_fresh_scopes(monkeypatch) -> None:
    created: list[FakeCurlClient] = []

    class FakeCurlClient:
        def __init__(
            self,
            *,
            impersonate_by_host=None,
            runtime_impersonate_by_host=None,
            headers_by_host=None,
            trace=None,  # noqa: ANN001
        ) -> None:
            self.closed = False
            self.impersonate_by_host = impersonate_by_host
            self.runtime_impersonate_by_host = runtime_impersonate_by_host
            self.headers_by_host = headers_by_host
            self.trace = trace
            created.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            self.close()

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("newsclip.composition.CurlCffiHttpClient", FakeCurlClient)
    service = build_service()
    assert created[0].impersonate_by_host == {
        "reuters.com": "safari2601",
        "www.reuters.com": "safari2601",
    }
    assert created[0].trace is not None
    factory = service._verification_client_factory
    assert factory is not None

    with factory("ft") as first:
        assert first._primary._http is created[1]
        assert first._browser_fallback._http._retriever.provider == "ft"
        assert first._browser_fallback._max_attempts == 1
        assert created[1].closed is False
    with factory("ft") as second:
        assert second._primary._http is created[2]
        assert second._browser_fallback._http._retriever.provider == "ft"
        assert created[2].closed is False

    assert len(created) == 3
    assert created[0].closed is False  # shared operational client
    assert created[1].closed is True
    assert created[2].closed is True


def test_ft_warm_verification_recovers_rotated_profile_through_composed_policy(
    monkeypatch,
):
    from contextlib import contextmanager

    from test_sessions import NOW, _artifact

    from newsclip.acquisition import AcquisitionMode
    from newsclip.errors import BrowserAuthorityChangedError
    from newsclip.models import (
        AccessState,
        SessionStatus,
        SessionVerification,
        StoredSession,
    )

    service = build_service()
    store = service._sessions
    assert isinstance(store, SessionStore)
    monkeypatch.setattr(store, "_now", lambda: NOW)
    old = _artifact("old-published-authority")
    rotated = _artifact("rotated-browser-authority")
    store._write(
        "ft", "default", StoredSession(status=SessionStatus.VERIFIED, artifact=old)
    )
    events = []

    class StrictFallback:
        def get(self, *args, **kwargs):
            raise BrowserAuthorityChangedError()

    @contextmanager
    def strict_client(_provider):
        yield StrictFallback()

    def scoped_proof(recipe, candidate):
        assert events == ["prepared"]
        assert recipe.provider == "ft" and candidate == old
        events.append("verified")
        return SessionVerification(
            verified=True,
            access_state=AccessState.FULL,
            reason="full_article_verified",
            verified_at=NOW,
        ), rotated.cookies

    monkeypatch.setattr(store, "_client_factory", strict_client)
    monkeypatch.setattr(store, "_profile_verifier", scoped_proof)
    try:
        result = store.explicit_login(
            "ft",
            allow_credential_mint=False,
            before_browser=lambda: events.append("prepared"),
        )
        assert events == ["prepared", "verified"]
        assert result.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
        assert result.artifact.cookies == rotated.cookies
        assert result.artifact.generation_id != old.generation_id
        assert store.get_valid_session("ft") == result.artifact
    finally:
        service.close()


@pytest.mark.parametrize(
    "responses",
    [
        ("full.html",),
        ("teaser.html",),
        ("challenge_http.html", "challenge_http.html"),
        ("challenge_http.html", "full.html"),
        ("interstitial.html",),
    ],
)
def test_ft_warm_authority_uses_bounded_http_policy_without_browser(
    monkeypatch,
    responses,
    tmp_path,
):
    from test_sessions import NOW, _artifact

    from newsclip.acquisition import AcquisitionMode
    from newsclip.errors import ProviderDefenseError, ProviderTransportError
    from newsclip.models import SessionStatus, StoredSession

    monkeypatch.setenv("NEWSCLIP_INVOCATION_ID", "live-ft-warm-fixture")
    monkeypatch.setenv("NEWSCLIP_TRACE_HOME", str(tmp_path / "traces/ft"))
    artifact = _artifact()
    calls = []
    browser_calls = []

    class Http:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def close(self):
            pass

        def get(self, url, *, session=None, **kwargs):
            assert session == artifact
            fixture = responses[len(calls)]
            calls.append(url)
            body = (Path(__file__).parent / "fixtures/ft" / fixture).read_bytes()
            body = body.replace(
                b"11111111-1111-4111-8111-111111111111", url.rsplit("/", 1)[-1].encode()
            )
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=403 if fixture == "challenge_http.html" else 200,
                content_type="text/html",
                retrieved_at=NOW,
                session_cookie_present=True,
                raw_html=body,
            )

    def defended_browser(*args, **kwargs):
        browser_calls.append(True)
        raise ProviderDefenseError(
            "fixture FT browser security verification", provider="ft"
        )

    monkeypatch.setattr(composition, "CurlCffiHttpClient", Http)
    service = build_service()
    store = service._sessions
    assert isinstance(store, SessionStore)
    monkeypatch.setattr(store, "_now", lambda: NOW)
    store._write(
        "ft", "default", StoredSession(status=SessionStatus.VERIFIED, artifact=artifact)
    )
    monkeypatch.setattr(
        service._browser_retriever, "profile_verification_client", defended_browser
    )
    try:
        if responses[-1] == "full.html":
            result = service.login("ft", allow_credential_mint=False)
            assert result.acquisition.mode is AcquisitionMode.ARTIFACT_REUSE
        else:
            with pytest.raises(ProviderTransportError) as caught:
                service.login("ft", allow_credential_mint=False)
            if responses[-1] in {"challenge_http.html", "interstitial.html"}:
                from newsclip.acquisition import MintFailureCategory
                from newsclip.live_reporting import _validated_incident
                from newsclip.timing import OperationFinishedEvent, iter_timing_runs

                assert isinstance(caught.value, ProviderDefenseError)
                assert caught.value.incident_id is not None
                terminal = [
                    record.event
                    for run in iter_timing_runs(service._timing.root)
                    for record in run.records
                    if isinstance(record.event, OperationFinishedEvent)
                ]
                assert len(terminal) == 1
                assert (
                    terminal[0].failure_category
                    is MintFailureCategory.CHALLENGE_BLOCKED
                )
                assert terminal[0].incident.incident_id == caught.value.incident_id
                run = next(iter_timing_runs(service._timing.root))
                validated = _validated_incident(run, tmp_path / "traces")
                assert validated is not None and validated.omission is None
                other_run = run.model_copy(
                    update={
                        "records": tuple(
                            record.model_copy(update={"invocation_id": "live-other"})
                            for record in run.records
                        )
                    }
                )
                rejected = _validated_incident(other_run, tmp_path / "traces")
                assert rejected is not None and rejected.omission == "invalid_capture"
        assert calls == [store._recipe("ft").verification_url] * len(responses)
        assert browser_calls == []
        assert store.get_valid_session("ft") == artifact
    finally:
        service.close()


def test_ft_warm_verification_preserves_the_serving_http_session(monkeypatch):
    """A warm probe must not discard the serving connection and response jar."""
    from types import SimpleNamespace

    from test_http import FakeSession
    from test_sessions import NOW, _artifact

    from newsclip.models import SessionStatus, StoredSession

    class AffinitySession(FakeSession):
        instances = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            response = (Path(__file__).parent / "fixtures/ft/full.html").read_bytes()
            response = response.replace(
                b"11111111-1111-4111-8111-111111111111", url.rsplit("/", 1)[-1].encode()
            )
            return SimpleNamespace(
                url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                content=response,
            )

    monkeypatch.setattr("newsclip.http.requests.Session", AffinitySession)
    service = build_service()
    store = service._sessions
    monkeypatch.setattr(store, "_now", lambda: NOW)
    artifact = _artifact()
    store._write(
        "ft", "default", StoredSession(status=SessionStatus.VERIFIED, artifact=artifact)
    )
    url = "https://www.ft.com/content/11111111-1111-4111-8111-111111111111"
    try:
        service._http.get(url, session=artifact)
        serving = AffinitySession.instances[0]
        # Stand in for a Set-Cookie update made by libcurl after serving.
        serving.cookies.set("edge-affinity", "fixture", domain=".ft.com", path="/")
        service.login("ft", allow_credential_mint=False)
        assert len(AffinitySession.instances) == 1
        assert serving.urls == [url, store._recipe("ft").verification_url]
        assert not serving.closed
        assert serving.cookies.get("edge-affinity") == "fixture"
        assert store.get_valid_session("ft") == artifact
    finally:
        service.close()


def test_composed_client_resolves_a_promoted_runtime_pin(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """R8's gate: a pin promoted elsewhere governs this process's next fetch.

    The wiring is the whole feature — a missing resolver would leave every
    other test passing while the runtime pin silently never applied.
    """

    from newsclip.transport_pins import TransportPinStore

    created: list[object] = []

    class FakeCurlClient:
        def __init__(
            self,
            *,
            impersonate_by_host=None,
            runtime_impersonate_by_host=None,
            headers_by_host=None,
            trace=None,  # noqa: ANN001
        ) -> None:
            self.runtime_impersonate_by_host = runtime_impersonate_by_host
            created.append(self)

        def close(self) -> None:
            pass

    monkeypatch.setattr("newsclip.composition.CurlCffiHttpClient", FakeCurlClient)
    build_service()
    resolve = created[0].runtime_impersonate_by_host
    assert resolve is not None

    # Nothing promoted yet: the definition's pin governs.
    assert resolve("www.reuters.com") is None

    # The keeper promotes over the shared state mount, in another process.
    TransportPinStore(tmp_path / "state" / "transport-pins").promote(
        "reuters", profile="chrome146", passes=3
    )

    assert resolve("www.reuters.com") == "chrome146"
    assert resolve("reuters.com") == "chrome146"
    # A provider that declares no escalation is not pinnable at all.
    assert resolve("www.ft.com") is None
    assert resolve("www.economist.com") is None


def test_browser_verification_scope_releases_retained_profile(monkeypatch) -> None:
    service = build_service()
    retrieval = service._browser_retriever
    factory = service._verification_client_factory
    assert retrieval is not None
    assert factory is not None
    releases: list[None] = []
    monkeypatch.setattr(retrieval, "release", lambda: releases.append(None))

    with factory("wsj"):
        assert releases == []

    assert releases == [None]


def test_session_mutation_and_service_close_release_browser(monkeypatch) -> None:
    service = build_service()
    retrieval = service._browser_retriever
    sessions = service._sessions
    assert retrieval is not None
    assert isinstance(sessions, SessionStore)
    calls: list[str] = []
    monkeypatch.setattr(retrieval, "release", lambda: calls.append("release"))
    monkeypatch.setattr(retrieval, "close", lambda: calls.append("browser-close"))
    monkeypatch.setattr(service._http, "close", lambda: calls.append("http-close"))
    monkeypatch.setattr(sessions, "reset", lambda provider: calls.append(provider))

    service.session_reset("wsj")
    service.close()
    service.close()

    assert calls == ["release", "wsj", "browser-close", "http-close"]


@pytest.mark.parametrize(
    "builder", [build_service, build_mcp_service, build_auth_service]
)
@pytest.mark.parametrize("browser_close_fails", [False, True])
def test_composed_service_owns_transport_cleanup_once(
    monkeypatch, builder, browser_close_fails
) -> None:
    calls: list[str] = []
    close_http = composition.CurlCffiHttpClient.close
    close_browser = composition.PatchrightBrowserRetriever.close

    def http_close(client):
        calls.append("http")
        close_http(client)

    def browser_close(browser):
        calls.append("browser")
        close_browser(browser)
        if browser_close_fails:
            raise RuntimeError("browser cleanup failed")

    # Instrument the resources before composition so the builder's actual
    # lifecycle wiring remains under test, including any HTTP-close wrapper.
    monkeypatch.setattr(composition.CurlCffiHttpClient, "close", http_close)
    monkeypatch.setattr(composition.PatchrightBrowserRetriever, "close", browser_close)
    service = builder()
    if browser_close_fails:
        with pytest.raises(RuntimeError, match="browser cleanup failed"):
            service.close()
    else:
        service.close()
    service.close()

    assert calls == ["browser", "http"]


@pytest.mark.parametrize("failure_at", ["runtime", "session_store", "service"])
@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_failed_composition_releases_acquired_transports(
    monkeypatch, failure_at, cleanup_fails
) -> None:
    calls: list[str] = []
    close_http = composition.CurlCffiHttpClient.close
    close_browser = composition.PatchrightBrowserRetriever.close

    def http_close(client):
        calls.append("http")
        close_http(client)
        if cleanup_fails:
            raise RuntimeError("HTTP cleanup failed")

    def browser_close(browser):
        calls.append("browser")
        close_browser(browser)
        if cleanup_fails:
            raise RuntimeError("browser cleanup failed")

    def fail(*args, **kwargs):
        raise ValueError("construction failed")

    monkeypatch.setattr(composition.CurlCffiHttpClient, "close", http_close)
    monkeypatch.setattr(composition.PatchrightBrowserRetriever, "close", browser_close)
    target = {
        "runtime": "PatchrightRuntime",
        "session_store": "SessionStore",
        "service": "NewsclipService",
    }[failure_at]
    monkeypatch.setattr(composition, target, fail)

    with pytest.raises(ValueError, match="construction failed"):
        build_service()

    assert calls == (["http"] if failure_at == "runtime" else ["browser", "http"])


def test_bloomberg_explicit_login_is_owned_by_the_cookie_session_store() -> None:
    service = build_service()

    assert isinstance(service._sessions, SessionStore)
    assert "bloomberg" in service._sessions._recipes
    assert "bloomberg" in service._sessions._adapters


def test_ft_session_status_still_works_with_a_browser_provider_present() -> None:
    service = build_service()

    health = service.session_status("ft")

    assert health.provider == "ft"
    assert health.status.value == "required"  # no session yet, but routed cleanly


def test_bloomberg_default_uses_the_pinned_verification_url(monkeypatch) -> None:
    monkeypatch.delenv("NEWSCLIP_ENABLE_BLOOMBERG", raising=False)
    monkeypatch.delenv("NEWSCLIP_BLOOMBERG_VERIFICATION_URL", raising=False)

    provider = build_registry().get("bloomberg")

    assert provider.login_recipe is not None
    assert provider.login_recipe.verification_url == BLOOMBERG_URL


def test_adapter_api_key_headers_resolve_lazily_and_cache(monkeypatch) -> None:
    monkeypatch.delenv("NEWSCLIP_SEARCH_API_KEY_GUARDIAN", raising=False)

    class Reader:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def read(self, reference: str) -> str:
            self.calls.append(reference)
            return "KEY_SENTINEL"

    reader = Reader()
    headers = _http_headers_by_host(
        load_builtin_provider_specs(),
        secret_reader=reader,  # type: ignore[arg-type]
    )

    assert set(headers) == {"content.guardianapis.com"}
    assert reader.calls == []
    resolve = headers["content.guardianapis.com"]
    assert resolve() == {"api-key": "KEY_SENTINEL"}
    assert resolve() == {"api-key": "KEY_SENTINEL"}
    assert reader.calls == ["op://Example/Guardian/credential"]


def test_adapter_api_key_resolution_failure_is_a_typed_operator_action(
    monkeypatch,
) -> None:
    monkeypatch.delenv("NEWSCLIP_SEARCH_API_KEY_GUARDIAN", raising=False)

    class FailingReader:
        def read(self, reference: str) -> str:
            raise SecretResolutionError("op unavailable")

    headers = _http_headers_by_host(
        load_builtin_provider_specs(),
        secret_reader=FailingReader(),  # type: ignore[arg-type]
    )

    with pytest.raises(OperatorActionRequiredError) as excinfo:
        headers["content.guardianapis.com"]()
    assert excinfo.value.provider == "guardian"
    assert excinfo.value.reason_code == "api_key_unresolvable"


def test_adapter_api_key_environment_wins_without_touching_op(monkeypatch) -> None:
    class ForbiddenReader:
        def read(self, reference: str) -> str:
            raise AssertionError("op must not be consulted when the env key is set")

    monkeypatch.setenv("NEWSCLIP_SEARCH_API_KEY_GUARDIAN", "ENV_SENTINEL")
    headers = _http_headers_by_host(
        load_builtin_provider_specs(),
        secret_reader=ForbiddenReader(),  # type: ignore[arg-type]
    )

    resolve = headers["content.guardianapis.com"]
    assert resolve() == {"api-key": "ENV_SENTINEL"}
    # Cached for the process exactly like an op-resolved key.
    monkeypatch.delenv("NEWSCLIP_SEARCH_API_KEY_GUARDIAN")
    assert resolve() == {"api-key": "ENV_SENTINEL"}


def test_adapter_api_key_empty_environment_falls_through_to_op(monkeypatch) -> None:
    class Reader:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def read(self, reference: str) -> str:
            self.calls.append(reference)
            return "KEY_SENTINEL"

    reader = Reader()
    monkeypatch.setenv("NEWSCLIP_SEARCH_API_KEY_GUARDIAN", "")
    headers = _http_headers_by_host(
        load_builtin_provider_specs(),
        secret_reader=reader,  # type: ignore[arg-type]
    )

    assert headers["content.guardianapis.com"]() == {"api-key": "KEY_SENTINEL"}
    assert reader.calls == ["op://Example/Guardian/credential"]


def test_adapter_api_key_environment_rejects_header_terminators(monkeypatch) -> None:
    class ForbiddenReader:
        def read(self, reference: str) -> str:
            raise AssertionError("op must not be consulted when the env key is set")

    monkeypatch.setenv("NEWSCLIP_SEARCH_API_KEY_GUARDIAN", "bad\r\nvalue")
    headers = _http_headers_by_host(
        load_builtin_provider_specs(),
        secret_reader=ForbiddenReader(),  # type: ignore[arg-type]
    )

    with pytest.raises(OperatorActionRequiredError) as excinfo:
        headers["content.guardianapis.com"]()
    assert excinfo.value.provider == "guardian"
    assert excinfo.value.reason_code == "api_key_unresolvable"


def test_keeper_is_wired_with_a_conforming_transport_drip(monkeypatch) -> None:
    """The keeper swallows drip faults, so the wiring is pinned here instead.

    A typo'd method or a missing declared profile would otherwise disable
    R8's slow drip permanently and silently.
    """

    from newsclip.transport_pins import DripOutcome, TransportDrip

    service = build_service()
    keeper = composition.build_session_keeper(service)
    drip = keeper._transport_pins

    assert isinstance(drip, TransportDrip)
    # The protocol call the keeper actually makes, exercised for real: an
    # unrelated provider is idle, and the method exists with this name.
    assert drip.drip("ft") is DripOutcome.IDLE
    # Reuters is the one provider that declares the escalation today, so it
    # is the one the drip may measure.
    assert set(drip._declared_profiles) == {"reuters"}
    assert drip._declared_profiles["reuters"] == "safari2601"
    assert drip._probe == service.probe_transport_candidate


def test_keeper_and_reads_share_the_challenge_rollback_setting(monkeypatch, tmp_path):
    from newsclip.composition import build_session_keeper

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("NEWSCLIP_CHALLENGE_MODE", "detect-only")
    service = build_auth_service()
    try:
        keeper = build_session_keeper(service)
        assert keeper._challenge_mode is ChallengeMode.DETECT_ONLY
        assert service._browser_retriever._challenge_mode is keeper._challenge_mode
    finally:
        service.close()


def test_composed_service_logs_ft_http_challenges_and_reuters_rot(
    tmp_path: Path,
) -> None:
    """One escalation callback feeds both recorders, each for its own providers."""

    from newsclip.composition import build_http_challenge_store
    from newsclip.transport_pins import TransportPinStore

    service = build_service()
    recorder = service._on_challenge_escalation_served
    assert recorder is not None

    recorder("ft", "chrome150")
    recorder("reuters", "safari2601")

    summary = build_http_challenge_store().summary("ft")
    assert summary is not None
    assert (summary.profile, summary.last_24h) == ("chrome150", 1)
    assert build_http_challenge_store().summary("reuters") is None
    pins = TransportPinStore(tmp_path / "state" / "transport-pins")
    assert pins.load("ft") is None
    reuters = pins.load("reuters")
    assert reuters is not None
    assert reuters.rot_profile == "safari2601"
