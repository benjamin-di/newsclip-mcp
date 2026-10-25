from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from newsclip.acquisition import CandidateVerificationMode
from newsclip.configured_provider import ConfiguredProvider
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch
from newsclip.provider_config import (
    ProviderDefinitionError,
    ProviderSpec,
    load_builtin_provider_specs,
)


def _payload(key: str) -> dict[str, object]:
    spec = next(spec for spec in load_builtin_provider_specs() if spec.key == key)
    return copy.deepcopy(spec.model_dump(mode="python"))


def test_builtin_provider_definitions_are_strict_ordered_and_complete() -> None:
    specs = load_builtin_provider_specs()
    policy_versions = [
        ConfiguredProvider(spec).assessment_policy_version for spec in specs
    ]

    assert [spec.key for spec in specs] == [
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
    assert [spec.enabled_by_default for spec in specs] == [
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    ]
    assert all(spec.enable_environment is None for spec in specs)
    assert [spec.search.kind for spec in specs] == [
        "html",
        "html",
        "adapter",
        "adapter",
        "adapter",
        "html",
        "html",
        "adapter",
        "adapter",
        "adapter",
    ]
    assert [
        specs[index].require_html_search().missing_published_fetch_limit
        for index in (0, 1, 5, 6)
    ] == [1, 0, 0, 0]
    assert specs[1].session.allowed_cookie_domains == ("wsj.com", "dowjones.com")
    assert specs[1].session.session_cookie_name_prefixes == ("djcs",)
    assert specs[1].session.verification_minimum_words == 250
    assert specs[1].auth.identity_hosts == ("sso.accounts.dowjones.com",)
    assert specs[2].auth.identity_hosts == ("accounts.google.com",)
    assert [str(url) for url in specs[2].auth.post_callback_urls] == [
        "https://www.bloomberg.com/",
        "https://www.bloomberg.com/account/profile",
        "https://www.bloomberg.com/subscriptions",
    ]
    assert all(
        not spec.auth.post_callback_urls for spec in (specs[0], specs[1], specs[5])
    )
    assert all(not spec.auth.identity_hosts for spec in (specs[0], specs[5]))
    assert specs[1].capabilities.retrieval_transport == "browser"
    assert specs[1].capabilities.search_transport == "browser"
    assert specs[2].capabilities.search_transport == "http"
    assert specs[5].capabilities.search_transport == "http"
    assert "strategy" not in type(specs[5].auth).model_fields
    assert specs[1].browser_retrieval.configured is True
    assert [spec.rate_budget.rate_limit_fallback_seconds for spec in specs] == [
        5,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert [
        spec.response_retry.status_code if spec.response_retry is not None else None
        for spec in specs
    ] == [403, None, None, None, None, None, None, None, None, None]
    assert specs[0].require_html_search().embedded_published is None
    assert (
        specs[1].require_html_search().embedded_published.script_id == "__NEXT_DATA__"
    )
    assert specs[5].require_html_search().embedded_published is None
    assert [
        specs[index].require_html_search().published_date_identity_group
        for index in (0, 1, 5, 6)
    ] == [None, None, "published", "published"]
    assert all(
        version.startswith(f"{spec.key}-cfg-")
        for spec, version in zip(specs, policy_versions, strict=True)
    )
    assert all(len(version.rsplit("-", 1)[-1]) == 12 for version in policy_versions)
    assert [bool(spec.browser_retrieval.configured) for spec in specs] == [
        False,
        True,
        True,
        False,
        False,
        True,
        True,
        False,
        False,
        False,
    ]
    assert specs[4].capabilities.http_impersonate == "safari2601"
    assert specs[5].require_html_search().published_date_format == "%Y/%m/%d"
    assert all(
        ConfiguredProvider(spec).owns_url(str(spec.check.canonical_url))
        for spec in specs
    )
    assert specs[4].check.require_canonical_result is False
    assert all(spec.check.query.strip() for spec in specs)
    assert [str(url) for url in specs[2].browser_retrieval.recovery_warmup_urls] == [
        "https://www.bloomberg.com/",
        "https://www.bloomberg.com/account/profile",
        "https://www.bloomberg.com/subscriptions",
        "https://www.bloomberg.com/",
    ]
    readiness = specs[2].browser_retrieval.semantic_readiness
    assert readiness is not None
    assert readiness.timeout_seconds == 3
    assert readiness.stable_seconds == 0.25
    assert readiness.poll_seconds == 0.1
    # NYT needs its own bounded stabilization: its ready selectors are satisfied
    # by the server-rendered shell while the body is still a stub.
    nyt_readiness = specs[6].browser_retrieval.semantic_readiness
    assert nyt_readiness is not None
    assert nyt_readiness.timeout_seconds == 8
    assert nyt_readiness.stable_seconds == 0.5
    assert nyt_readiness.poll_seconds == 0.1
    # WSJ metadata can likewise be present while the paid body is incomplete.
    wsj_readiness = specs[1].browser_retrieval.semantic_readiness
    assert wsj_readiness is not None
    assert wsj_readiness.timeout_seconds == 8
    assert wsj_readiness.stable_seconds == 0.5
    assert wsj_readiness.poll_seconds == 0.1
    assert all(
        spec.browser_retrieval.semantic_readiness is None
        for spec in (specs[0], *specs[3:6])
    )
    # Warm path must not bake fixed settle/idle tax into every article save.
    for key in ("wsj", "bloomberg", "economist", "nyt"):
        policy = next(spec for spec in specs if spec.key == key).browser_retrieval
        assert policy.warmup_urls == ()
        assert policy.warmup_settle_seconds == 0
        assert policy.article_settle_seconds == 0
        assert policy.network_idle_timeout_seconds == 0
        assert policy.recovery_warmup_urls
    for key in ("wsj", "bloomberg", "economist"):
        budget = next(spec for spec in specs if spec.key == key).rate_budget
        assert budget.requests_per_second >= 5.0
        assert budget.burst >= 5


def test_bloomberg_cookie_fallback_requires_the_modal_title() -> None:
    bloomberg = next(
        spec for spec in load_builtin_provider_specs() if spec.key == "bloomberg"
    )
    selectors = bloomberg.auth.control("cookie_accept")

    assert (
        "body:has-text('Your Privacy and Preferences Regarding Cookies') "
        "button:has-text('Accept All')"
    ) in selectors
    assert "button:has-text('Accept All')" not in selectors


def test_provider_key_contract_accepts_underscores_and_rejects_unsafe_keys() -> None:
    payload = _payload("ft")
    payload["key"] = "news_wire"
    assert ProviderSpec.model_validate(payload).key == "news_wire"

    for key in ("News", "news.wire", "../news", "news/wire", "a" * 33):
        payload["key"] = key
        with pytest.raises(ValidationError):
            ProviderSpec.model_validate(payload)


def test_challenge_escalation_requires_http_retrieval() -> None:
    payload = _payload("reuters")
    validated = ProviderSpec.model_validate(payload)
    assert validated.capabilities.retrieval_challenge_escalation == "browser"

    payload["capabilities"]["retrieval_transport"] = "browser"  # type: ignore[index]
    with pytest.raises(ValidationError, match="challenge escalation"):
        ProviderSpec.model_validate(payload)


def test_provider_check_url_must_be_a_canonical_owned_article() -> None:
    payload = _payload("ft")
    payload["check"]["canonical_url"] = "https://attacker.test/content/private"  # type: ignore[index]

    with pytest.raises(ValidationError, match="provider-check URL"):
        ProviderSpec.model_validate(payload)


@pytest.mark.parametrize(
    "identity_hosts",
    (
        ["accounts.google.com", "accounts.google.com"],
        ["Accounts.Google.com"],
        ["https://accounts.google.com"],
    ),
)
def test_auth_identity_hosts_are_unique_lowercase_hostnames(
    identity_hosts: list[str],
) -> None:
    payload = _payload("bloomberg")
    payload["auth"]["identity_hosts"] = identity_hosts  # type: ignore[index]

    with pytest.raises(ValidationError, match="identity hosts"):
        ProviderSpec.model_validate(payload)


def test_ft_cookie_fallback_requires_the_modal_title() -> None:
    ft = next(spec for spec in load_builtin_provider_specs() if spec.key == "ft")
    selectors = ft.auth.control("consent")

    assert 'body:has-text("Cookies on FT Sites") button:text-is("Accept")' in selectors
    assert 'button:text-is("Accept")' not in selectors


def test_ft_passkey_skip_requires_the_interstitial_title() -> None:
    ft = next(spec for spec in load_builtin_provider_specs() if spec.key == "ft")
    selectors = ft.auth.control("passkey_skip")

    assert 'body:has-text("Set up a passkey") button:text-is("Not now")' in selectors
    assert 'button:text-is("Not now")' not in selectors


def test_assessment_identity_tracks_only_assessment_behavior() -> None:
    payload = _payload("ft")
    baseline = ProviderSpec.model_validate(payload)
    baseline_version = baseline.assessment_policy_version("configured-r1")

    search_change = copy.deepcopy(payload)
    search_change["search"]["query_parameter"] = "query"  # type: ignore[index]
    changed_search = ProviderSpec.model_validate(search_change)
    assert changed_search.assessment_policy_version("configured-r1") == baseline_version

    assessment_change = copy.deepcopy(payload)
    assessment_change["assessment"]["article_xpath"] = ["//main"]  # type: ignore[index]
    changed_assessment = ProviderSpec.model_validate(assessment_change)
    assert (
        changed_assessment.assessment_policy_version("configured-r1")
        != baseline_version
    )
    assert baseline.assessment_policy_version("configured-r2") != baseline_version

    with pytest.raises(ValueError, match="invalid assessment engine revision"):
        baseline.assessment_policy_version("invalid revision")


def test_extraction_scope_enters_the_identity_only_where_it_is_configured() -> None:
    """A scope keys archived extractions; its absence must not churn a hash.

    FT declares no scope, so its identity has to stay byte-stable across this
    change. Reuters declares one, so its identity has to move — that is what
    creates a new archive extraction row instead of silently replacing the
    stored body.
    """

    payload = _payload("ft")
    baseline = ProviderSpec.model_validate(payload)
    assert baseline.extraction is None

    scoped = ProviderSpec.model_validate(
        {**copy.deepcopy(payload), "extraction": {"scope_xpath": ["//article"]}}
    )
    assert scoped.assessment_policy_version(
        "configured-r1"
    ) != baseline.assessment_policy_version("configured-r1")

    # The scope is extraction policy, not assessment evidence: the two are
    # allowed to diverge, so a matching article_xpath must not collapse them.
    assert scoped.extraction is not None
    assert scoped.extraction.scope_xpath != scoped.assessment.article_xpath

    # Reuters and Axios declare a scope. Every other provider's
    # identity therefore hashes an ``extraction``-free payload, exactly as it did
    # before the section existed, so no archive churns for a change it did not
    # receive. Adding a scope elsewhere must fail here and be considered against
    # that cost first.
    scoped_providers = {
        spec.key
        for spec in load_builtin_provider_specs()
        if spec.extraction is not None
    }
    assert scoped_providers == {"reuters", "axios"}

    with pytest.raises(ValidationError):
        ProviderSpec.model_validate(
            {**copy.deepcopy(payload), "extraction": {"scope_xpath": []}}
        )
    with pytest.raises(ValidationError):
        ProviderSpec.model_validate(
            {**copy.deepcopy(payload), "extraction": {"scope_xpath": ["not an xpath("]}}
        )


def test_search_kind_is_discriminated_with_legacy_html_compatibility() -> None:
    legacy_html = _payload("ft")
    legacy_html["search"].pop("kind")  # type: ignore[union-attr]
    parsed = ProviderSpec.model_validate(legacy_html)

    assert parsed.search.kind == "html"
    assert parsed.require_html_search().query_parameter == "q"
    with pytest.raises(ProviderDefinitionError, match="adapter search"):
        parsed.require_adapter_search()

    adapter = ProviderSpec.model_validate(_payload("cnbc"))
    assert str(adapter.require_adapter_search().endpoint) == (
        "https://api.queryly.com/cnbc/json.aspx"
    )
    with pytest.raises(ProviderDefinitionError, match="HTML search"):
        adapter.require_html_search()

    phantom_html_fields = _payload("cnbc")
    phantom_html_fields["search"]["result_xpath"] = ["//a"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="Extra inputs"):
        ProviderSpec.model_validate(phantom_html_fields)


def test_definition_rejects_invalid_xpath_and_unknown_fields() -> None:
    invalid_xpath = _payload("wsj")
    invalid_xpath["search"]["result_xpath"] = ["//*[invalid"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="invalid XPath"):
        ProviderSpec.model_validate(invalid_xpath)

    unknown = _payload("ft")
    unknown["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        ProviderSpec.model_validate(unknown)

    missing_empty_evidence = _payload("ft")
    missing_empty_evidence["search"]["empty_result_xpath"] = []  # type: ignore[index]
    with pytest.raises(ValidationError):
        ProviderSpec.model_validate(missing_empty_evidence)


def test_browser_readiness_configuration_rejects_silent_noops() -> None:
    blank_selector = _payload("wsj")
    blank_selector["browser_retrieval"]["ready_selectors"] = ["article", " "]  # type: ignore[index]
    with pytest.raises(ValidationError, match="browser retrieval entries"):
        ProviderSpec.model_validate(blank_selector)

    zero_timeout = _payload("wsj")
    zero_timeout["browser_retrieval"]["ready_timeout_seconds"] = 0  # type: ignore[index]
    with pytest.raises(ValidationError, match="positive timeout"):
        ProviderSpec.model_validate(zero_timeout)

    unused_timeout = _payload("cnbc")
    unused_timeout["browser_retrieval"] = {"ready_timeout_seconds": 3}
    with pytest.raises(ValidationError, match="timeout requires selectors"):
        ProviderSpec.model_validate(unused_timeout)

    unknown_resource_type = _payload("bloomberg")
    unknown_resource_type["browser_retrieval"]["block_resource_types"] = [  # type: ignore[index]
        "beacon"
    ]
    with pytest.raises(ValidationError, match="Input should be"):
        ProviderSpec.model_validate(unknown_resource_type)

    stability_past_timeout = _payload("bloomberg")
    stability_past_timeout["browser_retrieval"]["semantic_readiness"] = {  # type: ignore[index]
        "timeout_seconds": 1,
        "stable_seconds": 2,
    }
    with pytest.raises(ValidationError, match="stability cannot exceed"):
        ProviderSpec.model_validate(stability_past_timeout)

    polling_past_stability = _payload("bloomberg")
    polling_past_stability["browser_retrieval"]["semantic_readiness"] = {  # type: ignore[index]
        "timeout_seconds": 3,
        "stable_seconds": 0.1,
        "poll_seconds": 0.2,
    }
    with pytest.raises(ValidationError, match="poll interval cannot exceed"):
        ProviderSpec.model_validate(polling_past_stability)


def test_published_date_group_must_exist_in_identity_pattern() -> None:
    payload = _payload("ft")
    payload["search"]["published_date_identity_group"] = "missing"  # type: ignore[index]

    with pytest.raises(ValidationError, match="must exist in the article path"):
        ProviderSpec.model_validate(payload)


@pytest.mark.parametrize(
    ("provider", "mutate"),
    [
        (
            "ft",
            lambda payload: payload["search"].update(
                {"result_xpath": ["boolean(//a)"]}
            ),
        ),
        (
            "ft",
            lambda payload: payload["search"].update(
                {"published_container_xpath": "string(ancestor::article[1])"}
            ),
        ),
        (
            "ft",
            lambda payload: payload["assessment"]["negative_rules"][0].update(
                {"xpath_any": ["count(//*[@id='challenge-form'])"]}
            ),
        ),
        (
            "ft",
            lambda payload: payload["assessment"].update(
                {"article_xpath": ["string(//title)"]}
            ),
        ),
        (
            "bloomberg",
            lambda payload: payload["assessment"]["paragraph_floor"].update(
                {"root_xpath": "count(//article)"}
            ),
        ),
    ],
)
def test_element_xpath_roles_reject_scalar_results(provider, mutate) -> None:
    payload = _payload(provider)
    mutate(payload)

    with pytest.raises(ValidationError, match="must return a node-set"):
        ProviderSpec.model_validate(payload)


def test_non_element_node_set_cannot_supply_article_or_paragraph_evidence() -> None:
    payload = _payload("bloomberg")
    payload["assessment"]["article_xpath"] = ["//article/@data-proof"]  # type: ignore[index]
    payload["assessment"]["paragraph_floor"]["root_xpath"] = (  # type: ignore[index]
        "//article/@data-proof"
    )
    spec = ProviderSpec.model_validate(payload)
    url = (
        "https://www.bloomberg.com/news/articles/2026-07-16/"
        "fixture-chipmaker-beats-estimates"
    )
    raw_html = (
        (Path(__file__).parent / "fixtures" / "bloomberg" / "full.html")
        .read_bytes()
        .replace(b"<article>", b"<article data-proof='present'>")
    )
    fetch = RawFetch(
        requested_url=url,
        final_url=url,
        http_status=200,
        content_type="text/html; charset=utf-8",
        retrieved_at=datetime(2026, 7, 17, tzinfo=UTC),
        raw_html=raw_html,
    )
    extraction = TrafilaturaExtractor().extract(fetch)

    assessment = ConfiguredProvider(spec).assess(url, fetch, extraction)

    assert assessment.access_state is AccessState.UNKNOWN
    assert "article_body_structure" not in assessment.structural_signals
    assert "article_paragraph_floor" not in assessment.structural_signals


def test_browser_retrieval_policy_is_scoped_to_owned_browser_hosts() -> None:
    wrong_transport = _payload("ft")
    wrong_transport["browser_retrieval"]["warmup_urls"] = [  # type: ignore[index]
        "https://www.ft.com/"
    ]
    with pytest.raises(ValidationError, match="requires browser transport"):
        ProviderSpec.model_validate(wrong_transport)

    foreign_host = _payload("bloomberg")
    foreign_host["browser_retrieval"]["warmup_urls"] = [  # type: ignore[index]
        "https://evil.test/"
    ]
    with pytest.raises(ValidationError, match="canonical provider HTTPS URLs"):
        ProviderSpec.model_validate(foreign_host)

    foreign_callback = _payload("bloomberg")
    foreign_callback["auth"]["post_callback_urls"] = [  # type: ignore[index]
        "https://evil.test/callback"
    ]
    with pytest.raises(ValidationError, match="post-callback URLs"):
        ProviderSpec.model_validate(foreign_callback)


def test_provider_lifecycle_and_verification_sources_are_coherent() -> None:
    invalid_default = _payload("ft")
    invalid_default["session"]["default_verification_url"] = (  # type: ignore[index]
        "https://www.ft.com/search"
    )
    with pytest.raises(ValidationError, match="must identify an article"):
        ProviderSpec.model_validate(invalid_default)

    unreachable = _payload("bloomberg")
    unreachable["enabled_by_default"] = False
    with pytest.raises(ValidationError, match="need an enablement environment"):
        ProviderSpec.model_validate(unreachable)

    ambiguous = _payload("ft")
    ambiguous["session"]["verification_url_environment"] = "FT_VERIFY"  # type: ignore[index]
    with pytest.raises(ValidationError, match="exactly one verification URL source"):
        ProviderSpec.model_validate(ambiguous)


def test_candidate_verification_mode_is_explicit_with_compatible_default() -> None:
    specs = {spec.key: spec for spec in load_builtin_provider_specs()}

    for key in ("ft", "wsj", "bloomberg", "economist"):
        assert specs[key].require_session().candidate_verification_mode is (
            CandidateVerificationMode.BROWSER_PAID_PROBE
        )

    compatible = _payload("ft")
    compatible["session"].pop("candidate_verification_mode")  # type: ignore[union-attr]
    assert ProviderSpec.model_validate(
        compatible
    ).require_session().candidate_verification_mode is (
        CandidateVerificationMode.HTTP_PROBE
    )

    invalid = _payload("ft")
    invalid["session"]["candidate_verification_mode"] = "transport_inferred"  # type: ignore[index]
    with pytest.raises(ValidationError):
        ProviderSpec.model_validate(invalid)


def test_anonymous_provider_omits_session_and_auth_configuration() -> None:
    payload = _payload("ft")
    payload["capabilities"].update(  # type: ignore[union-attr]
        {
            "session_kind": "none",
            "requires_session_for_retrieve": False,
            "requires_session_for_search": False,
        }
    )
    del payload["session"]
    del payload["auth"]

    spec = ProviderSpec.model_validate(payload)
    provider = ConfiguredProvider(spec)

    assert spec.session is None
    assert spec.auth is None
    assert provider.login_recipe is None


def test_anonymous_provider_rejects_session_auth_and_browser_contracts() -> None:
    configured_session = _payload("ft")
    configured_session["capabilities"]["session_kind"] = "none"  # type: ignore[index]
    with pytest.raises(ValidationError, match="must not configure session or auth"):
        ProviderSpec.model_validate(configured_session)

    required_session = _payload("ft")
    required_session["capabilities"]["session_kind"] = "none"  # type: ignore[index]
    del required_session["session"]
    del required_session["auth"]
    with pytest.raises(ValidationError, match="cannot require a session"):
        ProviderSpec.model_validate(required_session)

    browser_transport = copy.deepcopy(required_session)
    browser_transport["capabilities"][  # type: ignore[index]
        "requires_session_for_retrieve"
    ] = False
    browser_transport["capabilities"]["search_transport"] = "browser"  # type: ignore[index]
    with pytest.raises(ValidationError, match="require HTTP transports"):
        ProviderSpec.model_validate(browser_transport)

    missing_auth = _payload("ft")
    del missing_auth["auth"]
    with pytest.raises(ValidationError, match="require session and auth"):
        ProviderSpec.model_validate(missing_auth)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["assessment"].update(
                {"canonical_signal": "markdown_body"}
            ),
            "must not shadow",
        ),
        (
            lambda payload: payload["assessment"].update(
                {
                    "required_signals": payload["assessment"]["required_signals"]
                    + ("article_word_floor",)
                }
            ),
            "unknown signals",
        ),
        (
            lambda payload: payload["assessment"].update(
                {
                    "required_signals": payload["assessment"]["required_signals"]
                    + ("jsonld_absent",)
                }
            ),
            "require state recording",
        ),
    ],
)
def test_definition_rejects_unproducible_or_ambiguous_evidence(
    mutate, message: str
) -> None:
    payload = _payload("ft")
    mutate(payload)

    with pytest.raises(ValidationError, match=message):
        ProviderSpec.model_validate(payload)


def test_paragraph_floor_rejects_an_impossible_substantial_count() -> None:
    payload = _payload("bloomberg")
    payload["assessment"]["paragraph_floor"]["minimum_count"] = 1  # type: ignore[index]

    with pytest.raises(ValidationError, match="cannot exceed total count"):
        ProviderSpec.model_validate(payload)


def test_session_providers_cannot_select_an_http_impersonation_profile() -> None:
    """A session route ignores the per-host profile, so accepting one lies."""

    payload = _payload("ft")
    payload["capabilities"]["http_impersonate"] = "chrome131_android"  # type: ignore[index]

    with pytest.raises(ValidationError, match="impersonation profile"):
        ProviderSpec.model_validate(payload)


def test_anonymous_providers_keep_their_declared_impersonation_profile() -> None:
    payload = _payload("reuters")

    assert (
        ProviderSpec.model_validate(payload).capabilities.http_impersonate
        == "safari2601"
    )


def test_story_word_floor_is_bounded_by_the_rendered_word_floor() -> None:
    """The payload floor may relax the rendered floor, never exceed it.

    The two floors answer different questions — a rendered body is judged by
    size because that is all a partial DOM offers, while a payload arrives
    whole — so the payload floor is allowed to sit lower. Letting it sit higher
    would reject a payload the rendered path already accepted, which is the
    asymmetry that rejected a complete short article in the first place.
    """

    payload = _payload("bloomberg")
    assert payload["assessment"]["minimum_words"] == 250  # type: ignore[index]
    assert payload["assessment"]["story_minimum_words"] == 120  # type: ignore[index]

    baseline = ProviderSpec.model_validate(payload)
    assert baseline.assessment.effective_story_minimum_words == 120

    exceeds = copy.deepcopy(payload)
    exceeds["assessment"]["story_minimum_words"] = 251  # type: ignore[index]
    with pytest.raises(ValidationError, match="cannot exceed the rendered word floor"):
        ProviderSpec.model_validate(exceeds)

    orphaned = copy.deepcopy(payload)
    del orphaned["assessment"]["minimum_words"]  # type: ignore[union-attr]
    del orphaned["assessment"]["paragraph_floor"]  # type: ignore[union-attr]
    with pytest.raises(ValidationError, match="requires a rendered word floor"):
        ProviderSpec.model_validate(orphaned)


def test_unset_story_word_floor_keeps_the_single_shared_floor() -> None:
    """Providers that never opted in are unchanged by the new knob."""

    payload = _payload("economist")
    spec = ProviderSpec.model_validate(payload)

    assert spec.assessment.story_minimum_words is None
    assert (
        spec.assessment.effective_story_minimum_words == spec.assessment.minimum_words
    )


def test_adapter_search_api_key_reference_must_use_op() -> None:
    payload = _payload("cnbc")
    payload["search"]["api_key_ref"] = "https://example.com/key"  # type: ignore[index]
    with pytest.raises(ValidationError, match="op://"):
        ProviderSpec.model_validate(payload)

    payload["search"]["api_key_ref"] = "op://Vault/Item/credential"  # type: ignore[index]
    spec = ProviderSpec.model_validate(payload)
    assert spec.require_adapter_search().api_key_ref == "op://Vault/Item/credential"


def test_adapter_search_api_key_reference_defaults_to_none(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("NEWSCLIP_CONFIG_HOME", str(tmp_path / "empty-config"))
    for key in ("cnbc", "reuters", "bloomberg"):
        spec = ProviderSpec.model_validate(_payload(key))
        assert spec.require_adapter_search().api_key_ref is None
