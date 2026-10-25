"""Composed serving keeps safety writes without constructing login authority."""

from pathlib import Path
from uuid import uuid4

import pytest
from test_sessions import NOW, _artifact

import newsclip.composition as composition
from newsclip.errors import (
    ContentNotFullError,
    OperatorActionRequiredError,
    SessionRequiredError,
)
from newsclip.models import RawFetch, SessionStatus, StoredSession
from newsclip.providers.ft import FTProvider
from newsclip.sessions import ServingSessions, SessionStore

ARTICLE = "https://www.ft.com/content/11111111-1111-4111-8111-111111111111"
PROBE = FTProvider().login_recipe.verification_url
FIXTURES = Path(__file__).parent / "fixtures/ft"


@pytest.fixture
def serving(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_PROVIDER_ALLOWLIST", "ft")
    bodies = {ARTICLE: "full.html", PROBE: "full.html"}
    calls = []
    on_probe = []

    def forbidden(*args, **kwargs):
        pytest.fail("serving attempted credential or browser acquisition")

    def get(client, url, *, session=None, timeout=40):
        calls.append(url)
        if url == PROBE:
            for callback in on_probe:
                callback()
        fixture = "search_results.html" if "/search?" in url else bodies[url]
        body = (FIXTURES / fixture).read_bytes()
        if url == PROBE:
            body = body.replace(
                ARTICLE.rsplit("/", 1)[-1].encode(), PROBE.rsplit("/", 1)[-1].encode()
            )
        return RawFetch(
            requested_url=url,
            final_url=(
                "https://www.ft.com/barrier/concurrency"
                if fixture == "account_security_reset.html"
                else url
            ),
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=body,
        )

    class OfflineBrowser:
        """The challenge escalation's browser leg, served from the same fixtures.

        A challenged HTTP probe escalates to the provider's browser profile.
        CI installs Chromium, so without this the leg navigated the real FT
        site with the fixture's cookie and the verdict followed live FT.
        """

        def get_for_check(self, url, *, session=None, timeout=40):
            fetch = get(None, url, session=session, timeout=timeout)
            calls[-1] = f"browser:{url}"
            return fetch

        get = get_for_check

    monkeypatch.setattr(composition.CurlCffiHttpClient, "get", get)
    monkeypatch.setattr(
        composition.PatchrightBrowserRetriever,
        "profile_verification_client",
        lambda self, key: (OfflineBrowser(), None),
    )

    class NoBrowser:
        def get(self, *args, **kwargs):
            pytest.fail("serving navigated a browser outside the offline fixtures")

        get_for_check = get

    monkeypatch.setattr(
        composition.PatchrightBrowserRetriever,
        "for_provider",
        lambda self, key, **kwargs: NoBrowser(),
    )
    monkeypatch.setattr("newsclip.login.OpSecretFiller.__init__", forbidden)
    monkeypatch.setattr(SessionStore, "explicit_login", forbidden)
    service = composition.build_mcp_service()
    assert isinstance(service._sessions, ServingSessions)
    store = service._sessions._store
    assert store._adapters == {}
    assert store._credential_readiness_probes == {}
    monkeypatch.setattr(store, "_now", lambda: NOW)
    monkeypatch.setattr(service, "_wall_clock", lambda: NOW)
    artifact = _artifact()
    store._write(
        "ft", "default", StoredSession(status=SessionStatus.VERIFIED, artifact=artifact)
    )
    try:
        yield service, store, artifact, bodies, calls, on_probe
    finally:
        service.close()


def test_serving_reads_search_and_archive_keep_existing_authority(serving):
    service, store, artifact, _, calls, _ = serving
    before = store._state_path("ft", "default").read_bytes()
    assert service.search("ft", "fixture")
    assert service.get(ARTICLE).provider == "ft"
    saved = service.save(ARTICLE)
    assert service.archive_get(saved.id).body_markdown == saved.body_markdown
    assert service.session_status("ft").status is SessionStatus.VERIFIED
    assert store.get_valid_session("ft") == artifact
    assert store._state_path("ft", "default").read_bytes() == before
    assert len(calls) == 3
    assert calls[-2:] == [ARTICLE, ARTICLE]


def test_serving_missing_session_never_attempts_login(serving):
    service, store, _, _, calls, _ = serving
    store.clear("ft")  # Operator setup of the missing-state scenario.
    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE)
    assert calls == []
    assert service.session_status("ft").status is SessionStatus.REQUIRED


@pytest.mark.parametrize("rotates_during_probe", [False, True])
def test_serving_dead_proof_only_downgrades_its_generation(
    serving, rotates_during_probe
):
    service, store, artifact, bodies, calls, on_probe = serving
    bodies[ARTICLE] = "teaser.html"
    bodies[PROBE] = "auth.html"
    replacement = artifact.model_copy(update={"generation_id": uuid4()})
    if rotates_during_probe:
        on_probe.append(
            lambda: store._write(
                "ft",
                "default",
                StoredSession(status=SessionStatus.VERIFIED, artifact=replacement),
            )
        )
    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE)
    assert calls == [ARTICLE, PROBE]
    if rotates_during_probe:
        assert store.get_valid_session("ft") == replacement
    else:
        assert service.session_status("ft").status is SessionStatus.REQUIRED


def test_serving_inconclusive_proof_preserves_authority(serving):
    service, store, artifact, bodies, calls, _ = serving
    bodies[ARTICLE] = "teaser.html"
    bodies[PROBE] = "interstitial.html"
    before = store._state_path("ft", "default").read_bytes()
    with pytest.raises(ContentNotFullError):
        service.get(ARTICLE)
    # The challenged probe escalates once to the browser, which is challenged too.
    assert calls == [ARTICLE, PROBE, f"browser:{PROBE}"]
    assert store.get_valid_session("ft") == artifact
    assert store._state_path("ft", "default").read_bytes() == before


def test_serving_account_alert_persists_without_an_extra_probe(serving):
    service, store, _, bodies, calls, _ = serving
    bodies[ARTICLE] = "account_security_reset.html"
    with pytest.raises(OperatorActionRequiredError) as caught:
        service.get(ARTICLE)
    assert caught.value.reason_code == "account_alert"
    assert caught.value.incident_id is not None
    assert store.status("ft").status is SessionStatus.OPERATOR_ACTION
    assert calls == [ARTICLE]


def test_serving_full_evidence_clears_expired_containment(serving):
    service, store, artifact, _, calls, _ = serving
    defense = service._defense
    record = defense.arm("ft", origin="retrieval")
    defense._write("ft", record.model_copy(update={"active_until": NOW}))
    assert service.get(ARTICLE).provider == "ft"
    assert defense.status("ft") is None
    assert store.get_valid_session("ft") == artifact
    assert calls == [ARTICLE]


def test_serving_view_rejects_a_store_with_acquisition_collaborators(serving):
    _, store, _, _, _, _ = serving
    store._credential_readiness_probes["ft"] = lambda: None
    with pytest.raises(ValueError, match="acquisition collaborators"):
        ServingSessions(store)
