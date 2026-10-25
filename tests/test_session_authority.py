"""Browser authority, isolated import, and publication regression tests.

The fake Chromium persists a cookie jar per profile. Article access depends on
that jar, not on the SessionArtifact argument, just as in the real transport.
"""

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from newsclip.browser_profiles import BrowserProfileManager
from newsclip.browser_retrieval import PatchrightBrowserRetriever
from newsclip.browser_runtime import HttpOperationRole, LeaseManager, PatchrightRuntime
from newsclip.errors import OperatorActionRequiredError, SessionRequiredError
from newsclip.models import SessionStatus
from newsclip.provider_config import BrowserRetrievalSpec
from newsclip.providers.wsj import WSJProvider
from newsclip.sessions import ServingSessions, SessionStore

URL = "https://www.wsj.com/finance/banks-rally-capital-1a2b3c4d"
NOW = datetime(2026, 9, 5, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures/wsj"


def cookie(value):
    return {"name": "djcs_session", "value": value, "domain": ".wsj.com", "path": "/"}


class ProfileHarness:
    def __init__(self, root, *, trace=None):
        self.jars = {}
        self.contexts = []
        self.visits = []
        self.captures = []
        owner = self

        class Page:
            url = "about:blank"

            def __init__(self, context):
                self.context = context

            def goto(self, url, **kwargs):
                self.url = url
                owner.visits.append((self.context.profile, url))
                return SimpleNamespace(
                    status=200, headers={"content-type": "text/html"}
                )

            def wait_for_timeout(self, *_):
                pass

            def wait_for_load_state(self, *_, **kwargs):
                pass

            def content(self):
                if not any(c["value"] == "working" for c in self.context.cookies()):
                    return (FIXTURES / "auth.html").read_text()
                html = (FIXTURES / "full.html").read_text()
                extra = "".join(
                    "<p>"
                    + f"Synthetic paragraph {i} describes "
                    + " ".join(f"fictionalword{i}_{j}" for j in range(50))
                    + ".</p>"
                    for i in range(10)
                )
                return html.replace("</article>", extra + "</article>")

            def screenshot(self, **kwargs):
                assert not self.context.closed
                owner.captures.append(self.context.profile)
                return b"private-proof-viewport"

        class Context:
            def __init__(self, **kwargs):
                self.profile = Path(kwargs["user_data_dir"])
                self.profile.mkdir(parents=True, exist_ok=True)
                (self.profile / "device-state").touch()
                owner.jars.setdefault(self.profile, [])
                owner.contexts.append(self)
                self.closed = False

            def add_cookies(self, cookies):
                owner.jars[self.profile] = [dict(c) for c in cookies]

            def cookies(self):
                return owner.jars[self.profile]

            def new_page(self):
                return Page(self)

            def close(self):
                self.closed = True

        self.profiles = BrowserProfileManager(
            root / "profiles",
            runtime=PatchrightRuntime(context_factory=Context, trace=trace),
            launch_configs={},
        )
        self.retriever = PatchrightBrowserRetriever(
            context_factory=Context,
            runtime=PatchrightRuntime(context_factory=Context, trace=trace),
            profile_resolver=self.profiles.path,
            lease_manager=LeaseManager(root / "locks"),
            policies={"wsj": BrowserRetrievalSpec()},
            clock=lambda: NOW,
            retain_profile=False,
            session_cookie_domains={"wsj": frozenset({"wsj.com", "dowjones.com"})},
        )
        self.recipe = WSJProvider(verification_url=URL).login_recipe

        def verify_profile(recipe, artifact):
            client, capture = self.retriever.profile_verification_client(
                recipe.provider
            )
            try:
                verification = recipe.verify(client, artifact)
            finally:
                self.retriever.release()
            assert capture.cookies is not None
            return verification, capture.cookies

        self.store = SessionStore(
            root / "sessions",
            recipes={"wsj": self.recipe},
            http=self.retriever.for_provider(
                "wsj", role=HttpOperationRole.VERIFICATION
            ),
            lease_manager=LeaseManager(root / "locks"),
            profile_access=self.profiles,
            verification_requires_browser=lambda _: True,
            clock=lambda: NOW,
            profile_verifier=verify_profile,
            diagnostic_trace=trace,
        )

    def seed_legacy(self, value):
        profile = self.profiles.path("wsj", "default")
        profile.mkdir(parents=True)
        (profile / "device-state").touch()
        self.jars[profile] = [cookie(value)]
        return profile


@pytest.fixture
def browser(tmp_path):
    harness = ProfileHarness(tmp_path)
    yield harness
    harness.retriever.close()


@pytest.mark.parametrize("change", ["addition", "rotation"])
@pytest.mark.parametrize("purpose", ["read", "provider_check"])
@pytest.mark.parametrize("builder_name", ["build_auth_service", "build_mcp_service"])
def test_read_proof_accepts_profile_cookie_changes_without_weakening_imports(
    tmp_path, monkeypatch, browser, change, purpose, builder_name
):
    import newsclip.composition as composition
    from newsclip.acquisition import verification_verdict
    from newsclip.errors import BrowserAuthorityChangedError
    from newsclip.models import SessionDisposition

    analytics = {**cookie("initial"), "name": "analytics"}
    candidate = [cookie("working")]
    if change == "rotation":
        candidate.append(analytics)
    artifact = browser.store.import_cookies("wsj", candidate)
    profile = browser.visits[-1][0]
    if change == "addition":
        browser.jars[profile].append(analytics)
    else:
        browser.jars[profile][-1]["value"] = "rotated"

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "service-state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "service-data"))
    monkeypatch.setenv("NEWSCLIP_WSJ_VERIFICATION_URL", URL)
    monkeypatch.setenv(composition._PROVIDER_ALLOWLIST_ENVIRONMENT, "wsj")
    monkeypatch.setattr(
        composition, "PatchrightBrowserRetriever", lambda **kwargs: browser.retriever
    )
    service = getattr(composition, builder_name)()
    provider = WSJProvider(verification_url=URL)
    try:
        start = len(browser.visits)
        if purpose == "read":
            verdict = service._classify_session(provider, artifact).disposition
        else:
            with service._provider_check_verification_client(provider) as client:
                verdict = verification_verdict(
                    provider.login_recipe.verify(client, artifact)
                )
        assert verdict is SessionDisposition.VERIFIED
        assert browser.visits[start:] == [(profile, URL)]
        assert all(context.closed for context in browser.contexts)
        assert browser.store.get_valid_session("wsj") == artifact
        assert service._sessions.status("wsj").status is SessionStatus.REQUIRED

        # The candidate factory still refuses ambient cookies before navigation.
        start = len(browser.visits)
        store = service._sessions
        if isinstance(store, ServingSessions):
            store = store._store
        with (
            pytest.raises(BrowserAuthorityChangedError),
            store._client_factory("wsj") as client,
        ):
            provider.login_recipe.verify(client, artifact)
        assert len(browser.visits) == start
        assert all(context.closed for context in browser.contexts)
    finally:
        service.close()


def test_bad_import_cannot_borrow_a_healthy_profiles_authority(browser):
    legacy = browser.seed_legacy("working")
    with pytest.raises((SessionRequiredError, OperatorActionRequiredError)):
        browser.store.import_cookies("wsj", [cookie("invalid")])
    assert browser.store.status("wsj").status is SessionStatus.REQUIRED
    assert browser.jars[legacy] == [cookie("working")]


def test_rejected_proof_retains_viewport_captured_before_browser_close(tmp_path):
    from newsclip.browser_runtime.events import RuntimeTrace, read_runtime_file

    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="proof-evidence")
    harness = ProfileHarness(tmp_path, trace=trace)
    try:
        with pytest.raises((SessionRequiredError, OperatorActionRequiredError)):
            harness.store.import_cookies("wsj", [cookie("invalid")])
        assert len(harness.captures) == 1
        assert all(context.closed for context in harness.contexts)
        assert next(tmp_path.glob("*.png")).read_bytes() == b"private-proof-viewport"
        read_runtime_file(tmp_path / "trace.jsonl")
    finally:
        harness.retriever.close()


@pytest.mark.parametrize("failure", ["close", "publication"])
def test_failed_warm_rotation_preserves_authority_and_proof_evidence(
    tmp_path, monkeypatch, failure
):
    from newsclip.browser_runtime.events import RuntimeTrace, read_runtime_file
    from newsclip.errors import PersistenceError, ProviderTransportError

    path = tmp_path / "trace.jsonl"
    harness = ProfileHarness(tmp_path, trace=RuntimeTrace(path, run_id="warm-evidence"))
    try:
        prior = harness.store.import_cookies("wsj", [cookie("working")])
        assert not list(tmp_path.glob("*.png"))
        harness.jars[harness.visits[-1][0]].append(
            {**cookie("rotation"), "name": "analytics"}
        )
        harness.store._adapters["wsj"] = object()
        if failure == "close":

            def fail(context):
                context.closed = True
                raise RuntimeError("fixture close failure")

            monkeypatch.setattr(type(harness.contexts[0]), "close", fail)
        else:

            def fault(point):
                if point == "before_session_replace":
                    raise OSError("fixture publication failure")

            harness.store._fault_hook = fault
        with pytest.raises((ProviderTransportError, PersistenceError)):
            harness.store.explicit_login("wsj", allow_credential_mint=False)
        assert harness.store.get_valid_session("wsj") == prior
        assert len(list(tmp_path.glob("*.png"))) == 1
        records = read_runtime_file(path).records
        assert [
            record.event.stage
            for record in records
            if record.event.event == "acquisition_evidence"
        ][-1] == "failed"
    finally:
        harness.retriever.close()


def test_good_import_recovers_without_overwriting_a_stale_profile(browser):
    legacy = browser.seed_legacy("stale")
    candidate = browser.store.import_cookies("wsj", [cookie("working")])
    assert browser.store.status("wsj").status is SessionStatus.VERIFIED
    assert browser.jars[legacy] == [cookie("stale")]
    assert browser.recipe.verify(browser.retriever, candidate).verified


def test_failed_import_preserves_the_published_generation(browser):
    prior = browser.store.import_cookies("wsj", [cookie("working")])
    with pytest.raises((SessionRequiredError, OperatorActionRequiredError)):
        browser.store.import_cookies("wsj", [cookie("invalid")])
    assert browser.store.get_valid_session("wsj") == prior
    assert browser.recipe.verify(browser.retriever, prior).verified


@pytest.mark.parametrize(
    "failure_point", ["before_session_replace", "after_session_replace"]
)
def test_import_publication_has_one_commit_point(browser, failure_point):
    from newsclip.errors import PersistenceError

    prior = browser.store.import_cookies("wsj", [cookie("working")])

    def fail(point):
        if point == failure_point:
            raise OSError("synthetic persistence failure")

    browser.store._fault_hook = fail
    with pytest.raises(PersistenceError):
        browser.store.import_cookies("wsj", [cookie("working")])
    # Read through a new store: no in-memory state may select the profile.
    reopened = SessionStore(
        browser.store.root,
        recipes={"wsj": browser.recipe},
        http=browser.retriever,
        clock=lambda: NOW,
    )
    current = reopened.get_valid_session("wsj")
    assert (current == prior) == (failure_point == "before_session_replace")
    assert browser.recipe.verify(browser.retriever, current).verified
    assert browser.recipe.verify(browser.retriever, prior).verified
    assert all(context.closed for context in browser.contexts)


def test_reader_with_old_artifact_can_finish_after_import_publication(browser):
    prior = browser.store.import_cookies("wsj", [cookie("working")])
    current = browser.store.import_cookies("wsj", [cookie("working")])
    assert current.browser_profile_id != prior.browser_profile_id
    assert browser.recipe.verify(browser.retriever, prior).verified
    old_path = browser.visits[-1][0]
    assert browser.recipe.verify(browser.retriever, current).verified
    assert browser.visits[-1][0] != old_path
    assert browser.store.get_valid_session("wsj") == current


def test_warm_verification_detects_different_authority_before_navigation(browser):
    from newsclip.errors import BrowserAuthorityChangedError

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    path = browser.visits[-1][0]
    browser.jars[path] = [cookie("rotated")]
    visits = list(browser.visits)
    client = browser.retriever.for_provider("wsj", role=HttpOperationRole.VERIFICATION)
    with pytest.raises(BrowserAuthorityChangedError):
        browser.recipe.verify(client, prior)
    assert browser.visits == visits
    assert browser.jars[path] == [cookie("rotated")]
    assert browser.store.get_valid_session("wsj") == prior


def test_import_does_not_accept_a_foreign_profile_locator(browser):
    prior = browser.store.import_cookies("wsj", [cookie("working")])
    imported = browser.store.import_cookies("wsj", prior.model_dump(mode="json"))
    assert imported.browser_profile_id != prior.browser_profile_id
    assert imported.generation_id != prior.generation_id


def test_dead_session_retains_its_profile_for_recovery(browser):
    prior = browser.store.import_cookies("wsj", [cookie("working")])
    browser.store.mark_required("wsj", generation_id=prior.generation_id)
    with pytest.raises(SessionRequiredError):
        browser.store.get_valid_session("wsj")
    inactive = browser.store._load("wsj", "default")
    assert inactive.artifact.browser_profile_id == prior.browser_profile_id
    assert inactive.status is SessionStatus.REQUIRED


def test_verification_cleanup_failure_cannot_publish_an_import(browser, monkeypatch):
    from newsclip.errors import ProviderTransportError

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    context_type = type(browser.contexts[0])

    def fail_close(context):
        context.closed = True
        raise OSError("synthetic close failure")

    monkeypatch.setattr(context_type, "close", fail_close)
    with pytest.raises(ProviderTransportError):
        browser.store.import_cookies("wsj", [cookie("working")])
    assert browser.store.get_valid_session("wsj") == prior


def test_import_can_publish_while_an_old_reader_holds_its_profile(browser, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    old_path = browser.visits[-1][0]
    entered, finish = Event(), Event()
    page_type = type(browser.contexts[0].new_page())
    navigate = page_type.goto

    def paused(page, url, **kwargs):
        if page.context.profile == old_path:
            entered.set()
            assert finish.wait(5), "old reader was not released"
        return navigate(page, url, **kwargs)

    monkeypatch.setattr(page_type, "goto", paused)
    reader = PatchrightBrowserRetriever(
        context_factory=type(browser.contexts[0]),
        profile_resolver=browser.profiles.path,
        lease_manager=browser.store._leases,
        retain_profile=False,
    )
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            reading = executor.submit(reader.get, URL, session=prior)
            try:
                assert entered.wait(5)
                current = browser.store.import_cookies("wsj", [cookie("working")])
                assert current.browser_profile_id != prior.browser_profile_id
                assert browser.store.get_valid_session("wsj") == current
            finally:
                finish.set()
            assert b"Synthetic paragraph" in reading.result(timeout=5).raw_html
    finally:
        reader.close()


def test_warm_acquisition_exports_and_proves_changed_profile_without_login(browser):
    from newsclip.acquisition import AcquisitionMode

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    path = browser.visits[-1][0]
    browser.jars[path].append({**cookie("analytics-state"), "name": "analytics"})

    class NoLogin:
        def rehydrate_profile(self, *args, **kwargs):
            pytest.fail("a working profile must be probed before visiting login")

    browser.store._adapters["wsj"] = NoLogin()
    result = browser.store.explicit_login("wsj", allow_credential_mint=False)
    assert result.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert result.evidence.session_proof_observed
    assert result.artifact.generation_id != prior.generation_id
    assert result.artifact.browser_profile_id == prior.browser_profile_id
    assert {c.name for c in result.artifact.cookies} == {"djcs_session", "analytics"}
    assert browser.store.get_valid_session("wsj") == result.artifact
    assert all(url == URL for _, url in browser.visits)


def test_recovered_authority_requires_successful_publication(browser):
    from newsclip.errors import PersistenceError

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    path = browser.visits[-1][0]
    browser.jars[path].append({**cookie("analytics-state"), "name": "analytics"})
    browser.store._adapters["wsj"] = object()

    def fail(point):
        if point == "before_session_replace":
            raise OSError("synthetic write failure")

    browser.store._fault_hook = fail
    with pytest.raises(PersistenceError):
        browser.store.explicit_login("wsj", allow_credential_mint=False)
    assert browser.store.get_valid_session("wsj") == prior


def test_warm_rotation_uses_one_context_and_exports_post_probe_cookies(browser):
    prior = browser.store.import_cookies("wsj", [cookie("working")])
    path = browser.visits[-1][0]
    browser.jars[path].append({**cookie("rotated"), "name": "analytics"})
    browser.store._adapters["wsj"] = object()
    contexts_before = len(browser.contexts)
    probes_before = len(browser.visits)
    acquired = browser.store.explicit_login("wsj", allow_credential_mint=False)
    assert len(browser.contexts) - contexts_before == 1
    assert len(browser.visits) - probes_before == 1
    assert acquired.artifact.generation_id != prior.generation_id
    assert any(
        c.name == "analytics" and c.value == "rotated"
        for c in acquired.artifact.cookies
    )
    assert browser.contexts[-1].closed


def test_rotation_during_probe_exports_latest_authority_without_reopening(
    browser, monkeypatch
):
    prior = browser.store.import_cookies("wsj", [cookie("working")])
    context_type = type(browser.contexts[0])
    original = context_type.cookies
    observations = []

    def changing(context):
        observations.append(True)
        return original(context) + [
            {**cookie(str(len(observations))), "name": "analytics"}
        ]

    monkeypatch.setattr(context_type, "cookies", changing)
    browser.store._adapters["wsj"] = object()
    visits = list(browser.visits)
    contexts_before = len(browser.contexts)
    acquired = browser.store.explicit_login("wsj", allow_credential_mint=False)
    assert len(browser.contexts) - contexts_before == 1
    assert len(browser.visits) - len(visits) == 1
    assert next(
        c.value for c in acquired.artifact.cookies if c.name == "analytics"
    ) == str(len(observations))
    assert acquired.artifact.generation_id != prior.generation_id
    assert browser.store.get_valid_session("wsj") == acquired.artifact


def test_warm_cleanup_failure_preserves_previous_authority(browser, monkeypatch):
    from newsclip.errors import ProviderTransportError

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    path = browser.visits[-1][0]
    browser.jars[path].append({**cookie("rotated"), "name": "analytics"})
    browser.store._adapters["wsj"] = object()
    context_type = type(browser.contexts[-1])

    def fail_close(context):
        context.closed = True
        raise OSError("fixture close failure")

    monkeypatch.setattr(context_type, "close", fail_close)
    with pytest.raises(ProviderTransportError):
        browser.store.explicit_login("wsj", allow_credential_mint=False)
    assert browser.store.get_valid_session("wsj") == prior


def test_failed_warm_navigation_cannot_retry_the_same_verification_capture(
    browser, monkeypatch
):
    from newsclip.errors import ProviderTransportError

    prior = browser.store.import_cookies("wsj", [cookie("working")])
    page_type = type(browser.contexts[-1].new_page())
    navigations = []

    def fail_navigation(page, *args, **kwargs):
        navigations.append(True)
        raise OSError("fixture failed navigation")

    monkeypatch.setattr(page_type, "goto", fail_navigation)
    client, capture = browser.retriever.profile_verification_client("wsj")
    with pytest.raises(ProviderTransportError):
        browser.recipe.verify(client, prior)
    with pytest.raises(ProviderTransportError, match="must navigate once"):
        browser.recipe.verify(client, prior)
    assert len(navigations) == 1
    assert capture.cookies is None
