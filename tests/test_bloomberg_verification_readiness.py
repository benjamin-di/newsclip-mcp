"""Serving must wait for entitlement proof even when story delivery is complete.

Only the browser document and clock are fake. Composition, both navigations,
extraction, verification, article acceptance and recovery handoff are real.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from lxml import html
from test_bloomberg_provider import ARTICLE_URL, FIXTURES, _with_full_story_bootstrap
from test_browser_plane import FakeContext, FakeMonotonicClock, FakePage

from newsclip.composition import build_service
from newsclip.errors import ContentNotFullError, SessionRequiredError
from newsclip.models import (
    PortableCookie,
    SessionArtifact,
    SessionStatus,
    StoredSession,
)


@pytest.fixture
def serving(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_PROVIDER_ALLOWLIST", "bloomberg")
    service = build_service()
    now = datetime.now(UTC)
    artifact = SessionArtifact(
        generation_id=uuid4(),
        provider="bloomberg",
        created_at=now,
        verified_at=now,
        cookies=(
            PortableCookie(name="session", value="fixture", domain=".bloomberg.com"),
        ),
    )
    service._sessions._write(
        "bloomberg",
        "default",
        StoredSession(status=SessionStatus.VERIFIED, artifact=artifact),
    )
    provider = service._registry.get("bloomberg")
    verification_url = provider.login_recipe.verification_url
    clock = FakeMonotonicClock()
    full = _with_full_story_bootstrap()
    document = html.fromstring(full)
    for paragraph in document.xpath("//article/p")[1:]:
        paragraph.getparent().remove(paragraph)
    teaser = html.tostring(document)
    state = {"proof": "delayed", "target_full": False}
    pages = []

    class Page(FakePage):
        def goto(self, *args, **kwargs):
            self.started = clock()
            return super().goto(*args, **kwargs)

        def route(self, *args):
            pass

        def wait_for_timeout(self, milliseconds):
            clock.advance(milliseconds / 1000)

        def content(self):
            body = teaser
            if self.url == verification_url:
                proof = state["proof"]
                if proof == "auth":
                    body = (FIXTURES / "auth.html").read_bytes()
                elif proof == "full" or (
                    proof == "delayed" and clock() - self.started >= 1
                ):
                    body = full
            elif state["target_full"]:
                body = full
            return body.replace(ARTICLE_URL.encode(), self.url.encode()).decode()

    class Context(FakeContext):
        def new_page(self):
            page = Page(self)
            pages.append(page)
            return page

        def cookies(self):
            return [
                {
                    "name": "session",
                    "value": "fixture",
                    "domain": ".bloomberg.com",
                    "path": "/",
                }
            ]

    retriever = service._browser_retriever
    retriever._runtime = None
    retriever._require_virtual_display = False
    retriever._context_factory = Context
    retriever._monotonic_clock = clock
    retriever._challenge_resolvers = {}
    # Model an existing profile, avoiding the unrelated empty-profile warmups.
    profile = service._sessions._profiles.path("bloomberg", "default")
    profile.mkdir(parents=True, exist_ok=True)
    (profile / "fixture-profile").touch()
    try:
        yield service, state, clock, pages, verification_url
    finally:
        service.close()


def _navigations(pages):
    return [url for page in pages for url, _, _ in page._context.goto_calls]


def test_serving_waits_for_delayed_entitlement_without_an_extra_navigation(serving):
    service, _, clock, pages, verification_url = serving

    article = service.get(ARTICLE_URL)

    assert article.word_count > 250
    assert str(article.url) == ARTICLE_URL
    assert _navigations(pages) == [ARTICLE_URL, verification_url]
    assert 1.3 <= clock() < 2
    assert service._recovery_store.load("bloomberg") is None


def test_permanent_teaser_exhausts_existing_window_and_still_queues_recovery(serving):
    service, state, clock, pages, verification_url = serving
    state["proof"] = "teaser"

    with pytest.raises(ContentNotFullError):
        service.get(ARTICLE_URL)

    assert _navigations(pages) == [ARTICLE_URL, verification_url]
    assert 3 <= clock() < 3.5
    recovery = service._recovery_store.load("bloomberg")
    assert recovery is not None
    assert not recovery.session_required
    assert recovery.health.attempts == 0
    assert service._sessions.get_valid_session("bloomberg") is not None


def test_explicit_authentication_failure_is_conclusive_without_waiting_three_seconds(
    serving,
):
    service, state, clock, pages, verification_url = serving
    state["proof"] = "auth"

    with pytest.raises(SessionRequiredError):
        service.get(ARTICLE_URL)

    assert _navigations(pages) == [ARTICLE_URL, verification_url]
    assert clock() < 1


def test_already_full_article_keeps_the_fast_path_without_a_probe(serving):
    service, state, clock, pages, _ = serving
    state["target_full"] = True

    assert service.get(ARTICLE_URL).word_count > 250
    assert _navigations(pages) == [ARTICLE_URL]
    assert clock() < 0.5


def test_complete_payload_remains_usable_with_an_immediately_verified_probe(serving):
    service, state, clock, pages, verification_url = serving
    state["proof"] = "full"

    assert service.get(ARTICLE_URL).word_count > 250
    assert _navigations(pages) == [ARTICLE_URL, verification_url]
    assert clock() < 1
