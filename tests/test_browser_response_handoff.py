"""Inert Chromium coverage for a challenge replacing the main document."""

from types import SimpleNamespace

import pytest
from patchright.sync_api import sync_playwright

from newsclip.browser_retrieval import PatchrightBrowserRetriever
from newsclip.browser_runtime import LeaseManager
from newsclip.challenge_resolver import ChallengeResolutionStatus
from newsclip.challenges import ChallengeMode
from newsclip.errors import ProviderTransportError
from newsclip.provider_config import BrowserRetrievalSpec


@pytest.mark.parametrize(
    "destination",
    [
        "/article",
        "/article#section",
        "/article?view=full",
        "about:blank",
        "data:text/html,<article>Unrelated document</article>",
    ],
)
def test_same_document_history_updates_preserve_the_original_response(
    tmp_path, destination
):
    url = "https://fixture.invalid/article"
    navigations = []
    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch(headless=True)

        def context_factory(**kwargs):
            context = chromium.new_context()

            def route_request(route):
                navigations.append(route.request.url)
                route.fulfill(
                    status=206,
                    content_type="text/html",
                    body="<article>Inert same-document fixture</article>",
                )

            context.route("**/*", route_request)
            return context

        class Resolver:
            def resolve(self, browser, mode):
                if destination.startswith("/"):
                    browser.page.evaluate(
                        "destination => history.replaceState({}, '', destination)",
                        destination,
                    )
                else:
                    browser.page.goto(destination)
                return SimpleNamespace(status=ChallengeResolutionStatus.NOT_PRESENT)

        retriever = PatchrightBrowserRetriever(
            context_factory=context_factory,
            profile_resolver=lambda *_: tmp_path / "profile",
            lease_manager=LeaseManager(tmp_path / "leases"),
            policies={"publicish": BrowserRetrievalSpec()},
            challenge_resolvers={"publicish": Resolver()},
            retain_profile=False,
        )
        try:
            if not destination.startswith("/"):
                with pytest.raises(
                    ProviderTransportError, match="response document changed"
                ):
                    retriever.for_provider("publicish").get(url)
                assert navigations == [url]
                return
            result = retriever.for_provider("publicish").get(url)
            assert result.http_status == 206
            assert b"Inert same-document fixture" in result.raw_html
            assert navigations == [url]
        finally:
            retriever.close()
            chromium.close()


@pytest.mark.parametrize("history_update", [False, True])
def test_real_browser_preserves_response_metadata_through_challenge_navigation(
    tmp_path,
    history_update,
):
    url = "https://fixture.invalid/search"
    navigations = []
    payload = b'{"stories":[{"headline":"Inert fixture"}]}'

    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch(headless=True)

        def context_factory(**kwargs):
            context = chromium.new_context()

            def route_request(route):
                if route.request.url != url:
                    route.abort()
                    return
                navigations.append(route.request.url)
                first = len(navigations) == 1
                route.fulfill(
                    status=403 if first else 206,
                    content_type="text/html" if first else "application/json",
                    body="<html><body>Fixture challenge</body></html>"
                    if first
                    else payload,
                )

            context.route("**/*", route_request)
            return context

        class Resolver:
            def resolve(self, browser, mode):
                # Simulate browser-native challenge passage. The retriever must
                # observe this response, not issue a third request to inspect it.
                with browser.page.expect_navigation(wait_until="domcontentloaded"):
                    browser.page.evaluate("() => location.reload()")
                if history_update:
                    browser.page.evaluate(
                        "history.replaceState({}, '', '/search?view=full')"
                    )
                return SimpleNamespace(status=ChallengeResolutionStatus.CLEARED)

        retriever = PatchrightBrowserRetriever(
            context_factory=context_factory,
            profile_resolver=lambda *_: tmp_path / "profile",
            lease_manager=LeaseManager(tmp_path / "leases"),
            policies={"publicish": BrowserRetrievalSpec()},
            challenge_resolvers={"publicish": Resolver()},
            challenge_mode=ChallengeMode.AUTO,
            retain_profile=False,
        )
        try:
            result = retriever.for_provider("publicish").get(url)
            assert result.http_status == 206
            assert result.content_type == "application/json"
            assert result.raw_html == payload
            assert navigations == [url, url]
        finally:
            retriever.close()
            chromium.close()
