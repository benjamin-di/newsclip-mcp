#!/usr/bin/env python3
# Gateway copy: VENDORED from newsclip/scripts/synthetic_route_check.py, verbatim.
"""Outer watchdog: exercise the public MCP route from an external vantage.

Guardian was completely dead on the public route for roughly four days
while every internal monitor reported it healthy. No provider mechanic
could catch that class: monitoring ran in the token-holding keeper and
serving ran in a container that deliberately holds no credentials, so the
fault was *where the check ran from* (ARCHITECTURE, "Public-route watchdog").

This runs off the serving host and calls the authenticated public MCP route
through the gateway exactly as a client does:

1. the route answers at all; and
2. no source reports a **local or configuration-class fault** — a missing
   API key, unreadable local state, or an operator-action condition, which
   is precisely Guardian's class.

With persistent --state configured, it also rotates one provider-scoped
search/get sample every 15 minutes. The product must return an assessed FULL
article. Streaks count checks without FULL proof, including skipped checks;
observation distinguishes failed reads from unverified articles. Healthy search
does not clear a streak. A skipped check or a failed read receives one
follow-up when search is healthy, using the next eligible slot and alternating
with normal rotation. The next slot is reserved before dispatch; interruption
cannot replay it.

One article is not the provider. The sample searches up to five results and
reads the first not among the provider's last five failed samples; the
journal keeps only a 12-hex SHA-256 prefix of each URL, never the URL. A
streak of `content_not_full` reads that all hit one identical URL is
`article_sample_stuck`: reported, never paged (a single unentitled article
that stays a publisher's top hit for hours once paged a provider DOWN that
served every other article). `not_entitled` (session verified, article
outside the subscription) is a sample problem: it neither extends nor clears
a streak and steers the next sample elsewhere. A sample search that returns
nothing for --threshold consecutive checks is reported as `search_empty`
without paging.

A source in a legible contained or held state does **not** fail the check.
Those are handled conditions the deployment is designed to sit in; the
keeper deliberately does not page for them, and a watchdog that turned
every defense cooldown into an external alert would rebuild the alert
fatigue that made Guardian's detection accidental in the first place.
Persistence is the escape hatch: a source that stays not-ok across
consecutive runs pages regardless of class, because a handled state that
never resolves has stopped being handled.

Transport faults get the same skepticism at a smaller scale: a 5xx or an
unreachable route is indistinguishable from a seconds-long gateway blip
on a single sample (2026-08-05: an 8-second health-gate window paged as
`route_http_503`), so it earns one bounded retry before paging. Auth,
redirect and payload faults never wait — time does not fix a credential.

The probe never invokes login or repair tools. An ordinary get may request
bounded background recovery through the product's existing keeper handoff.
That pending state uses persistence instead of immediately paging.

Deliberately stdlib-only: it runs on a different host from the
deployment, where newsclip itself is not installed.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

#: Per-source reasons that mean the serving deployment itself is broken:
#: a credential or key it cannot resolve, an operator-action condition, or
#: local state it cannot read. Guardian's outage was the first of these.
FAULT_REASONS = frozenset(
    {
        "session_required",
        "operator_action",
        "persistence",
    }
)

#: Consecutive runs a source may report not-ok before it pages regardless
#: of class. Sized against the run interval by the scheduler, not here.
DEFAULT_PERSISTENCE_THRESHOLD = 3

DEFAULT_QUERY = "markets"
DEFAULT_TIMEOUT_SECONDS = 120.0

#: Seconds before the single transport-fault retry. Comfortably longer than
#: the ~10s gateway health-gate window that produced the 2026-08-05 false
#: page, and far inside the 15-minute run cadence even with two
#: full-timeout attempts.
ROUTE_RETRY_DELAY_SECONDS = 30.0
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_PROTOCOL_VERSION = "2025-03-26"


class CheckError(RuntimeError):
    """The route could not be exercised at all."""

    def __init__(self, reason: str, *, observation: str = "unverified") -> None:
        super().__init__(reason)
        self.observation = observation


@dataclass(frozen=True)
class SourceOutcome:
    provider: str
    state: str
    reason: str | None
    result_count: int
    contained: bool

    @property
    def ok(self) -> bool:
        """Whether this source is serving normally *right now*.

        Containment counts as not-ok here even though the search leg
        answered: retrieval is refused, so selecting a result would fail.
        It never fails a single run — only the persistence rule reads this
        — but a provider contained for days has stopped being a handled
        condition and has to reach someone.
        """

        return self.state == "ok" and not self.contained

    @property
    def is_local_fault(self) -> bool:
        """A fault in the deployment rather than at the provider's edge."""

        return self.reason in FAULT_REASONS

    def public_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "state": self.state,
            "reason": self.reason,
            "result_count": self.result_count,
            "contained": self.contained,
        }


@dataclass
class CheckResult:
    ok: bool
    reason: str
    sources: list[SourceOutcome] = field(default_factory=list)
    failing: list[str] = field(default_factory=list)
    #: Which probe attempt produced this verdict: 2 means a transport fault
    #: was absorbed (or outlived) by the single retry.
    attempt: int = 1
    article: dict[str, Any] | None = None
    #: Non-paging conditions worth reading, as {condition: [provider, ...]}:
    #: `article_sample_stuck` and `search_empty`. Never changes `ok`.
    notes: dict[str, list[str]] = field(default_factory=dict)

    def public_dict(self) -> dict[str, Any]:
        payload = {
            "ok": self.ok,
            "reason": self.reason,
            "failing": sorted(self.failing),
            "sources": [source.public_dict() for source in self.sources],
            "attempt": self.attempt,
        }
        if self.article is not None:
            payload["article"] = self.article
        if self.notes:
            payload["notes"] = {key: sorted(value) for key, value in self.notes.items()}
        payload["summary"] = _summary(self)
        return payload


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow a redirect while carrying the bearer token.

    urllib preserves `Authorization` across hosts, so a gateway that
    answers with a login redirect would deliver the public token to
    whatever host it names — and the follow-up arrives as a GET with the
    body dropped, surfacing as an unparsable response rather than as the
    auth fault it is. Refusing turns it into an honest `route_http_3xx`.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post(
    url: str,
    token: str,
    payload: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(  # noqa: S310 - scheme validated in main
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        # The status is the diagnosis here: 401/403 is gateway auth or a
        # rotated token, 502/504 is the tunnel or the container.
        raise CheckError(f"route_http_{error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise CheckError("route_unreachable") from error
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CheckError("route_response_too_large")
    return _decode(raw)


def _decode(raw: bytes) -> dict[str, Any]:
    """Accept a plain JSON body or one SSE frame carrying it."""

    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("{"):
        payload = _loads(text)
    else:
        data_lines = [
            line[len("data:") :].strip()
            for line in text.splitlines()
            if line.startswith("data:")
        ]
        if not data_lines:
            raise CheckError("route_response_unparsable")
        payload = _loads("".join(data_lines))
    if not isinstance(payload, dict):
        raise CheckError("route_response_unparsable")
    return payload


def _loads(text: str, *, reason: str = "route_response_unparsable") -> Any:
    try:
        return json.loads(text)
    except ValueError as error:
        raise CheckError(reason) from error


def _tool_result_envelope(
    result: dict[str, Any],
    *,
    malformed_reason: str,
) -> dict[str, Any]:
    """Decode one FastMCP tool result without trusting arbitrary error text.

    Successful tool responses normally expose their JSON envelope as text (and
    may also expose ``structuredContent``). Native FastMCP failures omit
    ``structuredContent`` and carry that same JSON as their bare text. Anything
    else fails closed; callers project the small public fields they
    understand, so human messages never become logs.
    """

    envelope = result.get("structuredContent")
    if envelope is None:
        content = result.get("content")
        if (
            not isinstance(content, list)
            or not content
            or not isinstance(content[0], dict)
        ):
            raise CheckError(malformed_reason)
        text = content[0].get("text")
        if not isinstance(text, str):
            raise CheckError(malformed_reason)
        envelope = _loads(text, reason=malformed_reason)
    if not isinstance(envelope, dict):
        raise CheckError(malformed_reason)
    if result.get("isError") is True and envelope.get("ok") is not False:
        raise CheckError(malformed_reason)
    return envelope


def run_check(
    url: str,
    token: str,
    *,
    query: str = DEFAULT_QUERY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    post=_post,  # noqa: ANN001 - seam for offline tests
) -> CheckResult:
    """Exercise the real serving path once and classify what came back."""

    post(
        url,
        token,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "newsclip-synthetic", "version": "1"},
            },
        },
        timeout=timeout,
    )
    answered = post(
        url,
        token,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"query": query}},
        },
        timeout=timeout,
    )

    result = answered.get("result")
    if not isinstance(result, dict):
        raise CheckError("route_response_unparsable")
    if result.get("isError"):
        # The route answered and the product refused: a real serving fault,
        # not a transport one. Its own envelope names the category, and
        # carrying that through is the difference between an alert that
        # says "something is wrong" and one that says "operator action".
        return CheckResult(ok=False, reason=_rejection_reason(result))

    sources = _sources(result)
    if not sources:
        raise CheckError("route_reported_no_sources")
    faults = [source.provider for source in sources if source.is_local_fault]
    if faults:
        return CheckResult(
            ok=False,
            reason="local_fault",
            sources=sources,
            failing=faults,
        )
    return CheckResult(ok=True, reason="ok", sources=sources)


def _transient_route_fault(reason: str) -> bool:
    """Whether waiting seconds could plausibly fix this fault.

    5xx and unreachable are transport-shaped: a health-gate window, a
    tunnel re-dial, a restart. 3xx/4xx are credential or deploy faults and
    a payload fault means the route answered — waiting fixes none of those.
    """

    return reason == "route_unreachable" or reason.startswith("route_http_5")


def run_check_with_retry(
    url: str,
    token: str,
    *,
    query: str = DEFAULT_QUERY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    post=_post,  # noqa: ANN001 - seam for offline tests
    sleep=time.sleep,  # noqa: ANN001 - seam for offline tests
    delay: float = ROUTE_RETRY_DELAY_SECONDS,
) -> CheckResult:
    """`run_check`, but a transient transport fault gets one second look.

    A blip shorter than `delay` becomes a green run that still records
    `attempt=2` in the ping body, so the event stays visible without
    paging. A fault that outlives the retry pages one `delay` later than
    it used to — nothing against a 15-minute dead-man cadence.
    """

    try:
        return run_check(url, token, query=query, timeout=timeout, post=post)
    except CheckError as error:
        if not _transient_route_fault(str(error)):
            raise
        sleep(delay)
        try:
            result = run_check(url, token, query=query, timeout=timeout, post=post)
        except CheckError as retried:
            retried.attempt = 2  # read by main's alert path
            raise
        result.attempt = 2
        return result


def _rejection_reason(result: dict[str, Any]) -> str:
    """Name the refusal from the product's own closed error envelope."""

    try:
        envelope = _tool_result_envelope(
            result,
            malformed_reason="route_response_unparsable",
        )
    except CheckError:
        return "search_rejected"
    category = envelope.get("category")
    if isinstance(category, str) and category.isidentifier():
        return f"search_rejected_{category}"
    return "search_rejected"


def _sources(result: dict[str, Any]) -> list[SourceOutcome]:
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise CheckError("route_response_unparsable")
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        raise CheckError("route_response_unparsable")
    envelope = _loads(first["text"])
    if not isinstance(envelope, dict):
        raise CheckError("route_response_unparsable")
    payload = envelope.get("result")
    if not isinstance(payload, dict):
        raise CheckError("route_response_unparsable")
    reports = payload.get("sources")
    if not isinstance(reports, list):
        raise CheckError("route_response_unparsable")
    outcomes: list[SourceOutcome] = []
    for report in reports:
        if not isinstance(report, dict):
            raise CheckError("route_response_unparsable")
        outcomes.append(
            SourceOutcome(
                provider=str(report.get("provider", "")),
                state=str(report.get("state", "")),
                reason=(
                    str(report["reason"]) if report.get("reason") is not None else None
                ),
                result_count=int(report.get("result_count", 0) or 0),
                contained=report.get("retrieval_contained_until") is not None,
            )
        )
    return outcomes


def _load_streaks(path: Path | None) -> dict[str, int]:
    if path is None or not path.exists():
        return {}
    try:
        stored = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(stored, dict):
        return {}
    return {
        str(key): int(value)
        for key, value in stored.items()
        if isinstance(value, int) and value >= 0
    }


def _store_streaks(path: Path | None, streaks: dict[str, int]) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic: a torn write reads back as no memory at all, which would
        # silently reset persistence for every source.
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(json.dumps(streaks, sort_keys=True))
        os.replace(temporary, path)
    except OSError:
        # Losing the streak costs one cycle of persistence memory; failing
        # the check for it would page for a full disk on the watchdog host.
        return


def apply_persistence(
    result: CheckResult,
    *,
    previous: dict[str, int],
    threshold: int,
) -> tuple[CheckResult, dict[str, int], list[str]]:
    """Fold consecutive not-ok runs into the verdict.

    A contained or degraded source is a handled condition and does not
    fail a single run. One that has been not-ok for `threshold`
    consecutive runs has stopped being handled, and pages whatever its
    class — containment included.
    """

    streaks: dict[str, int] = {}
    for source in result.sources:
        streaks[source.provider] = (
            0 if source.ok else previous.get(source.provider, 0) + 1
        )
    persistent = sorted(
        provider for provider, streak in streaks.items() if streak >= threshold
    )
    if result.ok and persistent:
        return (
            CheckResult(
                ok=False,
                reason="persistently_degraded",
                sources=result.sources,
                failing=persistent,
            ),
            streaks,
            persistent,
        )
    return result, streaks, persistent


def _ping(base_url: str | None, result: CheckResult, *, timeout: float) -> None:
    """Report to the dead-man switch, carrying the per-source JSON.

    The failing ping carries the diagnosis so the alert names the provider
    and the reason instead of only saying that something is wrong.
    """

    if not base_url:
        return
    url = base_url.rstrip("/") if result.ok else f"{base_url.rstrip('/')}/fail"
    body = (
        _summary(result) + "\n\n" + json.dumps(result.public_dict(), sort_keys=True)
    ).encode()
    request = urllib.request.Request(  # noqa: S310 - operator-supplied https URL
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310
            return
    except (urllib.error.URLError, TimeoutError, OSError):
        # A missed ping is what the dead-man switch is for. Never let the
        # reporting channel decide the check's own exit code.
        return


_ARTICLE_PROVIDERS = (
    "ap",
    "axios",
    "bloomberg",
    "cnbc",
    "economist",
    "ft",
    "guardian",
    "nyt",
    "reuters",
    "wsj",
)
_ARTICLE_INTERVAL = 15 * 60
_SKIPPED_REASONS = frozenset({"article_source_unavailable", "article_search_empty"})
#: Results considered per sample search; enough to step past one bad article.
_SAMPLE_SEARCH_LIMIT = 5
#: Failures the sampled article itself can cause. Only a streak made entirely
#: of these, on one URL, is `article_sample_stuck`; defense, timeouts and
#: malformed replies are provider- or route-wide and keep their streak.
_URL_SPECIFIC_REASONS = frozenset({"content_not_full"})
#: Product-verified sample problems (session verified, article outside the
#: subscription): never provider failure, never streak progress.
_SAMPLE_REASONS = frozenset({"not_entitled"})
#: Reviewed public Axios article read when its rolling feed matched nothing.
#: A known-good baseline that fails is provider evidence, never "stuck".
_AXIOS_BASELINE_URL = (
    "https://www.axios.com/2026/09/06/chris-wright-gas-prices-labor-day"
)
#: Sample queries for providers whose search is headline-token matching over
#: a short recent sitemap window rather than full-text search. Any token
#: matches, so every added word only widens recall; the high-frequency
#: headline words keep the pool non-empty on quiet news days.
_SAMPLE_QUERIES = {
    "reuters": "world business markets",
    "ap": "police court government state city president trump says new us",
    "axios": "trump congress energy prices city government ai house says new",
}
_ARTICLE_CATEGORIES = frozenset(
    {
        "usage",
        "operator_action",
        "session_required",
        "content_not_full",
        "not_entitled",
        "provider_defense",
        "timeout",
        "dns",
        "transport",
        "persistence",
    }
)


def _tool_envelope(answer: dict[str, Any]) -> dict[str, Any]:
    result = answer.get("result")
    if not isinstance(result, dict):
        raise CheckError("article_response_unparsable")
    return _tool_result_envelope(
        result,
        malformed_reason="article_response_unparsable",
    )


def _url_hash(url: str) -> str:
    """A short, stable URL identity for the journal; never the URL itself."""

    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def _is_url_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 12
        and all(c in "0123456789abcdef" for c in value)
    )


def _avoided(value: dict[str, Any]) -> list[str]:
    """URL hashes of a provider's recent failed samples, oldest first.

    Reads the single `avoid_url_hash` of journals before 2026-10-15 as a one-entry list.
    """

    if "avoid_url_hashes" in value:
        return list(value["avoid_url_hashes"])
    return [value["avoid_url_hash"]] if "avoid_url_hash" in value else []


def _article_sample(  # noqa: ANN202, PLR0913
    url,  # noqa: ANN001
    token,  # noqa: ANN001
    provider,  # noqa: ANN001
    query,  # noqa: ANN001
    timeout,  # noqa: ANN001
    post,  # noqa: ANN001
    *,
    avoid: tuple[str, ...] = (),
    info: dict[str, Any] | None = None,
):
    """Search one provider and read one of its results.

    `avoid` holds the URL hashes of this provider's recent failed samples,
    oldest first. The first result outside it is read; when every result
    failed recently, the one whose failure is oldest.
    `info` receives `search_empty` (whether search matched nothing) and
    `url_hash` (the article requested), even when the read then raises.
    """

    info = {} if info is None else info

    def call(name, arguments):  # noqa: ANN001, ANN202
        try:
            return _tool_envelope(
                post(
                    url,
                    token,
                    {
                        "jsonrpc": "2.0",
                        "id": 3 if name == "search" else 4,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments},
                    },
                    timeout=timeout,
                ),
            )
        except CheckError as error:
            error.observation = "failed" if name == "get" else "unverified"
            raise

    query = _SAMPLE_QUERIES.get(provider, query)
    searched = call(
        "search",
        {"query": query, "providers": [provider], "limit": _SAMPLE_SEARCH_LIMIT},
    )
    if searched.get("ok") is not True:
        return {**_article_rejection(searched), "observation": "unverified"}
    payload = searched.get("result")
    if not isinstance(payload, dict):
        raise CheckError("article_response_unparsable")
    sources = payload.get("sources", [])
    if (
        not isinstance(sources, list)
        or len(sources) != 1
        or not isinstance(sources[0], dict)
    ):
        raise CheckError("article_response_unparsable")
    source = sources[0]
    if source.get("provider") != provider:
        raise CheckError("article_response_unparsable")
    if (
        source.get("state") != "ok"
        or source.get("retrieval_contained_until") is not None
    ):
        return {
            "ok": False,
            "reason": "article_source_unavailable",
            "observation": "unverified",
        }
    articles = payload.get("results")
    if not isinstance(articles, list) or len(articles) > _SAMPLE_SEARCH_LIMIT:
        raise CheckError("article_response_unparsable")
    info["search_empty"] = not articles
    if (
        not articles
        and provider == "axios"
        and isinstance(source.get("coverage_start"), str)
        and source["coverage_start"]
    ):
        # A healthy rolling feed need not match today's canary topic. Still
        # require independent FULL retrieval of the reviewed public baseline.
        articles = [{"provider": "axios", "url": _AXIOS_BASELINE_URL}]
    if not articles:
        return {
            "ok": False,
            "reason": "article_search_empty",
            "observation": "unverified",
        }
    candidates: list[str] = []
    for article in articles:
        if not isinstance(article, dict) or article.get("provider") != provider:
            raise CheckError("article_response_unparsable")
        candidate = article.get("url")
        if (
            not isinstance(candidate, str)
            or len(candidate) > 4096
            or urlsplit(candidate).scheme != "https"
        ):
            raise CheckError("article_response_unparsable")
        candidates.append(candidate)
    selected = next(
        (candidate for candidate in candidates if _url_hash(candidate) not in avoid),
        None,
    ) or min(candidates, key=lambda candidate: avoid.index(_url_hash(candidate)))
    info["url_hash"] = _url_hash(selected)
    fetched = call("get", {"url": selected})
    if fetched.get("ok") is not True:
        return {**_article_rejection(fetched), "observation": "failed"}
    article = fetched.get("result")
    # The product's get contract returns only assessed FULL articles. Do not
    # duplicate its provider extraction/entitlement policy in this stdlib client.
    if not isinstance(article, dict) or article.get("provider") != provider:
        raise CheckError("article_response_unparsable", observation="failed")
    words, body = article.get("word_count"), article.get("body_markdown")
    if (
        type(words) is not int
        or words <= 0
        or not isinstance(body, str)
        or not body.strip()
    ):
        raise CheckError("article_response_unparsable", observation="failed")
    return {"ok": True, "reason": "full", "word_count": words, "observation": "full"}


def _observation(outcome: dict[str, Any]) -> str:
    """Read old journals without inventing whether an article GET ran."""
    if "observation" in outcome:
        return outcome["observation"]
    if outcome["ok"]:
        return "full"
    if outcome["reason"] in _SKIPPED_REASONS or outcome["reason"] == "interrupted":
        return "unverified"
    if outcome["reason"] == "content_not_full":
        return "failed"
    return "unknown"


def _summary(result: CheckResult) -> str:
    """Deterministic operator text from closed verdicts, never provider prose."""
    degraded = (
        any(not source.ok for source in result.sources)
        or (result.article is not None and result.article.get("ok") is False)
        or bool(result.notes)
    )
    lines = [
        "Newsclip degraded."
        if not result.ok
        else "Newsclip: degradation observed; alert threshold not reached."
        if degraded
        else "Newsclip check passed."
    ]
    reasons = {
        "provider_defense": "publisher challenge or cooldown",
        "provider_error": "publisher refused or failed the request",
        "contract": "search response no longer matches the provider contract",
        "session_required": "verified subscription session unavailable",
        "operator_action": "account or configuration action required",
        "persistence": "local state unavailable",
        "timeout": "request timed out",
        "dns": "provider name resolution failed",
        "transport": "provider connection failed",
        "rate_limited": "publisher rate limit",
    }
    for source in result.sources:
        if not source.ok:
            name = (
                source.provider.upper()
                if source.provider in _ARTICLE_PROVIDERS
                else "UNKNOWN"
            )
            cause = reasons.get(source.reason, "source unavailable or contained")
            lines.append(f"{name}: search/retrieval access degraded; {cause}.")
    article = result.article or {}
    stuck = article.get("stuck", {})
    unresolved = article.get("unresolved", {})
    if (
        not unresolved
        and article.get("provider")
        and not article.get("ok")
        and article["provider"] not in stuck
    ):
        unresolved = {article["provider"]: article}
    for provider, outcome in sorted(unresolved.items()):
        name = provider.upper() if provider in _ARTICLE_PROVIDERS else "UNKNOWN"
        observation = _observation(outcome)
        if outcome["reason"] in _SAMPLE_REASONS:
            detail = (
                "sampled article is outside the subscription (session "
                "verified); a different article is sampled next"
            )
        elif observation == "unverified":
            detail = "article unverified"
            if outcome["reason"] in _SKIPPED_REASONS:
                detail += (
                    "; search unavailable, contained or empty. "
                    "No article request was sent"
                )
            else:
                detail += "; verification did not complete"
        else:
            detail = (
                "article read failed"
                if observation == "failed"
                else "article verification failed; request stage unknown"
            )
            if outcome["reason"] == "content_not_full":
                detail += "; complete content was not verified"
        stamp = outcome.get("last_full_at")
        last_full = (
            datetime.fromtimestamp(stamp, UTC).isoformat()
            if stamp is not None
            else "unknown"
        )
        lines.append(
            f"{name}: {detail}; last FULL: {last_full}. "
            f"{outcome['streak']} checks without FULL proof."
        )
        if outcome.get("recovery_id"):
            lines.append(
                f"Keeper recovery requested ({outcome['recovery_id']}); "
                "its current schedule is available in ops health."
            )
    for provider, outcome in sorted(stuck.items()):
        name = provider.upper() if provider in _ARTICLE_PROVIDERS else "UNKNOWN"
        lines.append(
            f"{name}: article_sample_stuck; the same sampled article failed "
            f"{outcome['streak']} consecutive checks. Not paging: one article "
            "is not the provider; a different article is sampled next."
        )
    for provider, count in sorted(article.get("search_empty", {}).items()):
        name = provider.upper() if provider in _ARTICLE_PROVIDERS else "UNKNOWN"
        lines.append(
            f"{name}: search_empty; the sample search matched nothing in "
            f"{count} consecutive checks. Not paging; discovery is not being "
            "exercised, so review the sample query."
        )
    if result.reason == "article_state_unavailable":
        lines.append(
            "Action: repair the watchdog article journal; preserve the failed "
            "state for diagnosis. No article request was sent."
        )
    elif not result.sources and not result.ok:
        lines.append(
            "Public route check failed. Inspect gateway authentication, "
            "tunnel and serving health."
        )
    elif not result.ok or unresolved:
        if any(source.is_local_fault for source in result.sources) or any(
            outcome["reason"] in FAULT_REASONS for outcome in unresolved.values()
        ):
            lines.append(
                "Action: inspect Newsclip ops health and repair the reported "
                "account/configuration/local fault."
            )
        else:
            lines.append(
                "Next: the scheduled probe verifies recovery; persistent failures "
                "need ops health and retained incident review. "
                "Preserve holds and retry limits."
            )
    if article.get("next_check_at") is not None:
        due = datetime.fromtimestamp(article["next_check_at"], UTC).isoformat()
        lines.append(
            f"Next article slot eligible: {due}; one follow-up after search "
            "recovery shares the existing rotation."
        )
    return "\n".join(lines)


def _article_rejection(envelope: dict[str, Any]) -> dict[str, Any]:
    category = envelope.get("category")
    outcome = {
        "ok": False,
        "reason": category
        if isinstance(category, str) and category in _ARTICLE_CATEGORIES
        else "article_rejected",
    }
    if category == "session_required" and envelope.get("action") == "renewal_pending":
        outcome["reason"] = "renewal_pending"
    # The product publishes an article outside the subscription (session
    # verified) as content_not_full with the closed reason not_entitled.
    if category == "content_not_full" and envelope.get("reason") == "not_entitled":
        outcome["reason"] = "not_entitled"
    for key in ("diagnostic_id", "incident_id", "recovery_id"):
        value = envelope.get(key)
        if (
            isinstance(value, str)
            and 0 < len(value) <= 128
            and all(c in "abcdefghijklmnopqrstuvwxyz0123456789._-" for c in value)
        ):
            outcome[key] = value
    return outcome


def _fold_sample(  # noqa: PLR0913
    outcome: dict[str, Any],
    *,
    prior: dict[str, Any],
    info: dict[str, Any],
    streak: int,
    stamp: float,
    last_full_at: float | None,
    follow_up: bool,
) -> dict[str, Any]:
    """Fold one sample into the journal entry that replaces `prior`.

    `streak` is the reserved value (prior + 1). A `not_entitled` sample is
    neutral: it keeps the prior streak and its URL identity instead of
    extending or clearing it. `streak_url_hash` survives only while every
    check in the streak failed with a URL-specific reason on that one URL;
    that is the `article_sample_stuck` evidence.
    """

    sampled = info.get("url_hash")
    neutral = not outcome["ok"] and outcome["reason"] in _SAMPLE_REASONS
    if outcome["ok"]:
        outcome["streak"] = 0
    elif neutral:
        outcome["streak"] = prior.get("streak", 0)
    else:
        outcome["streak"] = streak
    outcome["checked_at"] = stamp
    outcome["observation"] = _observation(outcome)
    outcome["last_full_at"] = stamp if outcome["ok"] else last_full_at
    # One follow-up per missed regular sample, for skipped checks and for
    # failed reads alike: it confirms or clears a failure one slot later.
    outcome["follow_up_pending"] = not follow_up and (
        outcome["reason"] in _SKIPPED_REASONS or outcome["observation"] == "failed"
    )
    if sampled is not None:
        outcome["url_hash"] = sampled
    # Every recently failed URL is stepped past, not only the last one: two
    # unreadable results on top of a search (Bloomberg's `markets` podcasts,
    # 2026-10-15) otherwise alternate into a paging streak of distinct URLs.
    avoid = _avoided(prior)
    if sampled is not None and outcome["observation"] == "failed":
        avoid = [*(h for h in avoid if h != sampled), sampled]
    if avoid:
        outcome["avoid_url_hashes"] = avoid[-_SAMPLE_SEARCH_LIMIT:]
    if neutral:
        if outcome["streak"] and "streak_url_hash" in prior:
            outcome["streak_url_hash"] = prior["streak_url_hash"]
    elif (
        not outcome["ok"]
        and sampled is not None
        and sampled != _url_hash(_AXIOS_BASELINE_URL)
        and outcome["reason"] in _URL_SPECIFIC_REASONS
        and (streak == 1 or prior.get("streak_url_hash") == sampled)
    ):
        outcome["streak_url_hash"] = sampled
    empties = prior.get("empty_searches", 0)
    if info.get("search_empty") is True:
        empties = min(empties + 1, 1000)
    elif info.get("search_empty") is False:
        empties = 0
    if empties:
        outcome["empty_searches"] = empties
    return outcome


def _sample_stuck(value: dict[str, Any], threshold: int) -> bool:
    """A threshold-length streak whose every failure was one identical URL."""

    return (
        value["streak"] >= threshold
        and "streak_url_hash" in value
        and value.get("reason") not in FAULT_REASONS
    )


def check_rotating_article(
    result: CheckResult,
    url: str,
    token: str,
    *,
    state: Path,
    query: str = DEFAULT_QUERY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    threshold: int = DEFAULT_PERSISTENCE_THRESHOLD,
    post=_post,
    now=time.time,
) -> CheckResult:  # noqa: ANN001 - offline clock/transport seams
    """One article per window, never a retry, with state reserved before I/O.

    A separate small journal counts checks without FULL proof, including
    skipped checks; observation says whether an article was actually requested.
    Only a sampled FULL result resets that provider's streak. A streak pages
    at `threshold` unless every failure in it was the same URL
    (`article_sample_stuck`, a non-paging note); account, configuration and
    local faults page at once. Holding the local lock across the bounded
    sample also serializes manual invocations.
    """
    path = state.with_name(state.name + ".articles")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.with_name(path.name + ".lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                result.article = {"status": "busy"}
                return result
            stored = {"cursor": 0, "next_at": 0, "outcomes": {}}
            if path.exists():
                with path.open("rb") as stream:
                    raw = stream.read(16385)
                if len(raw) > 16384:
                    raise ValueError("oversized article state")
                stored = json.loads(raw)
            if (
                not isinstance(stored, dict)
                or type(stored.get("cursor")) is not int
                or not 0 <= stored["cursor"] < len(_ARTICLE_PROVIDERS)
                or type(stored.get("next_at")) not in (int, float)
                or not 0 <= stored["next_at"] < 253402300800  # year 10000
                or not isinstance(stored.get("outcomes"), dict)
                or type(stored.get("last_was_follow_up", False)) is not bool
            ):
                raise ValueError("invalid article state")
            outcomes = stored["outcomes"]
            for key, value in outcomes.items():
                if (
                    key not in _ARTICLE_PROVIDERS
                    or not isinstance(value, dict)
                    or type(value.get("streak")) is not int
                    or value["streak"] < 0
                    or type(value.get("ok")) is not bool
                    or type(value.get("checked_at")) not in (int, float)
                    or not 0 <= value["checked_at"] < 253402300800
                    or not isinstance(value.get("reason"), str)
                    or len(value["reason"]) > 64
                    or not value["reason"].isascii()
                    or not value["reason"].replace("_", "").isalnum()
                    or set(value)
                    - {
                        "ok",
                        "reason",
                        "streak",
                        "checked_at",
                        "word_count",
                        "diagnostic_id",
                        "incident_id",
                        "recovery_id",
                        "observation",
                        "last_full_at",
                        "follow_up_pending",
                        "url_hash",
                        "avoid_url_hash",
                        "avoid_url_hashes",
                        "streak_url_hash",
                        "empty_searches",
                    }
                ):
                    raise ValueError("invalid article outcome")
                for reference in ("url_hash", "avoid_url_hash", "streak_url_hash"):
                    if reference in value and not _is_url_hash(value[reference]):
                        raise ValueError("invalid article URL hash")
                if "avoid_url_hashes" in value and (
                    not isinstance(value["avoid_url_hashes"], list)
                    or not 0 < len(value["avoid_url_hashes"]) <= _SAMPLE_SEARCH_LIMIT
                    or not all(map(_is_url_hash, value["avoid_url_hashes"]))
                    or len(set(value["avoid_url_hashes"]))
                    != len(value["avoid_url_hashes"])
                ):
                    raise ValueError("invalid article URL hash")
                if "empty_searches" in value and (
                    type(value["empty_searches"]) is not int
                    or not 0 < value["empty_searches"] <= 1000
                ):
                    raise ValueError("invalid empty search count")
                if "observation" in value and (
                    value["observation"]
                    not in {"full", "failed", "unverified", "unknown"}
                    or (value["observation"] == "full") != value["ok"]
                ):
                    raise ValueError("invalid article observation")
                if type(value.get("follow_up_pending", False)) is not bool:
                    raise ValueError("invalid follow-up reservation")
                full_at = value.get("last_full_at")
                if full_at is not None and (
                    type(full_at) not in (int, float)
                    or not 0 <= full_at <= value["checked_at"]
                ):
                    raise ValueError("invalid article verification time")
                for reference in ("diagnostic_id", "incident_id", "recovery_id"):
                    if (
                        reference in value
                        and _article_rejection(value).get(reference) != value[reference]
                    ):
                        raise ValueError("invalid article reference")
                if "word_count" in value and (
                    type(value["word_count"]) is not int or value["word_count"] <= 0
                ):
                    raise ValueError("invalid article word count")

            def save() -> None:
                temporary = path.with_name(path.name + ".tmp")
                temporary.write_text(json.dumps(stored, sort_keys=True))
                os.replace(temporary, path)

            stamp = now()
            if stamp >= stored["next_at"]:
                regular = _ARTICLE_PROVIDERS[stored["cursor"]]
                sources = {source.provider: source for source in result.sources}
                # At most one follow-up per missed regular sample, and never
                # two extra slots consecutively. A follow-up preserves the
                # regular cursor so healthy providers cannot be skipped.
                ready = sorted(
                    (
                        key
                        for key, value in outcomes.items()
                        if value.get(
                            "follow_up_pending", value["reason"] in _SKIPPED_REASONS
                        )
                        and key in sources
                        and sources[key].ok
                    ),
                    key=lambda key: (outcomes[key]["checked_at"], key),
                )
                provider = (
                    ready[0]
                    if ready and not stored.get("last_was_follow_up", False)
                    else regular
                )
                follow_up = provider != regular
                prior = outcomes.get(provider, {})
                last_full_at = prior.get(
                    "last_full_at", prior.get("checked_at") if prior.get("ok") else None
                )
                streak = min(prior.get("streak", 0) + 1, 1000)
                if not follow_up:
                    stored["cursor"] = (stored["cursor"] + 1) % len(_ARTICLE_PROVIDERS)
                stored["last_was_follow_up"] = follow_up
                stored["next_at"] = stamp + _ARTICLE_INTERVAL
                # Sample memory survives an interrupted window: the URLs to
                # step past and the empty-search count are not re-derivable.
                memory = {
                    key: prior[key] for key in ("empty_searches",) if key in prior
                }
                if _avoided(prior):
                    memory["avoid_url_hashes"] = _avoided(prior)
                outcomes[provider] = {
                    "ok": False,
                    "reason": "interrupted",
                    "streak": streak,
                    "checked_at": stamp,
                    "observation": "unverified",
                    "last_full_at": last_full_at,
                    "follow_up_pending": False,
                    **memory,
                }
                save()  # A crash or timeout cannot replay this window.
                info: dict[str, Any] = {}
                try:
                    source = next(
                        (s for s in result.sources if s.provider == provider), None
                    )
                    if source is None or not source.ok:
                        outcome = {"ok": False, "reason": "article_source_unavailable"}
                    else:
                        outcome = _article_sample(
                            url,
                            token,
                            provider,
                            query,
                            timeout,
                            post,
                            avoid=tuple(_avoided(prior)),
                            info=info,
                        )
                except CheckError as error:
                    outcome = {
                        "ok": False,
                        "reason": str(error),
                        "observation": error.observation,
                    }
                outcome = _fold_sample(
                    outcome,
                    prior=prior,
                    info=info,
                    streak=streak,
                    stamp=stamp,
                    last_full_at=last_full_at,
                    follow_up=follow_up,
                )
                outcomes[provider] = outcome
                save()
                result.article = {"provider": provider, **outcome}
            else:
                result.article = {"status": "not_due"}
            result.article["next_check_at"] = stored["next_at"]
            stuck = sorted(
                key
                for key, value in outcomes.items()
                if _sample_stuck(value, threshold)
            )
            failing = sorted(
                key
                for key, value in outcomes.items()
                if value.get("reason") in FAULT_REASONS
                or (value["streak"] >= threshold and key not in stuck)
            )
            empty = sorted(
                key
                for key, value in outcomes.items()
                if value.get("empty_searches", 0) >= threshold
            )
            if stuck:
                result.notes["article_sample_stuck"] = stuck
                result.article["stuck"] = {key: outcomes[key] for key in stuck}
            if empty:
                result.notes["search_empty"] = empty
                result.article["search_empty"] = {
                    key: outcomes[key]["empty_searches"] for key in empty
                }
            if failing:
                result.ok = False
                if result.reason == "ok":
                    result.reason = (
                        "article_unverified"
                        if all(
                            _observation(outcomes[key]) == "unverified"
                            for key in failing
                        )
                        else "article_unavailable"
                    )
                result.failing = sorted(set(result.failing) | set(failing))
                result.article["unresolved"] = {key: outcomes[key] for key in failing}
    except (OSError, ValueError, TypeError):
        result.ok = False
        result.reason = "article_state_unavailable"
        result.article = {"status": "state_unavailable"}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get("NEWSCLIP_MCP_URL", ""),
        help="Public MCP endpoint through the gateway, e.g. https://host/mcp.",
    )
    parser.add_argument(
        "--query",
        default=DEFAULT_QUERY,
        help="Fixed query the synthetic client issues.",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=(
            Path(os.environ["NEWSCLIP_SYNTHETIC_STATE"])
            if os.environ.get("NEWSCLIP_SYNTHETIC_STATE")
            else None
        ),
        help="Where consecutive not-ok streaks are remembered between runs.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_PERSISTENCE_THRESHOLD,
        help="Consecutive not-ok runs after which any source pages.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-request timeout in seconds.",
    )
    arguments = parser.parse_args(argv)

    token = os.environ.get("NEWSCLIP_MCP_TOKEN", "")
    if (
        not arguments.url
        or not token
        # A scheme allowlist, not decoration: an unqualified or file:// URL
        # would otherwise raise out of urllib and read as a deployment
        # fault rather than as this host being misconfigured.
        or urlsplit(arguments.url).scheme not in {"http", "https"}
        or not urlsplit(arguments.url).netloc
    ):
        # Not a route failure: this host is misconfigured, and saying so is
        # more useful than a dead-man ping that blames the deployment.
        print(
            json.dumps({"ok": False, "reason": "watchdog_not_configured"}),
            file=sys.stderr,
        )
        return 2

    healthchecks = os.environ.get("NEWSCLIP_SYNTHETIC_HEALTHCHECK_URL")
    try:
        result = run_check_with_retry(
            arguments.url,
            token,
            query=arguments.query,
            timeout=arguments.timeout,
        )
    except CheckError as error:
        result = CheckResult(
            ok=False,
            reason=str(error),
            attempt=getattr(error, "attempt", 1),
        )
        _ping(healthchecks, result, timeout=arguments.timeout)
        print(json.dumps(_stamped(result), sort_keys=True))
        return 1

    previous = _load_streaks(arguments.state)
    result, streaks, _persistent = apply_persistence(
        result,
        previous=previous,
        threshold=arguments.threshold,
    )
    if result.sources:
        # A run that produced no per-source verdict has nothing to say about
        # any streak; writing its empty map would erase the memory that the
        # persistence rule depends on.
        _store_streaks(arguments.state, streaks)
    if arguments.state is not None and result.sources:
        result = check_rotating_article(
            result,
            arguments.url,
            token,
            state=arguments.state,
            query=arguments.query,
            timeout=arguments.timeout,
            threshold=arguments.threshold,
        )
    _ping(healthchecks, result, timeout=arguments.timeout)
    print(json.dumps(_stamped(result), sort_keys=True))
    return 0 if result.ok else 1


def _stamped(result: CheckResult) -> dict[str, Any]:
    return {**result.public_dict(), "checked_at": datetime.now(UTC).isoformat()}


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
