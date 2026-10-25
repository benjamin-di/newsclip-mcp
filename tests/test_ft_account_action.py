"""Retained FT reset notice must stop reads and unattended credential renewal."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from newsclip.acquisition import MintFailureCategory
from newsclip.archive import ArchiveStore
from newsclip.errors import OperatorActionRequiredError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.incidents import IncidentStore
from newsclip.live_diagnostics import (
    DiagnosticFacts,
    LiveDiagnosis,
    classify_live_failure,
)
from newsclip.models import RawFetch, SessionStatus
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.provider_check import ProviderCheckFailure
from newsclip.provider_guard import GuardAction, ProviderGuard, ProviderGuardStore
from newsclip.providers import ProviderRegistry
from newsclip.providers.ft import FTProvider
from newsclip.service import NewsclipService
from newsclip.sessions import SessionStore
from newsclip.timing import OperationFinishedEvent, TimingRecorder, read_timing_file

NOW = datetime(2026, 9, 6, tzinfo=UTC)
ARTICLE_URL = "https://www.ft.com/content/11111111-1111-4111-8111-111111111111"
FIXTURES = Path(__file__).parent / "fixtures/ft"


class Http:
    fail = False

    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        search = "/search?" in url
        reset = self.fail and not search
        fixture = (
            "search_results.html"
            if search
            else "account_security_reset.html"
            if reset
            else "full.html"
        )
        return RawFetch(
            requested_url=url,
            final_url="https://www.ft.com/barrier/concurrency" if reset else url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=True,
            raw_html=(FIXTURES / fixture).read_bytes(),
        )


def setup(tmp_path):
    provider = FTProvider(verification_url=ARTICLE_URL)
    provider.check = provider.check.model_copy(update={"canonical_url": ARTICLE_URL})
    http = Http()
    sessions = SessionStore(
        tmp_path / "sessions",
        recipes={"ft": provider.login_recipe},
        # Any actual acquisition dispatch is a test failure.
        adapters={"ft": object()},
        profile_access=object(),
        http=http,
        clock=lambda: NOW,
    )
    artifact = sessions.import_cookies(
        "ft", [{"name": "FTSession_fixture", "value": "inert", "domain": ".ft.com"}]
    )
    identity = BuildIdentity(
        revision="a" * 40,
        dirty=False,
        source_fingerprint="a" * 64,
        source=BuildIdentitySource.ENVIRONMENT,
    )
    incidents = IncidentStore(
        tmp_path / "incidents", build_identity=identity, utc_now=lambda: NOW
    )
    registry = ProviderRegistry((provider,))
    service = NewsclipService(
        registry,
        http,
        TrafilaturaExtractor(),
        sessions=sessions,
        archive=ArchiveStore(tmp_path / "archive"),
        incidents=incidents,
        timing=TimingRecorder(tmp_path / "timing.jsonl"),
        network_sleep=lambda _: None,
    )
    guard = ProviderGuard(
        registry=registry,
        store=ProviderGuardStore(
            tmp_path / "guard", build_identity=identity, utc_now=lambda: NOW
        ),
    )
    http.fail = True
    http.calls.clear()
    return service, sessions, http, incidents, guard, artifact


@pytest.mark.parametrize("operation", ["get", "save", "login", "session_checkpoint"])
def test_ft_account_reset_retains_evidence_and_blocks_next_login(tmp_path, operation):
    service, sessions, http, incidents, _, artifact = setup(tmp_path)
    argument = "ft" if operation in {"login", "session_checkpoint"} else ARTICLE_URL
    with pytest.raises(OperatorActionRequiredError) as caught:
        getattr(service, operation)(argument)
    assert caught.value.reason_code == "account_alert"
    assert caught.value.incident_id is not None
    assert len(http.calls) == 1  # No redundant session probe or login dispatch.
    assert sessions.status("ft").status is SessionStatus.OPERATOR_ACTION
    assert sessions.status("ft").failure_reason_code == "account_alert"
    capsule = list(incidents.iter_capsules())[0]
    assert capsule.incident_id == caught.value.incident_id
    with pytest.raises(OperatorActionRequiredError):
        sessions.explicit_login("ft", allow_credential_mint=True)
    assert len(http.calls) == 1
    # The authority is retained for evidence, with its use disabled.
    stored = sessions._load("ft", "default")
    assert stored.artifact.generation_id == artifact.generation_id
    if operation != "session_checkpoint":
        events = [
            record.event
            for path in (tmp_path / "timing.jsonl").rglob("*.jsonl")
            for record in read_timing_file(path).records
            if isinstance(record.event, OperationFinishedEvent)
        ]
        assert len(events) == 1
        assert events[0].failure_category is MintFailureCategory.ACCOUNT_ALERT
        assert (
            classify_live_failure(
                DiagnosticFacts(failure_categories=(events[0].failure_category,))
            ).diagnosis
            is LiveDiagnosis.ACCOUNT_ACTION
        )


def test_ft_guard_classifies_reset_as_operator_action_with_incident(tmp_path):
    service, sessions, http, incidents, guard, _ = setup(tmp_path)
    result = guard.run("ft", lambda: service.provider_check("ft"))
    assert result.action is GuardAction.OPERATOR_ACTION
    assert result.check.failure is ProviderCheckFailure.OPERATOR_ACTION
    assert result.incident_id == list(incidents.iter_capsules())[0].incident_id
    assert len(http.calls) == 2  # One search, one target; no verification probe.
    assert sessions.status("ft").status is SessionStatus.OPERATOR_ACTION
    guard.run("ft", lambda: pytest.fail("held check dispatched"))
    assert len(http.calls) == 2


def test_account_alert_about_old_generation_preserves_current_authority(tmp_path):
    _, sessions, _, _, _, artifact = setup(tmp_path)
    sessions.mark_account_alert("ft", generation_id=uuid4())
    assert sessions.get_valid_session("ft").generation_id == artifact.generation_id
    assert sessions.status("ft").status is SessionStatus.VERIFIED
