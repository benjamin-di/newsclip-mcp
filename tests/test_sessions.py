from __future__ import annotations

import json
import multiprocessing
import stat
import threading
import time
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from newsclip.acquisition import (
    AcquisitionEvidence,
    AcquisitionFailure,
    AcquisitionMode,
    CandidateVerificationMode,
    CredentialAction,
    FlowCandidate,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from newsclip.browser_runtime import LeaseManager
from newsclip.errors import (
    OperatorActionRequiredError,
    PersistenceError,
    ProviderTransportError,
    SessionRequiredError,
    UsageError,
)
from newsclip.http import portable_cookie_jar
from newsclip.models import (
    AccessState,
    LoginRequirement,
    MintOutcome,
    PortableCookie,
    ProviderReadiness,
    RawFetch,
    SessionArtifact,
    SessionStatus,
    SessionVerification,
)
from newsclip.results import PublicErrorReason
from newsclip.session_cookies import (
    SessionCookiesMissing,
    normalize_browser_cookie_export,
    normalize_cookie_import,
)
from newsclip.sessions import SessionStore
from newsclip.timing import (
    StepFinishedEvent,
    TimingOperation,
    TimingOutcome,
    TimingRecorder,
    TimingStep,
    TimingTransport,
    read_timing_file,
)

NOW = datetime(2026, 7, 17, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()


class FakeHttp:
    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        raise AssertionError("fixture recipe does not perform HTTP")


class FakeRecipe:
    provider = "ft"
    candidate_verification_mode = CandidateVerificationMode.HTTP_PROBE
    allowed_origins = frozenset({"https://accounts.ft.com", "https://www.ft.com"})
    allowed_cookie_domains = frozenset({"ft.com"})
    secret_ref = "fixture-secret-ref"

    def verify(self, http: FakeHttp, artifact: SessionArtifact) -> SessionVerification:
        verified = all(cookie.value != "reject" for cookie in artifact.cookies)
        return SessionVerification(
            verified=verified,
            access_state=AccessState.FULL if verified else AccessState.AUTH_REQUIRED,
            reason="verified_fixture" if verified else "rejected_fixture",
            verified_at=NOW,
        )


class InconclusiveRecipe(FakeRecipe):
    def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
        return SessionVerification(
            verified=False,
            access_state=AccessState.UNKNOWN,
            reason="provider_unavailable_fixture",
            verified_at=NOW,
        )


class BrowserPaidRecipe(FakeRecipe):
    candidate_verification_mode = CandidateVerificationMode.BROWSER_PAID_PROBE

    def __init__(self) -> None:
        self.verify_calls = 0
        self.verify_fetch_calls = 0

    def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
        self.verify_calls += 1
        return super().verify(http, artifact)

    def verify_fetch(self, fetch: RawFetch) -> SessionVerification:
        self.verify_fetch_calls += 1
        verified = b"full paid fixture" in fetch.raw_html
        return SessionVerification(
            verified=verified,
            access_state=AccessState.FULL if verified else AccessState.TEASER,
            reason="verified_fixture" if verified else "rejected_fixture",
            verified_at=fetch.retrieved_at,
        )


def _artifact(value: str = "COOKIE_VALUE_SENTINEL") -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="ft",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="FTSession_fixture",
                value=value,
                domain=".ft.com",
                path="/content",
                expires=FUTURE,
                secure=True,
                http_only=True,
                same_site="Lax",
            ),
        ),
    )


def _verification_fetch(*, full: bool = True) -> RawFetch:
    return RawFetch(
        requested_url="https://www.ft.com/content/fixture",
        final_url="https://www.ft.com/content/fixture",
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=(
            b"<article>full paid fixture</article>"
            if full
            else b"<article>short preview</article>"
        ),
    )


class FakeAdapter:
    def __init__(
        self,
        outcome: MintOutcome = MintOutcome.VERIFIED,
        *,
        artifact: SessionArtifact | None = None,
        profile: Path | None = None,
        rehydrate_artifact: SessionArtifact | None = None,
        refresh_failure: MintFailureEvidence | None = None,
        candidate_verification_mode: CandidateVerificationMode = (
            CandidateVerificationMode.HTTP_PROBE
        ),
        verification_fetch: RawFetch | None = None,
    ) -> None:
        self.provider = "ft"
        self.outcome = outcome
        self.artifact = artifact or _artifact()
        self.rehydrate_artifact = rehydrate_artifact
        self.refresh_failure = refresh_failure
        self.candidate_verification_mode = candidate_verification_mode
        self.verification_fetch = (
            verification_fetch
            if verification_fetch is not None
            else (
                _verification_fetch()
                if candidate_verification_mode
                is CandidateVerificationMode.BROWSER_PAID_PROBE
                else None
            )
        )
        self.profile = profile or Path("profiles/ft/default")
        self.calls = 0
        self.rehydrate_calls = 0

    def rehydrate_profile(self, browser, *, account_key: str, challenge_mode):
        self.rehydrate_calls += 1
        if self.rehydrate_artifact is not None:
            return FlowCandidate(
                artifact=self.rehydrate_artifact,
                candidate_verification_mode=self.candidate_verification_mode,
                evidence=AcquisitionEvidence(
                    mode=AcquisitionMode.PROFILE_REHYDRATE,
                ),
                verification_fetch=self.verification_fetch,
                refresh_failure=self.refresh_failure,
            )
        return None

    def mint_credentials(self, browser, *, account_key: str, challenge_mode):
        self.calls += 1
        if self.outcome is not MintOutcome.VERIFIED:
            category = {
                MintOutcome.CREDENTIAL_REJECTED: (
                    MintFailureCategory.CREDENTIAL_REJECTED
                ),
                MintOutcome.SECOND_FACTOR_REQUIRED: (
                    MintFailureCategory.SECOND_FACTOR_REQUIRED
                ),
                MintOutcome.ACCOUNT_ALERT: MintFailureCategory.ACCOUNT_ALERT,
                MintOutcome.CHALLENGE_BLOCKED: (MintFailureCategory.CHALLENGE_BLOCKED),
                MintOutcome.UNKNOWN_FLOW: MintFailureCategory.UNKNOWN,
                MintOutcome.INFRASTRUCTURE_ERROR: (MintFailureCategory.INFRASTRUCTURE),
            }[self.outcome]
            raise AcquisitionFailure(
                self.outcome,
                MintFailureEvidence(
                    stage=MintFailureStage.CREDENTIAL,
                    category=category,
                ),
            )
        return FlowCandidate(
            artifact=self.artifact,
            candidate_verification_mode=self.candidate_verification_mode,
            evidence=AcquisitionEvidence(
                mode=AcquisitionMode.CREDENTIAL_MINT,
                credential_action=CredentialAction.PASSWORD_SUBMIT,
            ),
            verification_fetch=self.verification_fetch,
        )


class FakeProfileAccess:
    def __init__(self, profile: Path) -> None:
        self.profile = profile

    def path(self, provider: str, account_key: str, *, profile_id=None) -> Path:
        return (
            self.profile
            if profile_id is None
            else self.profile.with_name(profile_id.hex)
        )

    def open(
        self,
        provider: str,
        account_key: str,
        *,
        require_virtual_display: bool,
        profile_id=None,
    ):
        return nullcontext(object())


def test_session_store_requires_profile_access_for_acquisition_adapters(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="require browser profiles"):
        SessionStore(
            tmp_path / "state",
            recipes={"ft": FakeRecipe()},
            adapters={"ft": FakeAdapter()},
            http=FakeHttp(),
        )


def test_profile_rehydration_does_not_require_credential_tools(
    tmp_path: Path,
) -> None:
    adapter = FakeAdapter(
        profile=tmp_path / "profiles/ft/default",
        rehydrate_artifact=_artifact("retained-profile-session"),
    )
    store = _store(
        tmp_path / "state",
        adapter=adapter,
        credential_readiness_probes={
            "ft": lambda: ProviderReadiness(
                provider="ft",
                missing=(LoginRequirement.OP_CLI,),
            )
        },
    )

    acquired = store.explicit_login("ft")

    assert acquired.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert adapter.calls == 0
    assert adapter.rehydrate_calls == 1


def test_credential_readiness_fails_after_profile_before_secret_dispatch(
    tmp_path: Path,
) -> None:
    adapter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = _store(
        tmp_path / "state",
        adapter=adapter,
        credential_readiness_probes={
            "ft": lambda: ProviderReadiness(
                provider="ft",
                missing=(LoginRequirement.OP_CLI,),
            )
        },
    )

    with pytest.raises(SessionRequiredError, match="credential_infrastructure"):
        store.explicit_login("ft")

    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 0
    assert store.status("ft").status is SessionStatus.REQUIRED


def test_dead_profile_requires_credential_tools_before_fallback_mint(
    tmp_path: Path,
) -> None:
    adapter = FakeAdapter(
        profile=tmp_path / "profiles/ft/default",
        rehydrate_artifact=_artifact("reject"),
    )
    store = _store(
        tmp_path / "state",
        adapter=adapter,
        credential_readiness_probes={
            "ft": lambda: ProviderReadiness(
                provider="ft",
                missing=(LoginRequirement.OP_SERVICE_TOKEN,),
            )
        },
    )

    with pytest.raises(SessionRequiredError, match="credential_infrastructure"):
        store.explicit_login("ft")

    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 0


def test_verified_reuse_does_not_require_minting_tools(tmp_path: Path) -> None:
    available = [True]

    def readiness() -> ProviderReadiness:
        return ProviderReadiness(
            provider="ft",
            missing=(() if available[0] else (LoginRequirement.OP_SERVICE_TOKEN,)),
        )

    adapter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = _store(
        tmp_path / "state",
        adapter=adapter,
        credential_readiness_probes={"ft": readiness},
    )
    first = store.explicit_login("ft")
    available[0] = False

    second = store.explicit_login("ft")

    assert first.artifact == second.artifact
    assert adapter.calls == 1


def _store(
    root: Path,
    *,
    adapter: FakeAdapter | None = None,
    recipe: FakeRecipe | None = None,
    **kwargs: Any,
) -> SessionStore:
    resolved_adapter = adapter or FakeAdapter(profile=root / "profiles/ft/default")
    profile_access = kwargs.pop(
        "profile_access", FakeProfileAccess(resolved_adapter.profile)
    )
    return SessionStore(
        root,
        recipes={"ft": recipe or FakeRecipe()},
        adapters={"ft": resolved_adapter},
        http=FakeHttp(),
        clock=kwargs.pop("clock", lambda: NOW),
        lease_manager=LeaseManager(root / "leases"),
        profile_access=profile_access,
        **kwargs,
    )


def _cookie_payload(value: str = "COOKIE_VALUE_SENTINEL") -> list[dict[str, object]]:
    return [
        {
            "name": "FTSession_fixture",
            "value": value,
            "domain": ".ft.com",
            "path": "/content",
            "expirationDate": FUTURE,
            "secure": True,
            "httpOnly": True,
            "sameSite": "lax",
        }
    ]


def test_cookie_schema_round_trip_preserves_every_portable_field(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "state")

    imported = store.import_cookies("ft", _cookie_payload())
    loaded = store.get_valid_session("ft")

    assert loaded == imported
    assert loaded.cookies == _artifact().cookies
    raw = json.loads(
        (tmp_path / "state" / "sessions" / "ft" / "default.json").read_text()
    )
    assert raw["schema_version"] == 1
    assert raw["artifact"]["schema_version"] == 1


@pytest.mark.parametrize("account_key", ("../escape", "white space", "x" * 65))
def test_session_paths_enforce_the_canonical_account_key(
    tmp_path: Path,
    account_key: str,
) -> None:
    with pytest.raises(UsageError, match="invalid session account key"):
        _store(tmp_path / "state").get_valid_session("ft", account_key)


def test_session_store_rejects_invalid_provider_keys_before_lookup(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)

    with pytest.raises(UsageError, match="invalid provider key"):
        store.status("../ft")

    assert not (tmp_path / "sessions").exists()


def test_session_status_does_not_create_or_repair_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = _store(root)

    assert store.status("ft").status is SessionStatus.REQUIRED
    assert not (root / "sessions").exists()

    state_path = root / "sessions" / "ft" / "default.json"
    state_path.parent.mkdir(parents=True)
    payload = b'{"secret":"MALFORMED_SENTINEL"'
    state_path.write_bytes(payload)

    assert store.status("ft").status is SessionStatus.REQUIRED
    assert state_path.read_bytes() == payload
    assert list(state_path.parent.iterdir()) == [state_path]


def test_session_status_surfaces_read_failure_without_repair(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "state"
    store = _store(root)
    state_path = root / "sessions" / "ft" / "default.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("{}", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def fail_session_read(path: Path) -> bytes:
        if path == state_path:
            raise PermissionError("fixture access denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_session_read)

    with pytest.raises(PersistenceError, match="session state read failed"):
        store.status("ft")

    assert state_path.exists()
    assert list(state_path.parent.iterdir()) == [state_path]


def test_cookie_import_accepts_a_stored_newsclip_session() -> None:
    payload = {
        "schema_version": 1,
        "status": "verified",
        "artifact": {"cookies": _cookie_payload()},
    }

    normalized = normalize_cookie_import(
        payload,
        allowed_domains=frozenset({"ft.com"}),
        now=NOW,
    )

    assert [cookie.value for cookie in normalized] == ["COOKIE_VALUE_SENTINEL"]


def test_cookie_import_discards_individually_expired_entries() -> None:
    payload = [
        *_cookie_payload("current-cookie"),
        {
            **_cookie_payload("expired-cookie")[0],
            "name": "expired_fixture",
            "expirationDate": (NOW - timedelta(seconds=1)).timestamp(),
        },
    ]

    normalized = normalize_cookie_import(
        payload,
        allowed_domains=frozenset({"ft.com"}),
        now=NOW,
    )

    assert [cookie.value for cookie in normalized] == ["current-cookie"]


def test_cookie_import_rejects_an_all_expired_jar() -> None:
    payload = [
        {
            **_cookie_payload("expired-cookie")[0],
            "expirationDate": (NOW - timedelta(seconds=1)).timestamp(),
        }
    ]

    with pytest.raises(ValueError, match="no usable cookies"):
        normalize_cookie_import(
            payload,
            allowed_domains=frozenset({"ft.com"}),
            now=NOW,
        )


def test_structural_validation_discards_individually_expired_cookies(
    tmp_path: Path,
) -> None:
    clock = [NOW]
    short_lived = PortableCookie(
        name="short_lived",
        value="SHORT_LIVED_SENTINEL",
        domain=".ft.com",
        path="/",
        expires=(NOW + timedelta(hours=1)).timestamp(),
    )
    durable = PortableCookie(
        name="durable",
        value="DURABLE_SENTINEL",
        domain=".ft.com",
        path="/",
        expires=(NOW + timedelta(days=30)).timestamp(),
    )
    artifact = _artifact().model_copy(update={"cookies": (short_lived, durable)})
    root = tmp_path / "state"
    store = SessionStore(
        root,
        recipes={"ft": FakeRecipe()},
        adapters={
            "ft": FakeAdapter(
                artifact=artifact,
                profile=root / "profiles/ft/default",
            )
        },
        http=FakeHttp(),
        clock=lambda: clock[0],
        lease_manager=LeaseManager(root / "leases"),
        profile_access=FakeProfileAccess(root / "profiles/ft/default"),
    )
    store.explicit_login("ft")
    clock[0] = NOW + timedelta(hours=2)

    loaded = store.get_valid_session("ft")

    assert loaded.cookies == (durable,)
    assert store.status("ft").status is SessionStatus.VERIFIED


def test_browser_paid_candidate_skips_duplicate_probe_but_reuse_verifies(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
    )
    recipe = BrowserPaidRecipe()
    store = _store(
        root,
        adapter=adapter,
        recipe=recipe,
    )

    acquired = store.explicit_login("ft")
    reused = store.explicit_login("ft")

    assert acquired.artifact == reused.artifact
    assert acquired.artifact.verified_at == NOW
    assert acquired.evidence.session_proof_observed is True
    assert adapter.calls == 1
    assert recipe.verify_calls == 1
    assert recipe.verify_fetch_calls == 1


@pytest.mark.parametrize("mode", ["credential", "profile"])
@pytest.mark.parametrize("failure", [None, "proof", "close", "publication", "cleanup"])
def test_candidate_evidence_follows_real_session_publication(
    tmp_path, monkeypatch, mode, failure
):
    from types import SimpleNamespace

    from newsclip.browser_runtime.events import RuntimeTrace, read_runtime_file
    from newsclip.browser_runtime.runtime import PatchrightMintContext
    from newsclip.browser_runtime.surface import (
        BrowserRuntimeError,
        InfrastructureCategory,
    )

    root = tmp_path / "state"
    path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(path, run_id="candidate-evidence")
    closed = False
    captures = []

    def screenshot(**kwargs):
        assert not closed
        captures.append("paid-proof")
        return b"private-candidate-proof"

    class Profiles(FakeProfileAccess):
        @contextmanager
        def open(self, *args, **kwargs):
            nonlocal closed
            try:
                yield PatchrightMintContext(
                    SimpleNamespace(),
                    SimpleNamespace(screenshot=screenshot),
                    trace=trace,
                )
            finally:
                closed = True
            if failure == "close":
                raise BrowserRuntimeError(InfrastructureCategory.BROWSER_CLEANUP_FAILED)

    class Recipe(BrowserPaidRecipe):
        def verify_fetch(self, fetch):
            assert closed, "core proof and publication follow browser close"
            assert list(tmp_path.glob("*.png")), "proof must survive until verdict"
            return super().verify_fetch(fetch)

    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
        verification_fetch=_verification_fetch(full=failure != "proof"),
        rehydrate_artifact=_artifact() if mode == "profile" else None,
    )
    store = _store(
        root,
        adapter=adapter,
        recipe=Recipe(),
        profile_access=Profiles(adapter.profile),
        diagnostic_trace=trace,
    )

    def fault(point):
        if point == "before_session_replace":
            assert closed
            assert list(tmp_path.glob("*.png"))
            if failure == "publication":
                raise OSError("fixture session publication failure")

    store._fault_hook = fault
    if failure == "cleanup":
        original = Path.unlink

        def unlink(candidate, *args, **kwargs):
            if candidate.suffix == ".png":
                assert store.status("ft").status is SessionStatus.VERIFIED
                raise OSError("fixture artifact cleanup failure")
            return original(candidate, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", unlink)
    if failure in {"proof", "close", "publication"}:
        with pytest.raises(
            (ProviderTransportError, SessionRequiredError, PersistenceError)
        ):
            store.explicit_login("ft")
        assert store.status("ft").status is not SessionStatus.VERIFIED
    else:
        acquired = store.explicit_login("ft")
        assert store.get_valid_session("ft") == acquired.artifact
    assert captures == ["paid-proof"]
    assert bool(list(tmp_path.glob("*.png"))) is (failure is not None)
    stages = [
        record.event.stage
        for record in read_runtime_file(path).records
        if record.event.event == "acquisition_evidence"
    ]
    assert ("published" in stages) is (failure in {None, "cleanup"})


def test_browser_paid_candidate_requires_core_verified_full_evidence(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
        verification_fetch=_verification_fetch(full=False),
    )
    recipe = BrowserPaidRecipe()
    store = _store(root, adapter=adapter, recipe=recipe)

    with pytest.raises(ProviderTransportError, match="paid_probe_transport_failure"):
        store.explicit_login("ft")

    assert recipe.verify_fetch_calls == 1
    assert store.status("ft").status is SessionStatus.COOLDOWN


def test_browser_paid_candidate_wraps_unexpected_verification_exception(
    tmp_path: Path,
) -> None:
    class FailingBrowserPaidRecipe(BrowserPaidRecipe):
        def verify_fetch(self, fetch: RawFetch) -> SessionVerification:
            self.verify_fetch_calls += 1
            raise RuntimeError("PRIVATE_BROWSER_VERIFY_SENTINEL")

    root = tmp_path / "state"
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
    )
    recipe = FailingBrowserPaidRecipe()
    store = _store(root, adapter=adapter, recipe=recipe)

    with pytest.raises(
        ProviderTransportError,
        match="session verification transport failure",
    ) as captured:
        store.explicit_login("ft")

    assert "PRIVATE_BROWSER_VERIFY_SENTINEL" not in str(captured.value)
    assert recipe.verify_fetch_calls == 1
    assert store.status("ft").status is SessionStatus.COOLDOWN


def test_candidate_and_recipe_verification_modes_must_match(tmp_path: Path) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
    )
    store = _store(root, adapter=adapter)

    with pytest.raises(SessionRequiredError, match="session_infrastructure"):
        store.explicit_login("ft")

    health = store.status("ft")
    assert adapter.calls == 1
    assert health.status is SessionStatus.COOLDOWN
    assert health.failure_reason_code == "session_infrastructure"


def test_status_reports_required_when_every_stored_cookie_has_expired(
    tmp_path: Path,
) -> None:
    clock = [NOW]
    root = tmp_path / "state"
    store = SessionStore(
        root,
        recipes={"ft": FakeRecipe()},
        adapters={
            "ft": FakeAdapter(
                artifact=_artifact(),
                profile=root / "profiles/ft/default",
            )
        },
        http=FakeHttp(),
        clock=lambda: clock[0],
        lease_manager=LeaseManager(root / "leases"),
        profile_access=FakeProfileAccess(root / "profiles/ft/default"),
    )
    store.explicit_login("ft")
    clock[0] = NOW + timedelta(days=31)

    assert store.status("ft").status is SessionStatus.REQUIRED
    with pytest.raises(SessionRequiredError, match="not verified"):
        store.get_valid_session("ft")


def test_portable_cookie_loader_preserves_scope_and_flags() -> None:
    portable = _artifact().cookies[0]

    jar = portable_cookie_jar((portable,))
    loaded = next(iter(jar.jar))

    assert loaded.name == portable.name
    assert loaded.value == portable.value
    assert loaded.domain == portable.domain
    assert loaded.path == portable.path
    assert loaded.expires == int(portable.expires or 0)
    assert loaded.secure is True
    assert loaded.discard is False
    assert loaded.has_nonstandard_attr("HttpOnly")
    assert loaded.get_nonstandard_attr("SameSite") == "Lax"


@pytest.mark.parametrize(
    "mutation",
    [
        {"domain": ".evil.test"},
        {"name": ""},
        {"path": "content"},
        {"expirationDate": "tomorrow"},
        {"sameSite": "sometimes"},
        {"secure": "true"},
    ],
)
def test_bad_cookie_import_does_not_replace_valid_artifact(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    store = _store(tmp_path / "state")
    prior = store.import_cookies("ft", _cookie_payload("prior-valid"))
    bad = _cookie_payload("untrusted")
    bad[0].update(mutation)

    with pytest.raises((ValueError, TypeError)):
        store.import_cookies("ft", bad)

    assert store.get_valid_session("ft") == prior


def test_storage_state_with_origins_is_rejected() -> None:
    payload = {
        "cookies": _cookie_payload(),
        "origins": [
            {
                "origin": "https://www.ft.com",
                "localStorage": [{"name": "token", "value": "not-portable"}],
            }
        ],
    }

    with pytest.raises(ValueError, match="not portable"):
        normalize_cookie_import(payload, allowed_domains=frozenset({"ft.com"}), now=NOW)


def test_browser_export_discards_third_party_cookie_but_import_rejects_it() -> None:
    payload = [
        *_cookie_payload("provider-cookie"),
        {
            "name": "consent",
            "value": "THIRD_PARTY_SENTINEL",
            "domain": ".consent.example",
            "path": "/",
            "expires": -1,
            "secure": True,
            "httpOnly": False,
            "sameSite": "None",
        },
    ]

    exported = normalize_browser_cookie_export(
        payload, allowed_domains=frozenset({"ft.com"}), now=NOW
    )

    assert len(exported) == 1
    assert exported[0].value == "provider-cookie"
    with pytest.raises(ValueError, match="domain is not allowed"):
        normalize_cookie_import(payload, allowed_domains=frozenset({"ft.com"}), now=NOW)


class SharedAdapter(FakeAdapter):
    def __init__(self, counter, *, profile: Path) -> None:
        super().__init__(
            artifact=_artifact("shared-complete-artifact"), profile=profile
        )
        self.counter = counter

    def mint_credentials(self, browser, *, account_key: str, challenge_mode):
        with self.counter.get_lock():
            self.counter.value += 1
        time.sleep(0.05)
        return super().mint_credentials(
            browser, account_key=account_key, challenge_mode=challenge_mode
        )


def _competing_login(root: str, counter, results) -> None:
    root_path = Path(root)
    store = _store(
        root_path,
        adapter=SharedAdapter(counter, profile=root_path / "profiles/ft/default"),
    )
    acquired = store.explicit_login("ft")
    results.put(str(acquired.artifact.generation_id))


class CrossRootAdapter(FakeAdapter):
    def __init__(self, attempts, *, profile: Path) -> None:
        super().__init__(profile=profile)
        self.attempts = attempts

    def mint_credentials(self, browser, *, account_key: str, challenge_mode):
        with self.attempts.get_lock():
            self.attempts.value += 1
        return super().mint_credentials(
            browser, account_key=account_key, challenge_mode=challenge_mode
        )


class CrossRootProfileAccess(FakeProfileAccess):
    def __init__(self, profile: Path, active, peak) -> None:
        super().__init__(profile)
        self.active = active
        self.peak = peak

    @contextmanager
    def open(
        self,
        provider: str,
        account_key: str,
        *,
        require_virtual_display: bool,
    ):
        with self.active.get_lock(), self.peak.get_lock():
            self.active.value += 1
            self.peak.value = max(self.peak.value, self.active.value)
        try:
            time.sleep(0.1)
            yield object()
        finally:
            with self.active.get_lock():
                self.active.value -= 1


def _cross_root_login(root: str, lease_root: str, active, peak, attempts) -> None:
    root_path = Path(root)
    profile = root_path / "profiles/ft/default"
    adapter = CrossRootAdapter(attempts, profile=profile)
    store = SessionStore(
        root_path,
        recipes={"ft": FakeRecipe()},
        adapters={"ft": adapter},
        http=FakeHttp(),
        clock=lambda: NOW,
        lease_manager=LeaseManager(Path(lease_root)),
        profile_access=CrossRootProfileAccess(profile, active, peak),
    )
    store.explicit_login("ft")


def test_competing_explicit_logins_mint_exactly_once(tmp_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    counter = context.Value("i", 0)
    results = context.Queue()
    root = tmp_path / "state"
    processes = [
        context.Process(target=_competing_login, args=(str(root), counter, results))
        for _ in range(5)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    assert [process.exitcode for process in processes] == [0] * 5
    generations = [results.get(timeout=1) for _ in processes]
    assert counter.value == 1
    assert len(set(generations)) == 1
    assert _store(root).get_valid_session("ft").cookies[0].value == (
        "shared-complete-artifact"
    )


def test_same_account_attempts_across_state_roots_serialize(tmp_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    active = context.Value("i", 0)
    peak = context.Value("i", 0)
    attempts = context.Value("i", 0)
    lease_root = tmp_path / "account-global-leases"
    processes = [
        context.Process(
            target=_cross_root_login,
            args=(
                str(tmp_path / f"state-{index}"),
                str(lease_root),
                active,
                peak,
                attempts,
            ),
        )
        for index in range(2)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    assert [process.exitcode for process in processes] == [0, 0]
    assert attempts.value == 2
    assert peak.value == 1


def test_warm_first_modes_follow_observed_actions(tmp_path: Path) -> None:
    root = tmp_path / "state"
    rehydrated = _artifact("retained-profile-session")
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        rehydrate_artifact=rehydrated,
    )
    store = _store(root, adapter=adapter)

    first = store.explicit_login("ft")
    second = store.explicit_login("ft")

    assert first.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert second.evidence.mode is AcquisitionMode.ARTIFACT_REUSE
    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 0


def test_candidate_verification_runs_after_acquisition_browser_closes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"

    class LifetimeProfileAccess(FakeProfileAccess):
        browser_open = False

        @contextmanager
        def open(
            self,
            provider: str,
            account_key: str,
            *,
            require_virtual_display: bool,
        ):
            self.browser_open = True
            try:
                yield object()
            finally:
                self.browser_open = False

    adapter = FakeAdapter(
        rehydrate_artifact=_artifact("retained-profile-session"),
        profile=root / "profiles/ft/default",
    )
    profiles = LifetimeProfileAccess(adapter.profile)

    class BrowserBackedRecipe(FakeRecipe):
        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            assert profiles.browser_open is False
            return super().verify(http, artifact)

    store = _store(root, adapter=adapter, profile_access=profiles)
    store._recipes["ft"] = BrowserBackedRecipe()

    acquired = store.explicit_login("ft")

    assert acquired.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 0


def test_dead_profile_candidate_falls_through_to_credentials_once(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        artifact=_artifact("fresh-credential-session"),
        rehydrate_artifact=_artifact("reject"),
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=adapter)

    acquired = store.explicit_login("ft")

    assert acquired.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert acquired.artifact.cookies[0].value == "fresh-credential-session"
    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 1


def test_login_timing_distinguishes_warm_tiers_from_credential_mint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(profile=root / "profiles/ft/default")
    store = _store(root, adapter=adapter)
    recorder = TimingRecorder(tmp_path / "timings")

    with recorder.operation(
        TimingOperation.LOGIN,
        provider="ft",
        transport=TimingTransport.BROWSER,
    ) as operation:
        acquired = store.explicit_login("ft")

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert acquired.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert run.finished is not None
    assert run.finished.acquisition_mode is AcquisitionMode.CREDENTIAL_MINT
    steps = [
        event.step
        for record in run.records
        if isinstance((event := record.event), StepFinishedEvent)
    ]
    assert steps == [
        TimingStep.ARTIFACT_VERIFY,
        TimingStep.ATTEMPT_LEASE_WAIT,
        TimingStep.PROFILE_LEASE_WAIT,
        TimingStep.PROFILE_REHYDRATE,
        TimingStep.CREDENTIAL_FLOW,
        TimingStep.SESSION_VERIFY,
        TimingStep.SESSION_PERSIST,
    ]


def test_failed_login_timing_records_closed_mint_failure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        MintOutcome.CREDENTIAL_REJECTED,
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=adapter)
    recorder = TimingRecorder(tmp_path / "timings")

    with (
        pytest.raises(OperatorActionRequiredError),
        recorder.operation(
            TimingOperation.LOGIN,
            provider="ft",
            transport=TimingTransport.BROWSER,
        ) as operation,
    ):
        store.explicit_login("ft")

    assert operation.path is not None
    run = read_timing_file(operation.path)
    assert run.finished is not None
    assert run.finished.outcome is TimingOutcome.ERROR
    assert run.finished.failure_stage is MintFailureStage.CREDENTIAL
    assert run.finished.failure_category is MintFailureCategory.CREDENTIAL_REJECTED


def test_dead_credential_candidate_reports_paid_probe_failure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        artifact=_artifact("reject"),
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=adapter)

    with pytest.raises(
        OperatorActionRequiredError,
        match="paid_probe_article_not_full",
    ) as failure:
        store.explicit_login("ft")

    assert adapter.calls == 1
    health = store.status("ft")
    assert health.status is SessionStatus.OPERATOR_ACTION
    assert health.failure_reason_code == "paid_probe_article_not_full"
    assert failure.value.reason_code == health.failure_reason_code


def test_inconclusive_stored_session_is_preserved_without_opening_browser(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(profile=root / "profiles/ft/default")
    store = _store(root, adapter=adapter)
    prior = store.import_cookies("ft", _cookie_payload("known-good"))
    store._recipes["ft"] = InconclusiveRecipe()
    preparations = 0

    def prepare_browser() -> None:
        nonlocal preparations
        preparations += 1

    # The reason names the inconclusive PROBE, not a transport fault: the
    # request completed, so retrying the network resolves nothing, and the
    # scheduler needs the two apart to escalate a genuinely unentitled
    # session instead of reporting a network problem forever (P3).
    with pytest.raises(ProviderTransportError, match="paid_probe_unknown"):
        store.explicit_login("ft", before_browser=prepare_browser)

    assert preparations == 0
    assert adapter.rehydrate_calls == 0
    assert adapter.calls == 0
    assert store.status("ft").status is SessionStatus.VERIFIED
    assert store.get_valid_session("ft").generation_id == prior.generation_id


def test_inconclusive_profile_candidate_never_attempts_credentials(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(
        rehydrate_artifact=_artifact("opaque-profile"),
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=adapter)
    store._recipes["ft"] = InconclusiveRecipe()

    with pytest.raises(ProviderTransportError, match="transport_failure"):
        store.explicit_login("ft")

    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 0
    health = store.status("ft")
    assert health.status is SessionStatus.COOLDOWN
    assert health.failure_reason_code == "paid_probe_unknown"


def test_inconclusive_credential_candidate_is_not_operator_action(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(profile=root / "profiles/ft/default")
    store = _store(root, adapter=adapter)
    store._recipes["ft"] = InconclusiveRecipe()

    with pytest.raises(ProviderTransportError, match="transport_failure"):
        store.explicit_login("ft")

    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 1
    health = store.status("ft")
    assert health.status is SessionStatus.COOLDOWN
    assert health.failure_reason_code == "paid_probe_unknown"


def test_inconclusive_probe_persists_only_a_closed_reason_code(
    tmp_path: Path,
) -> None:
    class HttpErrorRecipe(FakeRecipe):
        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            return SessionVerification(
                verified=False,
                access_state=AccessState.UNKNOWN,
                reason="http_error",
                verified_at=NOW,
            )

    root = tmp_path / "state"
    store = _store(root, adapter=FakeAdapter(profile=root / "profiles/ft/default"))
    store._recipes["ft"] = HttpErrorRecipe()

    with pytest.raises(ProviderTransportError, match="paid_probe_transport_failure"):
        store.explicit_login("ft")

    assert store.status("ft").failure_reason_code == "paid_probe_http_error"


def test_profile_probe_exception_never_attempts_credentials(tmp_path: Path) -> None:
    class FailingRecipe(FakeRecipe):
        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            raise OSError("fixture provider outage")

    root = tmp_path / "state"
    adapter = FakeAdapter(
        rehydrate_artifact=_artifact("profile-session"),
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=adapter)
    store._recipes["ft"] = FailingRecipe()

    with pytest.raises(ProviderTransportError, match="transport failure"):
        store.explicit_login("ft")

    assert adapter.rehydrate_calls == 1
    assert adapter.calls == 0
    assert store.status("ft").status is SessionStatus.COOLDOWN


def test_cookie_import_probe_exception_is_typed_transport_failure(
    tmp_path: Path,
) -> None:
    class FailingRecipe(FakeRecipe):
        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            raise OSError("fixture provider outage")

    store = _store(tmp_path / "state")
    store._recipes["ft"] = FailingRecipe()

    with pytest.raises(ProviderTransportError, match="transport failure"):
        store.import_cookies("ft", _cookie_payload())

    assert store.status("ft").status is SessionStatus.REQUIRED


def test_cookie_import_verification_serializes_with_concurrent_login(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    live_token = {"value": "old"}
    login_holds_generation = threading.Event()
    release_login = threading.Event()
    import_invoked = threading.Event()
    old_import_verified = threading.Event()
    login_errors: list[BaseException] = []
    import_errors: list[BaseException] = []

    class LiveTokenRecipe(FakeRecipe):
        def verify(
            self, http: FakeHttp, artifact: SessionArtifact
        ) -> SessionVerification:
            token = artifact.cookies[0].value
            verified = token == live_token["value"]
            if token == "old":
                old_import_verified.set()
            return SessionVerification(
                verified=verified,
                access_state=(
                    AccessState.FULL if verified else AccessState.AUTH_REQUIRED
                ),
                reason="verified_fixture" if verified else "rejected_fixture",
                verified_at=NOW,
            )

    class BlockingMintAdapter(FakeAdapter):
        def mint_credentials(self, browser, *, account_key: str, challenge_mode):
            login_holds_generation.set()
            assert release_login.wait(2)
            live_token["value"] = "new"
            return super().mint_credentials(
                browser,
                account_key=account_key,
                challenge_mode=challenge_mode,
            )

    adapter = BlockingMintAdapter(
        artifact=_artifact("new"),
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=adapter, recipe=LiveTokenRecipe())

    def login() -> None:
        try:
            store.explicit_login("ft")
        except BaseException as error:
            login_errors.append(error)

    def import_old_cookies() -> None:
        import_invoked.set()
        try:
            store.import_cookies("ft", _cookie_payload("old"))
        except BaseException as error:
            import_errors.append(error)

    login_thread = threading.Thread(target=login)
    login_thread.start()
    assert login_holds_generation.wait(2)

    import_thread = threading.Thread(target=import_old_cookies)
    import_thread.start()
    assert import_invoked.wait(2)
    assert not old_import_verified.wait(0.2)

    release_login.set()
    login_thread.join(2)
    import_thread.join(2)

    assert not login_thread.is_alive()
    assert not import_thread.is_alive()
    assert not login_errors
    assert len(import_errors) == 1
    assert isinstance(import_errors[0], SessionRequiredError)
    assert old_import_verified.is_set()
    assert store.get_valid_session("ft").cookies[0].value == "new"


def test_verified_artifact_skips_browser_preparation(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = _store(root)
    store.import_cookies("ft", _cookie_payload("warm-artifact"))

    def unexpected_preparation() -> None:
        raise AssertionError("warm artifact must not prepare a browser surface")

    acquired = store.explicit_login(
        "ft",
        headless=True,
        before_browser=unexpected_preparation,
    )

    assert acquired.evidence.mode is AcquisitionMode.ARTIFACT_REUSE


def test_browser_preparation_runs_without_session_lock_and_rechecks_generation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(profile=root / "profiles/ft/default")
    store = _store(
        root,
        adapter=adapter,
        session_lock_timeout_seconds=0.1,
    )
    preparations = 0

    def prepare_browser() -> None:
        nonlocal preparations
        preparations += 1
        # Models a delegated child completing while the parent holds no lock.
        store.import_cookies("ft", _cookie_payload("delegated-generation"))

    acquired = store.explicit_login(
        "ft",
        headless=True,
        before_browser=prepare_browser,
    )

    assert preparations == 1
    assert acquired.evidence.mode is AcquisitionMode.ARTIFACT_REUSE
    assert adapter.rehydrate_calls == 0
    assert adapter.calls == 0


def test_profile_reset_is_explicit_leased_and_preserves_session(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    profile = root / "profiles/ft/default"
    profile.mkdir(parents=True)
    marker = profile / "device-state"
    marker.write_text("retained", encoding="utf-8")
    adapter = FakeAdapter(profile=profile)
    store = _store(root, adapter=adapter)
    artifact = store.import_cookies("ft", _cookie_payload("verified-jar"))

    store.reset_browser_profile("ft")

    assert profile.is_dir()
    assert not marker.exists()
    assert store.get_valid_session("ft") == artifact


@pytest.mark.parametrize("same_authority", [False, True])
def test_failed_refresh_can_preserve_only_the_independently_proven_authority(
    tmp_path: Path,
    same_authority: bool,
) -> None:
    root = tmp_path / "state"
    refreshed = _artifact("last-known-good" if same_authority else "new-browser-cookie")
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        rehydrate_artifact=refreshed,
        refresh_failure=MintFailureEvidence(
            stage=MintFailureStage.CALLBACK,
            category=MintFailureCategory.CALLBACK_NOT_CONFIRMED,
        ),
    )
    store = _store(root, adapter=adapter)
    prior = store.import_cookies("ft", _cookie_payload("last-known-good"))

    class StaleThenFullRecipe(FakeRecipe):
        def __init__(self) -> None:
            self.calls = 0

        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            self.calls += 1
            return SessionVerification(
                verified=self.calls > 1,
                access_state=(
                    AccessState.FULL if self.calls > 1 else AccessState.AUTH_REQUIRED
                ),
                reason="fixture",
                verified_at=NOW,
            )

    store._recipes["ft"] = StaleThenFullRecipe()

    acquired = store.explicit_login("ft")

    expected = prior if same_authority else refreshed
    assert acquired.artifact.generation_id == expected.generation_id
    assert acquired.artifact.cookies == expected.cookies
    assert acquired.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert acquired.refresh_failure is not None
    assert store.get_valid_session("ft").generation_id == expected.generation_id


def test_failed_refresh_does_not_restore_required_generation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    candidate = _artifact("rehydrated-browser-cookie")
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        rehydrate_artifact=candidate,
        refresh_failure=MintFailureEvidence(
            stage=MintFailureStage.CALLBACK,
            category=MintFailureCategory.CALLBACK_NOT_CONFIRMED,
        ),
    )
    store = _store(root, adapter=adapter)
    prior = store.import_cookies("ft", _cookie_payload("required-prior"))
    store.mark_required("ft", generation_id=prior.generation_id)
    probed_cookie_values: list[str] = []

    class RecordingRecipe(FakeRecipe):
        def verify(
            self,
            http: FakeHttp,
            artifact: SessionArtifact,
        ) -> SessionVerification:
            probed_cookie_values.append(artifact.cookies[0].value)
            return super().verify(http, artifact)

    store._recipes["ft"] = RecordingRecipe()

    acquired = store.explicit_login("ft")

    assert probed_cookie_values == ["rehydrated-browser-cookie"]
    assert acquired.artifact.generation_id == candidate.generation_id
    assert acquired.artifact.generation_id != prior.generation_id
    assert acquired.refresh_failure is not None
    assert store.get_valid_session("ft").generation_id == candidate.generation_id


def test_failed_refresh_with_full_profile_replaces_expired_generation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    clock = [NOW]
    candidate_cookie = (
        _artifact("rehydrated-browser-cookie")
        .cookies[0]
        .model_copy(update={"expires": (NOW + timedelta(days=60)).timestamp()})
    )
    candidate = _artifact("rehydrated-browser-cookie").model_copy(
        update={"cookies": (candidate_cookie,)}
    )
    recipe = BrowserPaidRecipe()
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        rehydrate_artifact=candidate,
        refresh_failure=MintFailureEvidence(
            stage=MintFailureStage.CALLBACK,
            category=MintFailureCategory.CALLBACK_NOT_CONFIRMED,
        ),
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
    )
    store = SessionStore(
        root,
        recipes={"ft": recipe},
        adapters={"ft": adapter},
        http=FakeHttp(),
        clock=lambda: clock[0],
        lease_manager=LeaseManager(root / "leases"),
        profile_access=FakeProfileAccess(root / "profiles/ft/default"),
    )
    prior = store.import_cookies("ft", _cookie_payload("expired-prior"))
    clock[0] = NOW + timedelta(days=31)

    acquired = store.explicit_login("ft")

    assert acquired.artifact.generation_id == candidate.generation_id
    assert acquired.artifact.generation_id != prior.generation_id
    assert acquired.artifact.cookies[0].value == "rehydrated-browser-cookie"
    assert acquired.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert acquired.refresh_failure is not None
    assert adapter.calls == 0
    assert recipe.verify_fetch_calls == 1
    assert store.status("ft").status is SessionStatus.VERIFIED
    assert store.get_valid_session("ft").generation_id == candidate.generation_id


def test_failed_refresh_prunes_expired_cookies_from_preserved_generation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    clock = [NOW]
    adapter = FakeAdapter(
        profile=root / "profiles/ft/default",
        rehydrate_artifact=_artifact("rehydrated-browser-cookie"),
        refresh_failure=MintFailureEvidence(
            stage=MintFailureStage.CALLBACK,
            category=MintFailureCategory.CALLBACK_NOT_CONFIRMED,
        ),
    )
    store = SessionStore(
        root,
        recipes={"ft": FakeRecipe()},
        adapters={"ft": adapter},
        http=FakeHttp(),
        clock=lambda: clock[0],
        lease_manager=LeaseManager(root / "leases"),
        profile_access=FakeProfileAccess(root / "profiles/ft/default"),
    )
    short_lived = (
        _artifact("short-lived")
        .cookies[0]
        .model_copy(
            update={
                "name": "short_lived",
                "expires": (NOW + timedelta(hours=1)).timestamp(),
            }
        )
    )
    durable = (
        _artifact("durable")
        .cookies[0]
        .model_copy(
            update={
                "name": "durable",
                "expires": (NOW + timedelta(days=60)).timestamp(),
            }
        )
    )
    prior = store.import_cookies(
        "ft",
        [
            cookie.model_dump(by_alias=True, exclude_none=True)
            for cookie in (short_lived, durable)
        ],
    )
    clock[0] = NOW + timedelta(hours=2)

    acquired = store.explicit_login("ft")

    assert acquired.artifact.generation_id == prior.generation_id
    assert [cookie.value for cookie in acquired.artifact.cookies] == ["durable"]
    assert [cookie.value for cookie in store.get_valid_session("ft").cookies] == [
        "durable"
    ]


def test_fault_before_replace_preserves_prior_bytes(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = _store(root)
    store.import_cookies("ft", _cookie_payload("prior-valid"))
    path = root / "sessions" / "ft" / "default.json"
    before = path.read_bytes()

    def fail(point: str) -> None:
        if point == "before_session_replace":
            raise OSError("injected atomic-write fault")

    failing = _store(root, fault_hook=fail)
    with pytest.raises(PersistenceError, match="session state write failed"):
        failing.reset("ft")

    assert path.read_bytes() == before
    assert store.get_valid_session("ft").cookies[0].value == "prior-valid"
    assert not list(path.parent.glob("*.tmp"))


@pytest.mark.parametrize(
    ("outcome", "failure"),
    [
        (MintOutcome.CREDENTIAL_REJECTED, "credential_rejected"),
        (MintOutcome.SECOND_FACTOR_REQUIRED, "second_factor_required"),
        (MintOutcome.ACCOUNT_ALERT, "account_alert"),
        (MintOutcome.CHALLENGE_BLOCKED, "challenge_blocked"),
        (MintOutcome.UNKNOWN_FLOW, "unknown_flow"),
    ],
)
def test_terminal_failure_requires_reset_before_another_attempt(
    tmp_path: Path, outcome: MintOutcome, failure: str
) -> None:
    root = tmp_path / outcome.value
    first = FakeAdapter(outcome, profile=root / "profiles/ft/default")
    store = _store(root, adapter=first)

    with pytest.raises(OperatorActionRequiredError) as first_failure:
        store.explicit_login("ft")
    second = FakeAdapter(profile=root / "profiles/ft/default")
    store._adapters["ft"] = second
    with pytest.raises(
        OperatorActionRequiredError,
        match="explicit reset",
    ) as blocked_failure:
        store.explicit_login("ft")

    assert first.calls == 1
    assert second.calls == 0
    assert store.status("ft").status is SessionStatus.OPERATOR_ACTION
    assert store.status("ft").last_failure.value == failure
    assert store.status("ft").failure_reason_code is not None
    assert first_failure.value.provider == "ft"
    assert first_failure.value.reason_code == store.status("ft").failure_reason_code
    assert blocked_failure.value.provider == "ft"
    assert blocked_failure.value.reason_code == store.status("ft").failure_reason_code

    store.reset("ft")
    assert store.explicit_login("ft").artifact.provider == "ft"
    assert second.calls == 1


def test_infrastructure_failure_respects_fake_clock_cooldown(
    tmp_path: Path,
) -> None:
    current = [NOW]
    store = SessionStore(
        tmp_path / "state",
        recipes={"ft": FakeRecipe()},
        adapters={},
        http=FakeHttp(),
        clock=lambda: current[0],
        lease_manager=LeaseManager(tmp_path / "leases"),
        profile_access=FakeProfileAccess(tmp_path / "profiles/ft/default"),
    )
    failing = FakeAdapter(
        MintOutcome.INFRASTRUCTURE_ERROR,
        profile=tmp_path / "profiles/ft/default",
    )
    store._adapters["ft"] = failing
    with pytest.raises(SessionRequiredError):
        store.explicit_login("ft")

    succeeding = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store._adapters["ft"] = succeeding
    with pytest.raises(SessionRequiredError, match="cooldown"):
        store.explicit_login("ft")
    assert succeeding.calls == 0

    current[0] += timedelta(minutes=16)
    assert store.explicit_login("ft").artifact.provider == "ft"
    assert succeeding.calls == 1


def test_session_paths_and_public_status_are_private_and_redacted(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = _store(root)
    store.import_cookies("ft", _cookie_payload())
    state_path = root / "sessions" / "ft" / "default.json"

    for directory in (root, root / "sessions", root / "sessions" / "ft"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    serialized = json.dumps(store.status("ft").public_dict())
    assert "COOKIE_VALUE_SENTINEL" not in serialized
    assert "cookies" not in serialized.lower()
    assert "secret" not in serialized.lower()


def test_unusable_state_root_is_a_typed_persistence_failure(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(PersistenceError, match="directory is unavailable"):
        _store(root)


def test_malformed_state_is_quarantined_without_content_in_error(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = _store(root)
    state_path = root / "sessions" / "ft" / "default.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text('{"secret":"MALFORMED_SENTINEL"', encoding="utf-8")

    with pytest.raises(SessionRequiredError) as caught:
        store.get_valid_session("ft")

    assert "MALFORMED_SENTINEL" not in str(caught.value)
    assert not state_path.exists()
    quarantined = list(state_path.parent.glob("default.invalid.*.json"))
    assert len(quarantined) == 1
    assert stat.S_IMODE(quarantined[0].stat().st_mode) == 0o600


def test_invalid_read_does_not_quarantine_a_concurrent_valid_generation(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "state"
    store = _store(root)
    imported = store.import_cookies("ft", _cookie_payload("fresh-generation"))
    state_path = root / "sessions" / "ft" / "default.json"
    replacement = state_path.with_suffix(".replacement")
    replacement.write_bytes(state_path.read_bytes())
    replacement.chmod(0o600)
    state_path.write_text("{", encoding="utf-8")
    original_read_bytes = Path.read_bytes
    first_read = True

    def replace_after_invalid_read(path: Path) -> bytes:
        nonlocal first_read
        payload = original_read_bytes(path)
        if path == state_path and first_read:
            first_read = False
            replacement.replace(state_path)
        return payload

    monkeypatch.setattr(Path, "read_bytes", replace_after_invalid_read)

    loaded = store.get_valid_session("ft")

    assert loaded == imported
    assert state_path.exists()
    assert not list(state_path.parent.glob("default.invalid.*.json"))


def test_clear_and_failure_acknowledgement_never_mint_or_read_op(
    tmp_path: Path, monkeypatch
) -> None:
    def forbidden_op(*args, **kwargs):
        raise AssertionError("operator-only session command invoked op")

    monkeypatch.setattr("subprocess.run", forbidden_op)
    root = tmp_path / "state"
    failing = FakeAdapter(
        MintOutcome.CREDENTIAL_REJECTED,
        profile=root / "profiles/ft/default",
    )
    store = _store(root, adapter=failing)
    with pytest.raises(OperatorActionRequiredError):
        store.explicit_login("ft")
    assert failing.calls == 1

    store.acknowledge("ft")

    assert store.status("ft").status is SessionStatus.REQUIRED
    assert failing.calls == 1
    store.import_cookies("ft", _cookie_payload("clear-me"))

    store.clear("ft")

    assert store.status("ft").status is SessionStatus.REQUIRED
    assert failing.calls == 1
    with pytest.raises(SessionRequiredError):
        store.get_valid_session("ft")


def test_acknowledgement_rejects_healthy_state(tmp_path: Path) -> None:
    store = _store(tmp_path / "state")
    store.import_cookies("ft", _cookie_payload())

    with pytest.raises(UsageError, match="no failure state"):
        store.acknowledge("ft")


def test_acknowledgement_preserves_inactive_last_known_generation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "state")
    prior = store.import_cookies("ft", _cookie_payload("last-known-generation"))
    store._persist_failure(
        "ft",
        "default",
        MintOutcome.INFRASTRUCTURE_ERROR,
        prior_artifact=prior,
    )

    store.acknowledge("ft")

    stored = store._load("ft", "default")
    assert stored is not None
    assert stored.status is SessionStatus.REQUIRED
    assert stored.artifact == prior
    assert stored.last_failure is None
    assert stored.retry_not_before is None
    with pytest.raises(SessionRequiredError):
        store.get_valid_session("ft")


def test_mark_required_downgrades_verified_and_status_reports_required(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "state")
    artifact = store.explicit_login("ft").artifact

    store.mark_required("ft", generation_id=artifact.generation_id)

    assert store.status("ft").status is SessionStatus.REQUIRED
    with pytest.raises(SessionRequiredError):
        store.get_valid_session("ft")


def test_mark_required_generation_mismatch_keeps_fresh_session(
    tmp_path: Path,
) -> None:
    """A stale probe verdict must not erase a concurrently re-minted session."""

    store = _store(tmp_path / "state")
    fresh = store.explicit_login("ft").artifact

    store.mark_required("ft", generation_id=uuid4())  # verdict about an old artifact

    assert store.status("ft").status is SessionStatus.VERIFIED
    assert store.get_valid_session("ft").generation_id == fresh.generation_id


def test_mark_required_never_clobbers_operator_action(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = _store(
        root,
        adapter=FakeAdapter(
            MintOutcome.CREDENTIAL_REJECTED,
            profile=root / "profiles/ft/default",
        ),
    )
    with pytest.raises(OperatorActionRequiredError):
        store.explicit_login("ft")

    store.mark_required("ft")

    health = store.status("ft")
    assert health.status is SessionStatus.OPERATOR_ACTION
    assert health.last_failure is not None


def test_login_probes_eagerly_and_through_the_metered_client(
    tmp_path: Path,
) -> None:
    """SV1.5: both login-path probes (post-mint verify and reuse check) happen
    eagerly and use the policy-issued client, never the raw one."""

    class SpyRecipe(FakeRecipe):
        def __init__(self) -> None:
            self.probes: list[object] = []

        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            self.probes.append(http)
            return super().verify(http, artifact)

    recipe = SpyRecipe()
    metered = FakeHttp()
    factory_keys: list[str] = []

    @contextmanager
    def factory(key: str):
        factory_keys.append(key)
        yield metered

    minter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = SessionStore(
        tmp_path / "state",
        recipes={"ft": recipe},
        adapters={"ft": minter},
        http=FakeHttp(),
        client_factory=factory,
        clock=lambda: NOW,
        lease_manager=LeaseManager(tmp_path / "leases"),
        profile_access=FakeProfileAccess(minter.profile),
    )

    store.explicit_login("ft")  # mint, then eager post-mint verify
    store.explicit_login("ft")  # reuse path: eager probe, no re-mint

    assert minter.calls == 1
    assert len(recipe.probes) == 2
    assert all(probe is metered for probe in recipe.probes)
    assert factory_keys == ["ft", "ft"]


def test_verification_challenge_preserves_operator_action_category(
    tmp_path: Path,
) -> None:
    class ChallengeRecipe(FakeRecipe):
        def verify(self, http, artifact: SessionArtifact) -> SessionVerification:
            raise OperatorActionRequiredError("interactive challenge fixture")

    recipe = ChallengeRecipe()
    store = _store(tmp_path / "state", recipe=recipe)

    with pytest.raises(
        OperatorActionRequiredError,
        match="interactive challenge fixture",
    ):
        store.import_cookies("ft", _cookie_payload())

    with pytest.raises(
        OperatorActionRequiredError,
        match="interactive challenge fixture",
    ):
        store.explicit_login("ft")


def test_warm_only_login_refuses_before_reaching_credentials(tmp_path: Path) -> None:
    """A scheduled keeper must not read a secret it was not permitted to use."""

    adapter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = _store(tmp_path / "state", adapter=adapter)

    with pytest.raises(SessionRequiredError, match="credential_mint_not_permitted"):
        store.explicit_login("ft", allow_credential_mint=False)

    assert adapter.calls == 0
    assert adapter.rehydrate_calls == 1


def test_warm_only_login_still_reuses_a_verified_artifact(tmp_path: Path) -> None:
    adapter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = _store(tmp_path / "state", adapter=adapter)

    minted = store.explicit_login("ft")
    reused = store.explicit_login("ft", allow_credential_mint=False)

    assert minted.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert reused.evidence.mode is AcquisitionMode.ARTIFACT_REUSE
    assert adapter.calls == 1


def test_reuse_records_when_access_was_last_proven(tmp_path: Path) -> None:
    """Upkeep decides staleness from this field.

    Leaving it at the generation's mint time makes every proven session look
    equally stale for ever, so scheduled upkeep re-proves it on every cycle
    without end.
    """

    clock = {"now": NOW}
    adapter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = _store(
        tmp_path / "state",
        adapter=adapter,
        clock=lambda: clock["now"],
    )
    minted = store.explicit_login("ft")
    generation = minted.artifact.generation_id

    later = NOW + timedelta(hours=24)
    clock["now"] = later
    reused = store.explicit_login("ft")

    assert reused.evidence.mode is AcquisitionMode.ARTIFACT_REUSE
    # A proof does not mint a generation; it only re-dates the one we hold.
    assert reused.artifact.generation_id == generation
    assert store.status("ft").last_verified_at == later
    assert adapter.calls == 1


def test_a_failed_redate_does_not_fail_a_proven_session(tmp_path: Path) -> None:
    """Recording the proof must not be able to invalidate the proof."""

    clock = {"now": NOW}
    adapter = FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = _store(
        tmp_path / "state",
        adapter=adapter,
        clock=lambda: clock["now"],
    )
    store.explicit_login("ft")

    def refuse(provider: str, account_key: str, stored: object) -> None:
        raise PersistenceError("state volume is full")

    clock["now"] = NOW + timedelta(hours=24)
    store._write = refuse  # type: ignore[method-assign]
    reused = store.explicit_login("ft")

    assert reused.evidence.mode is AcquisitionMode.ARTIFACT_REUSE
    assert adapter.calls == 1


def test_inconclusive_import_is_not_reported_as_a_transport_failure(
    tmp_path: Path,
) -> None:
    """The provider answered; the answer did not prove access.

    Reporting that as transport tells the caller to retry the network, which
    resolves nothing — a promoted Bloomberg session was retried twice against
    an identical `retryable: true` before anyone questioned the word
    (2026-07-28). This is the distinction the keeper's paid probe already
    draws, applied to the import path.
    """

    from newsclip.results import PublicErrorAction, PublicErrorCategory, public_error

    store = _store(tmp_path / "state")
    store._recipes["ft"] = InconclusiveRecipe()

    with pytest.raises(OperatorActionRequiredError) as raised:
        store.import_cookies("ft", _cookie_payload())

    envelope = public_error(raised.value)
    assert envelope is not None
    assert envelope.category is PublicErrorCategory.OPERATOR_ACTION
    assert envelope.reason is PublicErrorReason.IMPORT_VERIFICATION_INCONCLUSIVE
    assert envelope.retryable is False
    assert envelope.action is PublicErrorAction.HUMAN_ACCOUNT_CHECK


def test_an_inconclusive_import_still_preserves_the_prior_session(
    tmp_path: Path,
) -> None:
    """Changing the error class must not weaken the atomic import guarantee."""

    store = _store(tmp_path / "state")
    prior = store.import_cookies("ft", _cookie_payload("prior-valid"))
    store._recipes["ft"] = InconclusiveRecipe()

    with pytest.raises(OperatorActionRequiredError):
        store.import_cookies("ft", _cookie_payload("candidate"))

    assert store.get_valid_session("ft") == prior


def test_the_published_import_reason_matches_the_raised_text() -> None:
    """The classifier matches the exception text against the closed
    vocabulary, so a divergent copy would publish no reason at all rather
    than failing loudly."""

    from newsclip.sessions import _IMPORT_VERIFICATION_INCONCLUSIVE

    assert (
        PublicErrorReason.IMPORT_VERIFICATION_INCONCLUSIVE.value
        == _IMPORT_VERIFICATION_INCONCLUSIVE
    )


def _challenge_cookie(name: str) -> dict[str, object]:
    cookie = _cookie_payload("REPUTATION_TOKEN")[0].copy()
    cookie["name"] = name
    return cookie


def test_imported_challenge_vendor_cookies_are_dropped(tmp_path: Path) -> None:
    """Another host's defense cookies are worse than sending nothing.

    They attest that one particular address and fingerprint was found
    acceptable, so replaying them elsewhere is the exact mismatch the vendor
    looks for: importing a workstation's PerimeterX cookies onto the NAS made
    the verification page smaller than an anonymous fetch (2026-07-28).
    """

    store = _store(tmp_path / "state")
    payload = _cookie_payload("PUBLISHER_AUTH") + [
        _challenge_cookie("_px3"),
        _challenge_cookie("_pxhd"),
        _challenge_cookie("pxcts"),
    ]

    artifact = store.import_cookies("ft", payload)

    names = {cookie.name for cookie in artifact.cookies}
    assert names == {"FTSession_fixture"}


def test_an_import_of_only_defense_cookies_is_refused(tmp_path: Path) -> None:
    """Dropping everything must not persist an empty, useless session."""

    store = _store(tmp_path / "state")

    with pytest.raises(SessionCookiesMissing):
        store.import_cookies("ft", [_challenge_cookie("_px3")])


def test_a_stored_artifact_imports_directly(tmp_path: Path) -> None:
    """Promotion is one pipe because a stored session is itself the payload.

    `normalize_cookie_import` accepts the artifact envelope, so no export verb
    or hand-written extractor is needed — a claim worth pinning, since the
    one-command flow depends on it.
    """

    source = _store(tmp_path / "source")
    minted = source.import_cookies("ft", _cookie_payload("PUBLISHER_AUTH"))
    stored = json.loads(
        (tmp_path / "source" / "sessions" / "ft" / "default.json").read_text()
    )

    target = _store(tmp_path / "target")
    promoted = target.import_cookies("ft", stored)

    assert {c.name for c in promoted.cookies} == {c.name for c in minted.cookies}


def test_minting_keeps_this_host_own_defense_cookies(tmp_path: Path) -> None:
    """The drop is scoped to import. A mint normalizes through
    `normalize_browser_cookie_export`, where the cookies belong to this host
    and HTTP replay may still need them."""

    from newsclip.session_cookies import normalize_browser_cookie_export

    exported = normalize_browser_cookie_export(
        _cookie_payload("PUBLISHER_AUTH") + [_challenge_cookie("_px3")],
        allowed_domains=frozenset({"ft.com"}),
        now=NOW,
    )

    assert {cookie.name for cookie in exported} == {"FTSession_fixture", "_px3"}


def test_browser_verification_is_prepared_before_the_warm_probe(
    tmp_path: Path,
) -> None:
    """A provider that verifies through the browser needs the display first.

    The warm probe is cheap in requests but not in infrastructure: for a
    browser-transport provider it opens a browser itself. Preparing after it
    is too late, because the probe is the thing that dies — which is how this
    presented, as a bare transport failure from a verb that never said it
    wanted a browser.
    """

    root = tmp_path / "state"
    events: list[str] = []

    class _RecordingRecipe(FakeRecipe):
        def verify(self, client: object, artifact: object) -> object:
            events.append("verify")
            return super().verify(client, artifact)

    store = _store(
        root,
        recipe=_RecordingRecipe(),
        verification_requires_browser=lambda provider: True,
    )
    store.import_cookies("ft", _cookie_payload("warm-artifact"))
    # The import verifies as well; only the login's ordering is under test.
    events.clear()

    def prepare_browser() -> None:
        events.append("prepare")

    acquired = store.explicit_login(
        "ft",
        headless=True,
        before_browser=prepare_browser,
    )

    assert acquired.evidence.mode is AcquisitionMode.ARTIFACT_REUSE
    assert events[0] == "prepare"
    assert "verify" in events
    # Exactly once: the CLI's preparation re-execs the process, so preparing
    # again on the acquisition path would be a second re-exec.
    assert events.count("prepare") == 1


def test_browser_verification_prepares_only_once_when_the_warm_tier_misses(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    adapter = FakeAdapter(profile=root / "profiles/ft/default")
    preparations = 0

    def prepare_browser() -> None:
        nonlocal preparations
        preparations += 1

    store = _store(
        root,
        adapter=adapter,
        verification_requires_browser=lambda provider: True,
    )

    store.explicit_login("ft", headless=True, before_browser=prepare_browser)

    assert preparations == 1


def test_http_verification_still_defers_preparation_to_acquisition(
    tmp_path: Path,
) -> None:
    """The cheap path stays cheap for providers that verify over HTTP."""

    root = tmp_path / "state"
    store = _store(root, verification_requires_browser=lambda provider: False)
    store.import_cookies("ft", _cookie_payload("warm-artifact"))

    def unexpected_preparation() -> None:
        raise AssertionError("an HTTP verification must not prepare a browser")

    acquired = store.explicit_login(
        "ft",
        headless=True,
        before_browser=unexpected_preparation,
    )

    assert acquired.evidence.mode is AcquisitionMode.ARTIFACT_REUSE


@pytest.mark.parametrize(
    "reason", ["http_server_error", "http_rate_limited", "article_identity_mismatch"]
)
def test_warm_verification_preserves_provider_failure_reason(tmp_path, reason):
    class FailedProbe(FakeRecipe):
        def verify(self, http, artifact):
            return SessionVerification(
                verified=False,
                access_state=AccessState.UNKNOWN,
                reason=reason,
                verified_at=NOW,
            )

    store = _store(tmp_path)
    artifact = store.import_cookies("ft", _cookie_payload())
    store._recipes["ft"] = FailedProbe()
    with pytest.raises(ProviderTransportError, match=f"^paid_probe_{reason}$"):
        store.explicit_login("ft", allow_credential_mint=False)
    assert store.get_valid_session("ft") == artifact


def test_changed_browser_authority_is_recovered_without_credentials(tmp_path):
    recipe = BrowserPaidRecipe()
    adapter = FakeAdapter(
        profile=tmp_path / "profile",
        rehydrate_artifact=_artifact("current-browser-authority"),
        candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
    )

    def verify_profile(selected_recipe, artifact):
        return (
            selected_recipe.verify_fetch(_verification_fetch()),
            _artifact("current-browser-authority").cookies,
        )

    store = _store(
        tmp_path / "state",
        adapter=adapter,
        recipe=recipe,
        profile_verifier=verify_profile,
        verification_requires_browser=lambda _: True,
    )
    prior = store.import_cookies("ft", _cookie_payload("old-portable-authority"))

    class ChangedProfile(BrowserPaidRecipe):
        def verify(self, http, artifact):
            pytest.fail("warm authority must use the scoped profile verifier")

    store._recipes["ft"] = ChangedProfile()
    result = store.explicit_login("ft", allow_credential_mint=False)
    assert result.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert result.artifact.cookies[0].value == "current-browser-authority"
    assert result.artifact.browser_profile_id == prior.browser_profile_id
    assert result.artifact.generation_id != prior.generation_id
    assert adapter.calls == 0
    assert adapter.rehydrate_calls == 0
    assert store.get_valid_session("ft") == result.artifact


def test_teaser_verification_is_still_inconclusive(tmp_path):
    class Teaser(FakeRecipe):
        def verify(self, http, artifact):
            return SessionVerification(
                verified=False,
                access_state=AccessState.TEASER,
                reason="paywall_teaser",
                verified_at=NOW,
            )

    store = _store(tmp_path)
    prior = store.import_cookies("ft", _cookie_payload())
    store._recipes["ft"] = Teaser()
    with pytest.raises(ProviderTransportError, match="^paid_probe_inconclusive$"):
        store.explicit_login("ft", allow_credential_mint=False)
    assert store.get_valid_session("ft") == prior
