"""OIDC connections UI; publisher authority stays in each user's session store."""

from __future__ import annotations

import collections
import html
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from account_connections.ui import action_form
from signin_window.connections import disconnect_confirmation
from signin_window.connections import page as connection_page
from signin_window.oidc import BrowserAuth, OIDCConfig
from signin_window.page import PageText
from signin_window.relay import AttemptContext, Link, LinkLimited, Relay
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .connection_controls import ConnectionControls
from .connections_ui import (
    CONNECTIONS_STYLE,
    describe_access,
    render_avatar,
    render_check_banner,
    render_meta,
    render_overview,
    render_pill,
    render_topbar,
)
from .connections_ui import (
    PUBLISHER_NAMES as _PUBLISHER_NAMES,
)
from .errors import (
    AccountAlertError,
    NewsclipError,
    ProviderTransportError,
    SessionRequiredError,
    UsageError,
)
from .models import SessionHealth, SessionStatus
from .sessions import ServingSessions, SessionStore
from .subscription_access import SubscriptionAccess
from .tenancy import application_root, load_users, user_scope
from .ui import renderer_options

FRESH_SECONDS = (
    300  # Share and disconnect need an identity-provider confirmation at most this old
)
_CHECK_COOLDOWN_SECONDS = 15.0
_CHECK_TTL_SECONDS = 600.0


class _ReservedRelay(Relay):
    """Relay with binding pre-teardown slot reservation so 429 keeps live windows."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.RLock()
        self._reserved_slots = 0

    def reserve_slot(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            made = self._made.setdefault(key, collections.deque())
            while made and now - made[0] > 3600:
                made.popleft()
            if len(made) >= self.links_per_hour:
                return False
            self._expire(now)
            if len(self._retired) + self._reserved_slots >= self.max_links:
                return False
            self._reserved_slots += 1
            return True

    def release_slot(self) -> None:
        with self._lock:
            if self._reserved_slots > 0:
                self._reserved_slots -= 1

    def create(
        self,
        key: str,
        *,
        params: dict | None = None,
        label: str | None = None,
        context: AttemptContext | None = None,
        reserved: bool = False,
    ) -> Link:
        if self._authorize is not None and (context is None or not context.owner):
            raise ValueError("authenticated links require a host-assigned owner")
        to_retire: list[Link] = []
        with self._lock:
            if reserved and self._reserved_slots > 0:
                self._reserved_slots -= 1
            now = self._clock()
            made = self._made.setdefault(key, collections.deque())
            while made and now - made[0] > 3600:
                made.popleft()
            if len(made) >= self.links_per_hour:
                raise LinkLimited(key)
            self._expire(now)
            if (
                not reserved
                and len(self._retired) + self._reserved_slots >= self.max_links
            ):
                raise LinkLimited(key)
            made.append(now)
            for old in [item for item in self._links.values() if item.key == key]:
                self._links.pop(old.id, None)
                old.closed = True
                old.view_token = None
                if old.window_id is not None:
                    self._track_retired_locked(old)
                    if old.state != "saving":
                        to_retire.append(old)
            while len(self._links) >= self.max_links:
                oldest = self._links.pop(
                    min(self._links.values(), key=lambda item: item.created).id
                )
                oldest.closed = True
                oldest.view_token = None
                if oldest.window_id is not None:
                    self._track_retired_locked(oldest)
                    if oldest.state != "saving":
                        to_retire.append(oldest)
            link_id = secrets.token_urlsafe(24)
            link = Link(
                link_id,
                key,
                now,
                now + self.link_ttl,
                f"{self.public_url}/{link_id}",
                dict(params or {}),
                key if label is None else label,
            )
            link.context = context
            self._links[link.id] = link
        for old in to_retire:
            threading.Thread(target=self._retire, args=(old,), daemon=True).start()
        return link


@dataclass(frozen=True)
class ConnectionsConfig:
    oidc: OIDCConfig
    claim: str | None
    bindings: dict

    @classmethod
    def from_env(cls, origin, env=None):
        env = os.environ if env is None else env
        try:
            issuer = env["NEWSCLIP_CONNECTIONS_ISSUER"].rstrip("/")
            claim = env.get("NEWSCLIP_CONNECTIONS_ACCOUNT_CLAIM")
            bindings_file = env.get("NEWSCLIP_CONNECTIONS_BINDINGS_FILE")
            if bool(claim) == bool(bindings_file):
                raise ValueError("choose a signed claim or subject bindings")
            bindings = (
                json.loads(Path(bindings_file).read_text()) if bindings_file else {}
            )
            if not isinstance(bindings, dict) or (
                bindings_file and not bindings.get(issuer)
            ):
                raise ValueError("issuer-scoped subject bindings")
            for fixed_issuer, subjects in bindings.items():
                if fixed_issuer != issuer or not isinstance(subjects, dict):
                    raise ValueError("issuer-scoped subject bindings")
                if any(
                    not isinstance(subject, str)
                    or not subject
                    or not isinstance(user, str)
                    for subject, user in subjects.items()
                ):
                    raise ValueError("subject bindings")
            secret = None
            if env.get("NEWSCLIP_CONNECTIONS_CLIENT_SECRET_FILE"):
                fd = os.open(
                    env["NEWSCLIP_CONNECTIONS_CLIENT_SECRET_FILE"],
                    os.O_RDONLY | os.O_NOFOLLOW,
                )
                with os.fdopen(fd) as stream:
                    info = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_mode & 0o077
                        or info.st_uid != os.getuid()
                    ):
                        raise ValueError("private client credential")
                    secret = stream.read(8193).strip()
                if not secret or len(secret) > 8192:
                    raise ValueError("client credential")
            group = env["NEWSCLIP_CONNECTIONS_GROUP"]
            if not group:
                raise ValueError("group")
            config = OIDCConfig(
                issuer=issuer,
                client_id=env["NEWSCLIP_CONNECTIONS_CLIENT_ID"],
                public_url=origin,
                state_dir=application_root("NEWSCLIP_STATE_HOME", ".local/state")
                / "connections-browser",
                cookie_name="__Host-newsclip-connections",
                required_group=group,
                claim_names=(claim,) if claim else (),
                client_secret=secret,
            )
            return cls(config, claim, bindings)
        except (KeyError, ValueError, OSError):
            raise ValueError(
                "Configure Newsclip connections OIDC and user identity bindings."
            ) from None


class Connections:
    def __init__(self, config, users_path, *, transport=None, clock=time.time):
        self.config, self.users_path, self.clock = config, users_path, clock
        self.auth = BrowserAuth(
            config.oidc,
            transport=transport,
            clock=clock,
            **renderer_options(BrowserAuth),
        )
        self.home = urlsplit(config.oidc.public_url).path.rstrip("/") + "/connections/"
        self.relays, self.adapters, self.controls, self.links = {}, {}, {}, {}
        self.access: SubscriptionAccess | None = None
        self._start_locks: dict[tuple[str, str], threading.Lock] = {}
        self._start_locks_guard = threading.Lock()
        self._pending_close: dict[tuple[str, str], list[Link]] = {}
        self._known_links: dict[tuple[str, str], dict[str, Link]] = {}
        self._draining: set[tuple[str, str]] = set()
        self._checks: dict[tuple[str, str], dict[str, Any]] = {}
        self._checks_lock = threading.Lock()
        self._check_threads: list[threading.Thread] = []

    @staticmethod
    def _link_still_open(link: Link) -> bool:
        with link.lock:
            return (
                link.window_id is not None
                or link.closing
                or link.state in ("starting", "waiting", "saving")
            )

    @staticmethod
    def _is_already_completed_idle(link: Link) -> bool:
        if not link.lock.acquire(blocking=False):
            return False
        try:
            return (
                link.window_id is None
                and not link.closing
                and link.state == "connected"
            )
        finally:
            link.lock.release()

    def _cancel_and_check(self, user: str, link: Link) -> tuple[bool, bool]:
        self.relays[user].cancel(link)
        with link.lock:
            still_open = (
                link.window_id is not None
                or link.closing
                or link.state in ("starting", "waiting", "saving")
            )
            completed = link.state == "connected"
            return still_open, completed

    def _snapshot_links(
        self, user: str, provider: str
    ) -> tuple[list[Link], set[str], set[str]]:
        relay = self.relays[user]
        seen: dict[str, Link] = {}
        known = self._known_links.get((user, provider))
        if known:
            for link_id, link in list(known.items()):
                if link.key == provider:
                    seen[link_id] = link
        for link in relay.links(provider):
            if link.key == provider:
                seen[link.id] = link
        with relay._lock:
            for link in relay._retired.values():
                if link.key == provider:
                    seen[link.id] = link
            active_relay_ids = {
                link_id
                for link_id, link in relay._links.items()
                if link.key == provider
            }
            live_ids = set(relay._links) | set(relay._retired)
        already_completed: set[str] = set()
        for link_id, link in list(seen.items()):
            if link.lock.acquire(blocking=False):
                try:
                    still_open = (
                        link.window_id is not None
                        or link.closing
                        or link.state in ("starting", "waiting", "saving")
                    )
                    if not still_open and link.state == "connected":
                        already_completed.add(link_id)
                finally:
                    link.lock.release()
                if known and link_id not in live_ids and not still_open:
                    known.pop(link_id, None)
        return list(seen.values()), already_completed, active_relay_ids

    def _provider_links(self, user: str, provider: str) -> list[Link]:
        links, _, _ = self._snapshot_links(user, provider)
        return links

    def _start_lock(self, user: str, provider: str) -> threading.Lock:
        with self._start_locks_guard:
            lock = self._start_locks.get((user, provider))
            if lock is None:
                lock = threading.Lock()
                self._start_locks[(user, provider)] = lock
            return lock

    def user(self, request):
        identity = self.auth.identity(request)
        if not identity:
            return None
        name = (
            identity["claims"].get(self.config.claim)
            if self.config.claim
            else self.config.bindings.get(identity["issuer"], {}).get(identity["sub"])
        )
        try:
            registered = {user.id for user in load_users(self.users_path)}
        except (OSError, ValueError):
            return None
        return name if isinstance(name, str) and name in registered else None

    def register(self, user, adapter, backend, origin):
        with user_scope(user.id):
            root = application_root("NEWSCLIP_STATE_HOME", ".local/state")
        controls = ConnectionControls(root)
        self.controls[user.id], self.adapters[user.id] = controls, adapter
        store = self._store(user.id)
        if store is not None and store.root.resolve() != root.resolve():
            raise ValueError("reader and connections must use the same user state root")

        async def authorize(request, link, operation):
            return bool(
                self.user(request) == user.id
                and link.context
                and link.context.owner == user.id
                and not link.closed
                and (user.id, link.key) not in self._draining
                and controls.current(link.key, "default", link.context.target)
            )

        def before_start(link):
            return (
                None
                if link.context
                and controls.current(link.key, "default", link.context.target)
                else "cancelled"
            )

        def ended(link, result):
            if result.get("state") == "connected":
                return "connected"
            if link.context:
                controls.cancel(link.key, "default", link.context.target)
            return "cancelled" if result.get("state") == "cancelled" else "failed"

        relay = _ReservedRelay(
            backend,
            f"{origin}/users/{user.id}/connect",
            text=PageText(
                service="Newsclip",
                title="Connect {label} to Newsclip",
                notice=(
                    "Use your password or email code — device passkeys aren't "
                    "available in this remote window."
                ),
                help_html=(
                    "Sign in on {label}'s own page below, using your password or "
                    "email code. On a phone or tablet, tap Paste, Keyboard, or Zoom "
                    "in the toolbar above; on a desktop, paste with Ctrl+V or Cmd+V."
                ),
                intro_html=(
                    "This connects your <b>{label}</b> subscription to Newsclip. "
                    "Choose the publisher account you intend to use."
                ),
                button="Continue to {label}'s sign-in",
                reconnect=True,
                # Every link is bound to the signed-in owner who just pressed Connect
                # (authorize refuses any other), so the window opens at once.
                auto_start=True,
                return_url=self.home,
                **renderer_options(PageText),
            ),
            authorize=authorize,
            before_start=before_start,
            on_ended=ended,
        )
        self.relays[user.id] = relay
        return relay

    def viewer_routes(self, user, prefix="/connect"):
        relay = self.relays[user]

        async def cancel(request):
            link = relay.find(
                request.path_params["id"],
                request.client.host if request.client else "unknown",
            )
            if not (
                isinstance(link, Link)
                and self.auth.origin_ok(request)
                and self.user(request) == user
                and link.context
                and link.context.owner == user
                and not link.closed
                and (user, link.key) not in self._draining
                and self.controls[user].current(
                    link.key, "default", link.context.target
                )
            ):
                return Response(status_code=404)
            for_restart = False
            content_type = (
                (request.headers.get("content-type") or "")
                .split(";")[0]
                .strip()
                .lower()
            )
            if content_type == "application/json":
                try:
                    payload = await request.json()
                except ValueError:
                    payload = {}
                for_restart = isinstance(payload, dict) and bool(
                    payload.get("for_restart")
                )
            if for_restart:
                await self.adapters[user].dispatcher.run(
                    lambda: relay.cancel(link, for_restart=True)
                )
                data = link.public()
                if link.state in ("starting", "waiting"):
                    data["can_restart"] = link.starts < relay.max_starts
                    if link.viewer_revoked:
                        data["closing"] = True
                return JSONResponse(data, headers={"Cache-Control": "no-store"})
            self.controls[user].cancel(link.key, "default", link.context.target)
            await self.adapters[user].dispatcher.run(lambda: relay.cancel(link))
            return Response(status_code=204, headers={"Cache-Control": "no-store"})

        return [
            route
            for route in relay.routes(prefix)
            if getattr(route, "path", "") != prefix + "/{id}/cancel"
        ] + [Route(prefix + "/{id}/cancel", cancel, methods=["POST"])]

    def connection(self, user, provider, *, replace=None):
        selected = self.adapters[user]._service_ready()._registry.get(provider)
        if selected.login_recipe is None:
            raise UsageError("this provider does not require sign-in")
        with self._start_lock(user, provider):
            still_open: list[Link] = []
            pending_completed = False
            for held in self._pending_close.get((user, provider), ()):
                open_now, done_now = self._cancel_and_check(user, held)
                if open_now:
                    still_open.append(held)
                if done_now:
                    pending_completed = True
            if still_open:
                self._pending_close[user, provider] = still_open
                raise UsageError(
                    "The previous sign-in window is still closing. "
                    "Wait a moment and try again."
                )
            self._pending_close.pop((user, provider), None)
            if pending_completed:
                raise UsageError(
                    "Your previous sign-in just completed. "
                    "Return to Connections to check its status."
                )
            # Verify controls are readable before retiring any working relay link.
            current = self.controls[user].status(provider)
            if current["phase"] == 2:
                raise UsageError("Finish disconnecting before starting a new sign-in.")
            slot_reserved = False
            link: Link | None = None
            committed = False
            draining_entered = False
            try:
                now = self.clock()
                current_link = self.links.get((user, provider))
                if replace is not None:
                    with self.relays[user]._lock:
                        pre_target = self.relays[user]._links.get(replace)
                    if (
                        pre_target is None
                        or current_link is None
                        or current_link.id != replace
                        or pre_target.key != provider
                        or pre_target.closed
                        or pre_target.expires <= now
                        or pre_target.context is None
                        or not self.controls[user].current(
                            provider, "default", pre_target.context.target
                        )
                        or pre_target.state
                        not in ("ready", "starting", "waiting", "cancelled")
                    ):
                        raise UsageError(
                            "This sign-in attempt is no longer active. "
                            "Return to Connections to check its status."
                        )
                else:
                    with self.relays[user]._lock:
                        live_links = [
                            item
                            for item in self.relays[user]._links.values()
                            if item.key == provider
                        ]
                    if any(
                        not item.closed
                        and item.expires > now
                        and item.context is not None
                        and self.controls[user].current(
                            provider, "default", item.context.target
                        )
                        and item.state
                        in ("ready", "starting", "waiting", "saving", "cancelled")
                        for item in live_links
                    ):
                        raise UsageError(
                            "A sign-in attempt is already open. "
                            "Return to Connections to continue or replace it."
                        )
                if not self.relays[user].reserve_slot(provider):
                    raise LinkLimited(provider)
                slot_reserved = True
                self._draining.add((user, provider))
                draining_entered = True
                previous, already_completed, active_relay_ids = self._snapshot_links(
                    user, provider
                )
                now = self.clock()

                def is_active_attempt(item: Link) -> bool:
                    return (
                        item.id in active_relay_ids
                        and not item.closed
                        and item.expires > now
                        and item.id not in already_completed
                        and item.context is not None
                        and self.controls[user].current(
                            provider, "default", item.context.target
                        )
                        and item.state
                        in ("ready", "starting", "waiting", "saving", "cancelled")
                    )

                if replace is not None:
                    target_link = next(
                        (old for old in previous if old.id == replace), None
                    )
                    if (
                        target_link is None
                        or current_link is None
                        or current_link.id != replace
                        or target_link.id not in active_relay_ids
                        or target_link.closed
                        or target_link.expires <= now
                        or target_link.id in already_completed
                        or target_link.context is None
                        or not self.controls[user].current(
                            provider, "default", target_link.context.target
                        )
                        or target_link.state
                        not in ("ready", "starting", "waiting", "cancelled")
                    ):
                        raise UsageError(
                            "This sign-in attempt is no longer active. "
                            "Return to Connections to check its status."
                        )
                    already_completed.discard(replace)
                elif any(is_active_attempt(old) for old in previous):
                    raise UsageError(
                        "A sign-in attempt is already open. "
                        "Return to Connections to continue or replace it."
                    )
                if any(old.state == "saving" for old in previous):
                    raise UsageError(
                        "A previous sign-in is still finishing. "
                        "Wait a moment and try again."
                    )
                for old in previous:
                    old.closed = True
                completed = False
                for old in previous:
                    open_now, done_now = self._cancel_and_check(user, old)
                    if open_now:
                        still_open.append(old)
                    if done_now and old.id not in already_completed:
                        completed = True
                if still_open:
                    self._pending_close[user, provider] = still_open
                    raise UsageError(
                        "The previous sign-in window is still closing. "
                        "Wait a moment and try again."
                    )
                if completed:
                    raise UsageError(
                        "Your previous sign-in just completed. "
                        "Return to Connections to check its status."
                    )
                slot_reserved = False
                link = self.relays[user].create(
                    provider,
                    params={
                        "user": user,
                        "provider": provider,
                        "account_key": "default",
                        "connection_revision": "",
                    },
                    label=_PUBLISHER_NAMES.get(provider, provider),
                    context=AttemptContext(owner=user, target=""),
                    reserved=True,
                )
                self._known_links.setdefault((user, provider), {})[link.id] = link
                revision = self.controls[user].begin(provider)
                link.params["connection_revision"] = revision
                link.context = AttemptContext(owner=user, target=revision)
                self.links[user, provider] = link
                committed = True
                return link
            finally:
                if slot_reserved:
                    self.relays[user].release_slot()
                if link is not None and not committed:
                    link.closed = True
                    if (user, provider) in self._known_links:
                        self._known_links[user, provider].pop(link.id, None)
                if draining_entered:
                    self._draining.discard((user, provider))

    def request(self, user, provider):
        """Requesting an owner page never pauses or supersedes a connection."""
        selected = self.adapters[user]._service_ready()._registry.get(provider)
        if selected.login_recipe is None:
            raise UsageError("this provider does not require sign-in")
        return self.config.oidc.public_url.rstrip("/") + "/connections/#" + provider

    def _store(self, user):
        source = self.adapters[user]._service_ready()._sessions
        store = source._store if isinstance(source, ServingSessions) else source
        return store if isinstance(store, SessionStore) else None

    def _own_health(self, service, store, provider: str) -> SessionHealth | None:
        own_status = getattr(service, "own_session_status", None)
        if callable(own_status):
            try:
                return own_status(provider)
            except (NewsclipError, OSError, ValueError):
                pass
        return store.status(provider) if store else None

    def _owner_access_summary(
        self, owner: str, provider: str
    ) -> tuple[str, str, str] | None:
        """Return safe (access_status, badge_label, tone) for a shared owner's provider.

        Never exposes private incident IDs, diagnostic IDs or recovery details.
        """
        adapter = self.adapters.get(owner)
        controls = self.controls.get(owner)
        if adapter is None or controls is None:
            return None
        try:
            control = controls.status(provider)
            if control["phase"] == 2:
                return ("in_progress", "Disconnecting", "warn")
            if control["phase"]:
                return ("disconnected", "Owner disconnected", "bad")
            service = adapter._service_ready()
            store = self._store(owner)
            health = self._own_health(service, store, provider)
        except (NewsclipError, OSError, ValueError):
            return ("unavailable", "Unavailable", "bad")
        if health is None or health.status is not SessionStatus.VERIFIED:
            if health is not None and health.status is SessionStatus.OPERATOR_ACTION:
                return ("action_required", "Needs owner reconnect", "bad")
            if health is not None and health.status is SessionStatus.COOLDOWN:
                return ("cooldown", "Paused", "warn")
            return ("not_connected", "Not connected", "muted")
        access_status, label, tone, _ = describe_access(
            state="connected",
            health=health.model_copy(
                update={
                    "renewal_incident_id": None,
                    "renewal_diagnostic_id": None,
                    "recovery": None,
                }
            ),
            detail="",
        )
        return (access_status, label, tone)

    def _current_check(
        self, user: str, provider: str, revision: str | None
    ) -> dict[str, Any] | None:
        now = self.clock()
        with self._checks_lock:
            record = self._checks.get((user, provider))
            if record is None:
                return None
            if revision is not None and record.get("revision") != revision:
                self._checks.pop((user, provider), None)
                return None
            if record.get("state") != "checking":
                finished = record.get("finished_at")
                if (
                    isinstance(finished, int | float)
                    and now - finished > _CHECK_TTL_SECONDS
                ):
                    self._checks.pop((user, provider), None)
                    return None
            return {
                "state": record["state"],
                "checked_at": record.get("checked_at"),
                "detail": record["detail"],
            }

    def start_check(self, user: str, provider: str) -> bool:
        """Start a bounded background live verification for the user's own session."""
        service = self.adapters[user]._service_ready()
        selected = service._registry.get(provider)
        if selected.login_recipe is None:
            raise UsageError("this provider does not require sign-in")
        control = self.controls[user].status(provider)
        if control["phase"] != 0:
            return False
        revision = control["revision"]
        now = self.clock()
        with self._checks_lock:
            existing = self._checks.get((user, provider))
            if existing is not None and existing.get("revision") == revision:
                if existing.get("state") == "checking":
                    return False
                finished = existing.get("finished_at")
                if (
                    isinstance(finished, int | float)
                    and now - finished < _CHECK_COOLDOWN_SECONDS
                ):
                    return False
            self._checks[user, provider] = {
                "state": "checking",
                "revision": revision,
                "started_at": now,
                "finished_at": None,
                "checked_at": None,
                "detail": "Running a live subscription check against the publisher…",
            }
            self._check_threads = [t for t in self._check_threads if t.is_alive()]

        def run_check() -> None:
            checked_at = datetime.fromtimestamp(self.clock(), UTC).isoformat()
            try:
                service.session_checkpoint(provider)
            except SessionRequiredError:
                result_state = "failed"
                result_detail = (
                    "Live check failed — sign-in is no longer valid. "
                    "Reconnect to restore access."
                )
            except AccountAlertError:
                result_state = "failed"
                result_detail = (
                    "Publisher reported an account alert — sign in directly "
                    "on the publisher site, then reconnect."
                )
            except ProviderTransportError:
                result_state = "inconclusive"
                result_detail = (
                    "Live check was inconclusive due to a temporary publisher or "
                    "network issue. Your saved connection was kept."
                )
            except (NewsclipError, OSError, ValueError):
                result_state = "inconclusive"
                result_detail = (
                    "Live check could not finish right now. "
                    "Your saved connection was kept."
                )
            else:
                result_state = "passed"
                result_detail = "Live check passed — subscription access is working."
            finished_at = self.clock()
            with self._checks_lock:
                current = self._checks.get((user, provider))
                if current is not None and current.get("revision") == revision:
                    self._checks[user, provider] = {
                        "state": result_state,
                        "revision": revision,
                        "started_at": now,
                        "finished_at": finished_at,
                        "checked_at": checked_at,
                        "detail": result_detail,
                    }

        thread = threading.Thread(
            target=run_check,
            name=f"newsclip-check-{user}-{provider}",
            daemon=True,
        )
        with self._checks_lock:
            self._check_threads.append(thread)
        thread.start()
        return True

    def wait_checks(self, timeout: float = 10.0) -> None:
        """Wait for any in-flight live checks to finish (primarily for tests)."""
        deadline = time.monotonic() + timeout
        with self._checks_lock:
            threads = list(self._check_threads)
        for thread in threads:
            remaining = max(0.0, deadline - time.monotonic())
            thread.join(timeout=remaining)

    def statuses(self, user, *, include_replace: bool = False):
        service = self.adapters[user]._service_ready()
        store = self._store(user)
        if (
            store is not None
            and store.root.resolve() != self.controls[user].root.parent.resolve()
        ):
            raise ValueError("reader and connections must use the same user state root")
        items = []
        for selected in service._registry:
            if selected.login_recipe is None:
                continue
            provider = selected.key
            try:
                control = self.controls[user].status(provider)
                link = self.links.get((user, provider))
                health = self._own_health(service, store, provider)
            except (NewsclipError, OSError, ValueError):
                detail = (
                    "Connection state is unavailable. "
                    "Ask your administrator to recover this record."
                )
                items.append(
                    {
                        "provider": provider,
                        "name": _PUBLISHER_NAMES.get(provider, provider),
                        "revision": None,
                        "state": "unavailable",
                        "detail": detail,
                        "access_status": "unavailable",
                        "access_label": "Unavailable",
                        "access_tone": "bad",
                        "access_detail": detail,
                        "health": None,
                        "verified_age_seconds": None,
                        "consecutive_renewal_failures": None,
                        "last_verified": None,
                        "last_check": None,
                        "url": None,
                    }
                )
                continue
            link_live = bool(
                (user, provider) not in self._draining
                and link
                and not link.closed
                and link.expires > self.clock()
                and link.context
                and link.context.target == control["revision"]
                and self.controls[user].current(
                    provider, "default", link.context.target
                )
                and link.state in ("ready", "starting", "waiting", "saving")
            )
            layout = getattr(link, "layout", "") if link_live and link else ""
            if control["phase"] == 2:
                state, detail = (
                    "disconnecting",
                    "Access stopped. Finish disconnecting to remove the saved sign-in.",
                )
            elif link_live and link and link.state == "saving":
                state, detail = (
                    "saving",
                    "Saving connection.",
                )
            elif link_live:
                view_note = (
                    " (mobile view)"
                    if layout == "phone"
                    else " (desktop view)"
                    if layout == "desktop"
                    else ""
                )
                state, detail = (
                    "connecting",
                    f"Sign-in is in progress{view_note}. "
                    "Continue the sign-in you already started.",
                )
            elif control.get("human_until", 0) > self.clock():
                state, detail = (
                    "recovering",
                    "Your sign-in may still be finishing. Check its status, "
                    "or cancel it before starting again.",
                )
            elif control["phase"]:
                state, detail = (
                    "disconnected",
                    "Disconnected. Connect this subscription to use it again.",
                )
            elif health and health.status is SessionStatus.VERIFIED:
                state, detail = (
                    "connected",
                    "Connection saved. Access to each article is checked separately.",
                )
            else:
                state, detail = (
                    "needs_signin",
                    "Connect the subscription you want to use.",
                )
            check = self._current_check(user, provider, control["revision"])
            access_status, access_label, access_tone, access_detail = describe_access(
                state=state,
                health=health,
                check=check,
                detail=detail,
            )
            rec_replace = None
            if (
                include_replace
                and state == "recovering"
                and link is not None
                and not link.closed
                and link.expires > self.clock()
                and link.state == "cancelled"
                and link.context is not None
                and link.context.target == control["revision"]
                and self.controls[user].current(
                    provider, "default", link.context.target
                )
            ):
                with self.relays[user]._lock:
                    if link.id in self.relays[user]._links:
                        rec_replace = link.id
            items.append(
                {
                    "provider": provider,
                    "name": _PUBLISHER_NAMES.get(provider, provider),
                    "revision": control["revision"],
                    "state": state,
                    "detail": detail,
                    "access_status": access_status,
                    "access_label": access_label,
                    "access_tone": access_tone,
                    "access_detail": access_detail,
                    "health": health.health.value
                    if health and health.health is not None
                    else None,
                    "verified_age_seconds": health.verified_age_seconds
                    if health
                    else None,
                    "consecutive_renewal_failures": health.consecutive_renewal_failures
                    if health
                    else None,
                    "last_verified": health.last_verified_at.isoformat()
                    if health and health.last_verified_at
                    else None,
                    "last_check": check,
                    "url": link.url if state == "connecting" and link else None,
                    **({"layout": layout} if state in ("connecting", "saving") else {}),
                    **({"_replace": rec_replace} if include_replace else {}),
                }
            )
        return items

    def page(self, body, *, refresh=False):
        return connection_page(
            "News subscriptions",
            body,
            refresh=refresh,
            login_url=self.home + "login",
            **renderer_options(connection_page),
        )

    def form(self, action, provider, text, *, revision=None, replace=None):
        fence = (
            f'<input type="hidden" name="revision" value="{html.escape(revision)}">'
            if action in ("cancel", "disconnect")
            else ""
        )
        if replace is not None and action == "start":
            fence += (
                f'<input type="hidden" name="replace" value="{html.escape(replace)}">'
            )
        kind = (
            "danger"
            if action == "disconnect"
            else "quiet"
            if action == "cancel"
            else "secondary"
            if action == "check" or text in ("Reconnect", "Start new sign-in")
            else "primary"
        )
        form = (
            f'<form method="post" action="{self.home}{action}">'
            '<input type="hidden" name="provider" '
            f'value="{html.escape(provider)}">{fence}'
            f'<button class="{kind}">{html.escape(text)}</button></form>'
        )
        if action == "disconnect" and text.startswith("Disconnect"):
            return disconnect_confirmation(
                form,
                "this subscription",
                "This stops this application from using this publisher sign-in. "
                "This also stops people using your shared sign-in until you reconnect. "
                "It does not cancel your subscription "
                "or delete anyone's saved articles.",
            )
        return form

    async def index(self, request):
        identity = self.auth.identity(request)
        if not identity:
            return RedirectResponse(self.home + "login", status_code=303)
        user = self.user(request)
        if user is None:
            return HTMLResponse(
                self.page(
                    "<p>This sign-in cannot manage a Newsclip subscription. "
                    "Sign in with another account, "
                    "or ask your administrator to check access.</p>"
                    f'<form method=post action="{self.home}logout">'
                    "<button class=quiet>Sign out of Connections</button></form>"
                ),
                status_code=403,
            )

        def load_index():
            loaded_statuses = self.statuses(user, include_replace=True)
            sharing_snapshots = None
            sharing_members = None
            sharing_failed = False
            shared_health: dict[tuple[str, str], tuple[str, str, str] | None] = {}
            if self.access is not None:
                try:
                    sharing_snapshots, sharing_members = self.access.view_all(
                        user, [item["provider"] for item in loaded_statuses]
                    )
                    for item in loaded_statuses:
                        provider = item["provider"]
                        snap = sharing_snapshots.get(provider)
                        if snap is None:
                            continue
                        row, offered, _, _ = snap
                        owners = {owner for owner, _ in offered}
                        selected = row["selection"]
                        if selected and selected["owner"] != user:
                            owners.add(selected["owner"])
                        for owner in owners:
                            shared_health[owner, provider] = self._owner_access_summary(
                                owner, provider
                            )
                except (NewsclipError, OSError, ValueError):
                    sharing_failed = True
            return (
                loaded_statuses,
                sharing_snapshots,
                sharing_members,
                sharing_failed,
                shared_health,
            )

        (
            statuses,
            sharing_snapshots,
            sharing_members,
            sharing_failed,
            shared_health,
        ) = await self.adapters[user].dispatcher.run(load_index)

        effective_tones: list[str] = []
        cards: list[str] = []
        any_checking = False
        any_checkable = False

        for status in statuses:
            provider, state = status["provider"], status["state"]
            is_checking = status["access_status"] == "checking"
            if is_checking:
                any_checking = True
            if state == "connected":
                any_checkable = True

            card_label = status["access_label"]
            card_tone = status["access_tone"]
            card_detail = status["access_detail"]
            callout_tone = status["access_tone"]
            source_label: str | None = None
            using_shared = False

            if (
                self.access is not None
                and not sharing_failed
                and sharing_snapshots is not None
                and provider in sharing_snapshots
            ):
                row, _, _, admitted_ok = sharing_snapshots[provider]
                selected = row["selection"]
                if selected and selected["owner"] != user:
                    using_shared = True
                    owner = selected["owner"]
                    if admitted_ok is False:
                        card_label, card_tone = "Access removed", "bad"
                        callout_tone = "bad"
                        card_detail = (
                            f"Shared access from {owner} was removed or changed. "
                            "Choose another subscription below or connect your own."
                        )
                        source_label = f"Selected: {owner}'s subscription (removed)"
                    else:
                        owner_info = shared_health.get((owner, provider))
                        if owner_info is not None:
                            _, o_label, o_tone = owner_info
                            card_label, card_tone = o_label, o_tone
                            source_label = f"Using {owner}'s subscription ({o_label})"
                            if state == "needs_signin":
                                callout_tone = o_tone
                                if o_tone == "ok":
                                    card_detail = (
                                        f"Using {owner}'s subscription — "
                                        "access is working. You can also "
                                        "connect your own subscription below."
                                    )
                                else:
                                    card_detail = (
                                        f"{owner}'s shared subscription status "
                                        f"is {o_label}. You can also connect "
                                        "your own subscription below."
                                    )
                        else:
                            source_label = f"Using {owner}'s subscription"
                elif selected and selected["owner"] == user:
                    source_label = "Active source: Your subscription"
                else:
                    source_label = "Active source: None selected"

            last_check = status.get("last_check")
            show_check_banner = last_check
            if (
                last_check
                and last_check.get("state") == "passed"
                and status["access_status"] == "working"
                and not using_shared
            ):
                card_detail = str(last_check["detail"])
                show_check_banner = None

            effective_tones.append(card_tone)
            pulse = is_checking or state in ("connecting", "saving")
            role = "alert" if state == "unavailable" or card_tone == "bad" else "status"
            subtitle = (
                f'<p class="nc-pub-sub">{html.escape(source_label)}</p>'
                if source_label and using_shared
                else ""
            )

            tone_attr = html.escape(card_tone, quote=True)
            callout_attr = html.escape(callout_tone, quote=True)
            card_parts = [
                f'<article class="nc-card nc-tone-{tone_attr}" '
                f'id="{html.escape(provider, quote=True)}">',
                '<div class="nc-card-head">',
                '<div class="nc-pub">',
                render_avatar(provider),
                f'<div><h2 class="nc-pub-title">{html.escape(status["name"])}</h2>'
                f"{subtitle}</div>",
                "</div>",
                render_pill(card_label, card_tone, pulse=pulse),
                "</div>",
                f'<p class="nc-callout nc-callout--{callout_attr}" '
                f'role="{role}">{html.escape(card_detail)}</p>',
                render_check_banner(show_check_banner),
                render_meta(
                    last_verified=status["last_verified"],
                    verified_age_seconds=status.get("verified_age_seconds"),
                    source_label=source_label if not using_shared else None,
                ),
            ]

            actions: list[str] = []
            disconnect_html = ""
            if state == "unavailable":
                pass
            elif state == "connecting":
                continue_href = html.escape(status["url"], quote=True)
                actions.append(
                    f'<a class="button" href="{continue_href}">Continue sign-in</a>'
                )
                actions.append(
                    self.form(
                        "start",
                        provider,
                        "Start new sign-in",
                        replace=status["url"].rsplit("/", 1)[-1],
                    )
                )
                actions.append(
                    self.form(
                        "cancel",
                        provider,
                        "Cancel sign-in",
                        revision=status["revision"],
                    )
                )
            elif state == "saving":
                card_parts.append(
                    '<p class="muted">'
                    "You can close this page while the connection is saved.</p>"
                )
            elif state == "recovering":
                actions.append(
                    self.form(
                        "start",
                        provider,
                        "Start a new sign-in",
                        replace=status.get("_replace"),
                    )
                )
                actions.append(
                    self.form(
                        "cancel",
                        provider,
                        "Cancel sign-in",
                        revision=status["revision"],
                    )
                )
            elif state == "disconnecting":
                actions.append(
                    self.form(
                        "disconnect",
                        provider,
                        "Finish disconnecting",
                        revision=status["revision"],
                    )
                )
            else:
                if state == "connected":
                    if is_checking:
                        actions.append(
                            '<button type="button" class="secondary" disabled>'
                            "Checking…</button>"
                        )
                    else:
                        actions.append(self.form("check", provider, "Check access"))
                    actions.append(self.form("start", provider, "Reconnect"))
                else:
                    actions.append(self.form("start", provider, "Connect"))
                if state in ("connected", "needs_signin") and status["revision"]:
                    disconnect_html = self.form(
                        "disconnect",
                        provider,
                        "Disconnect this subscription",
                        revision=status["revision"],
                    )

            if actions:
                card_parts.append(f'<div class="nc-actions">{"".join(actions)}</div>')

            if self.access is not None:
                if (
                    sharing_failed
                    or sharing_snapshots is None
                    or provider not in sharing_snapshots
                ):
                    card_parts.append(
                        '<div class="nc-sharing">'
                        '<p role="alert">Sharing controls are unavailable. '
                        "Ask the administrator to recover this record. "
                        "Your own connection controls above remain available.</p>"
                        "</div>"
                    )
                else:
                    try:
                        card_parts.append(
                            self.sharing_body(
                                user,
                                provider,
                                status,
                                snapshot=sharing_snapshots[provider],
                                members=sharing_members,
                                shared_health=shared_health,
                            )
                        )
                    except (NewsclipError, OSError, ValueError):
                        card_parts.append(
                            '<div class="nc-sharing">'
                            '<p role="alert">Sharing controls are unavailable. '
                            "Ask the administrator to recover this record. "
                            "Your own connection controls above remain available.</p>"
                            "</div>"
                        )

            if disconnect_html:
                card_parts.append(disconnect_html)

            card_parts.append("</article>")
            cards.append("".join(card_parts))

        body = (
            f"<style>{CONNECTIONS_STYLE}</style>"
            + render_topbar(identity["name"], self.home + "logout")
            + render_overview(
                effective_tones,
                check_all_action=self.home + "check-all" if any_checkable else None,
                any_checking=any_checking,
            )
            + f'<div class="nc-cards">{"".join(cards)}</div>'
            + '<p class="nc-footer-note">'
            "Connecting a subscription does not give an assistant "
            "permission to use it. Access to each article is checked separately. "
            "Disconnecting keeps your saved articles.</p>"
        )
        return HTMLResponse(
            self.page(
                body,
                refresh=any_checking
                or any(
                    item["state"] in ("connecting", "saving", "recovering")
                    for item in statuses
                ),
            ),
        )

    def sharing_body(
        self,
        user,
        provider,
        status,
        *,
        snapshot=None,
        members=None,
        shared_health=None,
    ):
        assert self.access is not None
        if snapshot is not None:
            row, offered, unavailable, admitted_ok = snapshot
        else:
            row, offered, unavailable = self.access.view(user, provider)
            admitted_ok = None
        selected = row["selection"]
        summary = (
            "Using my subscription."
            if selected and selected["owner"] == user
            else f"Using {selected['owner']}'s subscription."
            if selected
            else "No subscription selected. Choose below to continue."
        )
        if selected and selected["owner"] != user:
            if admitted_ok is False:
                summary = (
                    "The selected shared access was removed or changed. Choose below."
                )
            elif admitted_ok is None:
                try:
                    self.access.admit(user, provider)
                except NewsclipError:
                    summary = (
                        "The selected shared access was removed or changed. "
                        "Choose below."
                    )

        parts = [
            '<div class="nc-sharing">',
            '<section aria-label="Account selection">',
            '<div class="nc-sharing-head">',
            f'<p class="nc-sharing-summary" role="status">{html.escape(summary)}</p>',
            "</div>",
        ]
        offer_rows: list[str] = []
        if not selected or selected["owner"] != user:
            own_pill = render_pill(status["access_label"], status["access_tone"])
            choose_own = action_form(
                self.home + "choose",
                {
                    "provider": provider,
                    "owner": user,
                    "selection_revision": row["revision"],
                    "grant": "own",
                },
                "Use my subscription",
            )
            offer_rows.append(
                '<div class="nc-offer-row">'
                '<div class="nc-offer-info">'
                f'<p class="nc-offer-title">My subscription {own_pill}</p>'
                "</div>"
                f'<div class="nc-offer-actions">{choose_own}</div>'
                "</div>"
            )
        for owner, grant in offered:
            owner_info = (
                shared_health.get((owner, provider))
                if shared_health is not None
                else self._owner_access_summary(owner, provider)
            )
            owner_pill = (
                render_pill(owner_info[1], owner_info[2])
                if owner_info is not None
                else ""
            )
            is_selected = selected == {"owner": owner, "grant": grant}
            row_actions: list[str] = []
            if not is_selected:
                row_actions.append(
                    action_form(
                        self.home + "choose",
                        {
                            "provider": provider,
                            "owner": owner,
                            "selection_revision": row["revision"],
                            "grant": grant,
                        },
                        "Use this subscription",
                    )
                )
            row_actions.append(
                action_form(
                    self.home + "leave",
                    {"provider": provider, "owner": owner, "grant": grant},
                    "Leave " + owner + "'s shared subscription"
                    if selected and selected["owner"] == owner
                    else "Decline access from " + owner,
                )
            )
            offer_rows.append(
                '<div class="nc-offer-row">'
                '<div class="nc-offer-info">'
                f'<p class="nc-offer-title">{html.escape(owner)}\'s subscription '
                f"{owner_pill}</p>"
                '<p class="nc-offer-detail">Read with their subscription; '
                "save articles privately to your own archive.</p>"
                "</div>"
                f'<div class="nc-offer-actions">{"".join(row_actions)}</div>'
                "</div>"
            )
        if offer_rows:
            parts.append(f'<div class="nc-offer-list">{"".join(offer_rows)}</div>')
        parts.append("</section>")

        if unavailable:
            parts.append(
                '<p role="alert">Some shared offers are unavailable. '
                "Other controls remain usable.</p>"
            )

        active_grant_count = len(row["grants"])
        shared_label = (
            f"Shared with ({active_grant_count})"
            if active_grant_count
            else "Shared with"
        )
        parts.append(
            f"<details><summary>{html.escape(shared_label)}</summary>"
            "<p>Share your own publisher sign-in with an existing user. They choose "
            "when to use it and cannot reconnect, disconnect or share it further. "
            "Activity may appear in the publisher account. Stopping sharing keeps "
            "articles they already saved.</p>"
        )
        if members is None:
            members = self.access.users() - {user}
        member_rows: list[str] = []
        for member in sorted(members | row["grants"].keys()):
            grant = row["grants"].get(member)
            if grant:
                btn = action_form(
                    self.home + "unshare",
                    {"provider": provider, "member": member, "grant": grant},
                    "Stop sharing",
                    danger=True,
                )
            elif status["state"] == "connected":
                btn = action_form(
                    self.home + "share",
                    {
                        "provider": provider,
                        "member": member,
                        "grant": "new",
                        "revision": status["revision"],
                    },
                    "Share my subscription",
                )
            else:
                btn = '<span class="muted">Connect first to share</span>'
            member_rows.append(
                '<div class="nc-member-row">'
                f'<p class="nc-member-name">{html.escape(member)}</p>'
                f"{btn}</div>"
            )
        if member_rows:
            parts.append(f'<div class="nc-members">{"".join(member_rows)}</div>')
        elif not members:
            parts.append("<p>No other registered users are available.</p>")
        parts.append("</details></div>")
        return "".join(parts)

    async def sharing_action(self, request):
        user = self.user(request)
        if user is None or not self.auth.origin_ok(request):
            return self.auth.refused(request)
        if self.access is None:
            return Response(status_code=503)
        action = request.url.path.rsplit("/", 1)[1]
        payload = bytearray()
        async for chunk in request.stream():
            payload.extend(chunk)
            if len(payload) > 4096:
                return Response(status_code=413)
        expected = {
            "choose": {"provider", "owner", "selection_revision", "grant"},
            "share": {"provider", "member", "grant", "revision"},
            "unshare": {"provider", "member", "grant"},
            "leave": {"provider", "owner", "grant"},
        }
        try:
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/x-www-form-urlencoded"
            ):
                raise ValueError("form required")
            parsed = parse_qs(payload.decode(), strict_parsing=True, max_num_fields=4)
            if set(parsed) != expected[action] or any(
                len(v) != 1 or not v[0] for v in parsed.values()
            ):
                raise ValueError("invalid fields")
            values = {key: value[0] for key, value in parsed.items()}
            provider = values["provider"]
            selected = self.adapters[user]._service_ready()._registry.get(provider)
            if selected.login_recipe is None:
                raise ValueError("publisher needs no connection")
        except (ValueError, UnicodeError, NewsclipError):
            return Response(status_code=400)
        if action == "share" and (
            confirm := self.auth.require_fresh(
                request, max_age=FRESH_SECONDS, action="share this connection"
            )
        ):
            return confirm
        access = self.access

        def apply():
            if action == "choose":
                access.choose(
                    user,
                    provider,
                    values["owner"],
                    values["selection_revision"],
                    None if values["grant"] == "own" else values["grant"],
                )
            elif action == "share":
                if (
                    self.controls[user].status(provider)["revision"]
                    != values["revision"]
                ):
                    raise UsageError("connection changed")
                store = self._store(user)
                if store is None:
                    raise UsageError("session storage unavailable")
                store.get_valid_session(provider)
                access.share(
                    user,
                    provider,
                    values["member"],
                    None if values["grant"] == "new" else values["grant"],
                )
            elif action == "unshare":
                access.revoke(user, provider, values["member"], values["grant"])
            else:
                access.revoke(
                    values["owner"], provider, user, values["grant"], leaving=True
                )

        try:
            await self.adapters[user].dispatcher.run(apply)
        except (NewsclipError, OSError, ValueError):
            return HTMLResponse(
                self.page(
                    '<p role="alert">Access changed or this action could not finish. '
                    "Return to Connections to check the current selection "
                    "and try again.</p>"
                    f'<a href="{self.home}">Back to Connections</a>'
                ),
                status_code=409,
            )
        return RedirectResponse(self.home, status_code=303)

    async def status(self, request):
        user = self.user(request)
        if not user:
            return Response(status_code=401)
        providers = await self.adapters[user].dispatcher.run(
            lambda: self.statuses(user)
        )
        return JSONResponse({"providers": providers})

    async def action(self, request):
        user = self.user(request)
        if not user or not self.auth.origin_ok(request):
            return self.auth.refused(request)
        payload = bytearray()
        async for chunk in request.stream():
            payload.extend(chunk)
            if len(payload) > 4096:
                return Response(status_code=413)
        try:
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/x-www-form-urlencoded"
            ):
                raise ValueError("form")
            values = parse_qs(payload.decode(), strict_parsing=True, max_num_fields=4)
            if not {"provider"} <= set(values) <= {
                "provider",
                "revision",
                "replace",
            } or any(len(v) != 1 for v in values.values()):
                raise ValueError("provider")
            provider = values["provider"][0]
            selected = self.adapters[user]._service_ready()._registry.get(provider)
            if selected.login_recipe is None:
                raise ValueError("provider")
        except (ValueError, UnicodeError, NewsclipError):
            return Response(status_code=400)
        action = request.url.path.rsplit("/", 1)[1]
        if action == "disconnect" and (
            confirm := self.auth.require_fresh(
                request, max_age=FRESH_SECONDS, action="disconnect this publisher"
            )
        ):
            return confirm
        adapter = self.adapters[user]
        expected_revision = values.get("revision", [""])[0]
        replace_id = values.get("replace", [None])[0]
        if action in ("cancel", "disconnect") and not expected_revision:
            return Response(status_code=400)
        try:
            if action == "start":
                link = await adapter.dispatcher.run(
                    lambda: self.connection(user, provider, replace=replace_id)
                )
                return RedirectResponse(link.url, status_code=303)
            if action == "disconnect":
                disconnect_revision = self.controls[user].suspend(
                    provider, expected_revision=expected_revision
                )
                if disconnect_revision is None:
                    return RedirectResponse(self.home, status_code=303)
            else:
                self.controls[user].cancel(provider, "default", expected_revision)
            settled_ids: set[str] = set()

            def drain_links():
                with self._start_lock(user, provider):
                    if action == "disconnect":
                        status = self.controls[user].status(provider)
                        if (
                            status["phase"] != 2
                            or status["revision"] != disconnect_revision
                        ):
                            return
                    link = self.links.get((user, provider))
                    to_cancel = list(self._pending_close.get((user, provider), ()))
                    if (
                        link
                        and link.context
                        and link.context.target == expected_revision
                        and link not in to_cancel
                    ):
                        to_cancel.append(link)
                    if action == "disconnect":
                        for item in self._provider_links(user, provider):
                            if item not in to_cancel:
                                to_cancel.append(item)
                    if not to_cancel:
                        return
                    remaining = []
                    for item in to_cancel:
                        open_now, _ = self._cancel_and_check(user, item)
                        if open_now:
                            remaining.append(item)
                        else:
                            settled_ids.add(item.id)
                    if remaining:
                        self._pending_close[user, provider] = remaining
                    else:
                        self._pending_close.pop((user, provider), None)

            await adapter.dispatcher.run(drain_links)
            if action == "disconnect":

                def disconnect():
                    service = adapter._service_ready()
                    store = self._store(user)
                    if store is None:
                        raise UsageError("session storage is unavailable")
                    store.disconnect(
                        provider,
                        connection_revision=disconnect_revision,
                        drain=service._release_browser,
                    )
                    with self._start_lock(user, provider):
                        open_ids = {
                            item.id
                            for item in self._pending_close.get((user, provider), ())
                        }
                        purge_ids = settled_ids - open_ids
                        current_link = self.links.get((user, provider))
                        if current_link is not None and current_link.id in purge_ids:
                            self.links.pop((user, provider), None)
                        known = self._known_links.get((user, provider))
                        if known:
                            for lid in list(known):
                                if lid in purge_ids:
                                    known.pop(lid, None)
                            if not known:
                                self._known_links.pop((user, provider), None)
                        with self.relays[user]._lock:
                            for aid, alink in list(self.relays[user]._links.items()):
                                if alink.key == provider and aid in purge_ids:
                                    alink.closed = True
                                    self.relays[user]._links.pop(aid, None)
                            for rid, rlink in list(self.relays[user]._retired.items()):
                                if rlink.key == provider and rid in purge_ids:
                                    rlink.closed = True
                                    self.relays[user]._retired.pop(rid, None)

                await adapter.dispatcher.run(disconnect)
        except LinkLimited:
            return HTMLResponse(
                self.page(
                    '<p role="alert">Too many sign-in attempts for this subscription. '
                    "Wait a while and try again.</p>"
                    f'<a href="{self.home}">Back to Connections</a>'
                ),
                status_code=429,
            )
        except (NewsclipError, OSError):
            return HTMLResponse(
                self.page(
                    '<p role="alert">The operation could not finish. '
                    "A pending disconnect stays blocked. "
                    "Return to Connections and retry.</p>"
                    f'<a href="{self.home}">Back to Connections</a>'
                ),
                status_code=409,
            )
        return RedirectResponse(self.home, status_code=303)

    async def check_action(self, request):
        user = self.user(request)
        if not user or not self.auth.origin_ok(request):
            return self.auth.refused(request)
        action = request.url.path.rsplit("/", 1)[1]
        payload = bytearray()
        async for chunk in request.stream():
            payload.extend(chunk)
            if len(payload) > 4096:
                return Response(status_code=413)
        if (
            request.headers.get("content-type", "").split(";", 1)[0]
            != "application/x-www-form-urlencoded"
        ):
            return Response(status_code=400)
        if action == "check-all":
            if payload:
                return Response(status_code=400)

            def start_all():
                for item in self.statuses(user):
                    if item["state"] == "connected":
                        self.start_check(user, item["provider"])

            try:
                await self.adapters[user].dispatcher.run(start_all)
            except (NewsclipError, OSError, ValueError):
                return Response(status_code=409)
            return RedirectResponse(self.home, status_code=303)
        try:
            values = parse_qs(payload.decode(), strict_parsing=True, max_num_fields=2)
            if set(values) != {"provider"} or len(values["provider"]) != 1:
                raise ValueError("provider")
            provider = values["provider"][0]
            selected = self.adapters[user]._service_ready()._registry.get(provider)
            if selected.login_recipe is None:
                raise ValueError("provider")
        except (ValueError, UnicodeError, NewsclipError):
            return Response(status_code=400)
        try:
            await self.adapters[user].dispatcher.run(
                lambda: self.start_check(user, provider)
            )
        except (NewsclipError, OSError, ValueError):
            return Response(status_code=409)
        return RedirectResponse(self.home + "#" + provider, status_code=303)

    def routes(self):
        routes = [
            Route("/connections/", self.index),
            Route("/connections/status", self.status),
            *self.auth.routes(),
            *(
                Route("/connections/" + action, self.sharing_action, methods=["POST"])
                for action in ("choose", "share", "unshare", "leave")
            ),
            *(
                Route("/connections/" + action, self.action, methods=["POST"])
                for action in ("start", "cancel", "disconnect")
            ),
            *(
                Route("/connections/" + action, self.check_action, methods=["POST"])
                for action in ("check", "check-all")
            ),
        ]

        def fixed_origin(endpoint):
            async def checked(request):
                target = urlsplit(self.config.oidc.public_url)
                origins = request.headers.getlist("origin")
                if request.headers.getlist("host") != [target.netloc] or (
                    origins and not self.auth.origin_ok(request)
                ):
                    return Response(status_code=403)
                return await endpoint(request)

            return checked

        return [
            Route(route.path, fixed_origin(route.endpoint), methods=route.methods)
            for route in routes
        ]
