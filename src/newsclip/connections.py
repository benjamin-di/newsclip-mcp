"""OIDC connections UI; publisher authority stays in each user's session store."""

from __future__ import annotations

import html
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from signin_window.connections import disconnect_confirmation, timestamp
from signin_window.connections import page as connection_page
from signin_window.oidc import BrowserAuth, OIDCConfig
from signin_window.page import PageText
from signin_window.relay import AttemptContext, Link, Relay
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .connection_controls import ConnectionControls
from .errors import NewsclipError, UsageError
from .models import SessionStatus
from .sessions import ServingSessions, SessionStore
from .tenancy import application_root, load_users, user_scope

_PUBLISHER_NAMES = {
    "ft": "Financial Times",
    "economist": "The Economist",
    "wsj": "The Wall Street Journal",
    "nyt": "The New York Times",
    "bloomberg": "Bloomberg",
    "reuters": "Reuters",
    "cnbc": "CNBC",
}


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
        self.auth = BrowserAuth(config.oidc, transport=transport, clock=clock)
        self.home = urlsplit(config.oidc.public_url).path.rstrip("/") + "/connections/"
        self.relays, self.adapters, self.controls, self.links = {}, {}, {}, {}

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

        relay = Relay(
            backend,
            f"{origin}/users/{user.id}/connect",
            text=PageText(
                service="Newsclip",
                title="Connect {label} to Newsclip",
                help_html=(
                    "Sign in on {label}'s own page below. Use a password or code; "
                    "device passkeys do not work in this remote window. Pasting works."
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
                and self.controls[user].current(
                    link.key, "default", link.context.target
                )
            ):
                return Response(status_code=404)
            self.controls[user].cancel(link.key, "default", link.context.target)
            await self.adapters[user].dispatcher.run(lambda: relay.cancel(link))
            return Response(status_code=204, headers={"Cache-Control": "no-store"})

        return [
            route
            for route in relay.routes(prefix)
            if getattr(route, "path", "") != prefix + "/{id}/cancel"
        ] + [Route(prefix + "/{id}/cancel", cancel, methods=["POST"])]

    def connection(self, user, provider):
        selected = self.adapters[user]._service_ready()._registry.get(provider)
        if selected.login_recipe is None:
            raise UsageError("this provider does not require sign-in")
        revision = self.controls[user].begin(provider)
        link = self.relays[user].create(
            provider,
            params={
                "user": user,
                "provider": provider,
                "account_key": "default",
                "connection_revision": revision,
            },
            label=_PUBLISHER_NAMES.get(provider, provider),
            context=AttemptContext(owner=user, target=revision),
        )
        self.links[user, provider] = link
        return link

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

    def statuses(self, user):
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
            control = self.controls[user].status(provider)
            link = self.links.get((user, provider))
            health = store.status(provider) if store else None
            if control["phase"] == 2:
                state, detail = (
                    "disconnecting",
                    "Access stopped. Finish disconnecting to remove the saved sign-in.",
                )
            elif (
                link
                and link.context
                and self.controls[user].current(
                    provider, "default", link.context.target
                )
                and link.state in ("ready", "starting", "waiting", "saving")
            ):
                state, detail = (
                    "connecting",
                    "Sign-in is in progress. Continue the sign-in you already started.",
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
            items.append(
                {
                    "provider": provider,
                    "name": _PUBLISHER_NAMES.get(provider, provider),
                    "revision": control["revision"],
                    "state": state,
                    "detail": detail,
                    "last_verified": health.last_verified_at.isoformat()
                    if health and health.last_verified_at
                    else None,
                    "url": link.url if state == "connecting" else None,
                }
            )
        return items

    def page(self, body, *, refresh=False):
        return connection_page(
            "News subscriptions", body, refresh=refresh, login_url=self.home + "login"
        )

    def form(self, action, provider, text, *, revision=None):
        fence = (
            f'<input type="hidden" name="revision" value="{html.escape(revision)}">'
            if action in ("cancel", "disconnect")
            else ""
        )
        kind = (
            "danger"
            if action == "disconnect"
            else "quiet"
            if action == "cancel"
            else "secondary"
            if text == "Reconnect"
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
                "It does not cancel your subscription or delete your saved articles.",
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
        statuses = self.statuses(user)
        body = "<p>Signed in as " + html.escape(identity["name"]) + ".</p>"
        for status in statuses:
            provider, state = status["provider"], status["state"]
            body += (
                f'<article id="{html.escape(provider)}">'
                f"<h2>{html.escape(status['name'])}</h2>"
                f"<p role=status>{html.escape(status['detail'])}</p>"
            )
            if status["last_verified"]:
                body += timestamp(status["last_verified"])
            if state == "connecting":
                body += f'<a href="{html.escape(status["url"])}">Continue sign-in</a>'
                body += self.form(
                    "cancel", provider, "Cancel sign-in", revision=status["revision"]
                )
            elif state == "recovering":
                body += self.form(
                    "cancel", provider, "Cancel sign-in", revision=status["revision"]
                )
                body += self.form("start", provider, "Start a new sign-in")
            elif state == "disconnecting":
                body += self.form(
                    "disconnect",
                    provider,
                    "Finish disconnecting",
                    revision=status["revision"],
                )
            else:
                body += self.form(
                    "start",
                    provider,
                    "Reconnect" if state == "connected" else "Connect",
                )
                if state == "connected":
                    body += self.form(
                        "disconnect",
                        provider,
                        "Disconnect this subscription",
                        revision=status["revision"],
                    )
            body += "</article>"
        body += (
            "<p class=muted>Connecting a subscription does not give an assistant "
            "permission to use it. Access to each article is checked separately. "
            "Disconnecting keeps your saved articles.</p>"
            f'<form method="post" action="{self.home}logout">'
            "<button class=quiet>Sign out of Connections</button></form>"
        )
        return HTMLResponse(
            self.page(
                body,
                refresh=any(
                    item["state"] in ("connecting", "recovering") for item in statuses
                ),
            ),
        )

    async def status(self, request):
        user = self.user(request)
        return (
            JSONResponse({"providers": self.statuses(user)})
            if user
            else Response(status_code=401)
        )

    async def action(self, request):
        user = self.user(request)
        if not user:
            return Response(status_code=401)
        if not self.auth.origin_ok(request):
            return Response(status_code=403)
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
            if not {"provider"} <= set(values) <= {"provider", "revision"} or any(
                len(v) != 1 for v in values.values()
            ):
                raise ValueError("provider")
            provider = values["provider"][0]
            if provider not in {item["provider"] for item in self.statuses(user)}:
                raise ValueError("provider")
        except (ValueError, UnicodeError):
            return Response(status_code=400)
        action = request.url.path.rsplit("/", 1)[1]
        identity = self.auth.identity(request)
        if action == "disconnect":
            fresh = identity.get("reauthenticated_at") if identity else None
            if (
                not isinstance(fresh, int | float)
                or not 0 <= self.clock() - fresh <= 300
            ):
                return RedirectResponse(self.home + "login?reauth=1", status_code=303)
        adapter = self.adapters[user]
        expected_revision = values.get("revision", [""])[0]
        if action in ("cancel", "disconnect") and not expected_revision:
            return Response(status_code=400)
        try:
            if action == "start":
                link = await adapter.dispatcher.run(
                    lambda: self.connection(user, provider)
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
            link = self.links.get((user, provider))
            if link and link.context and link.context.target == expected_revision:
                await adapter.dispatcher.run(lambda: self.relays[user].cancel(link))
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

                await adapter.dispatcher.run(disconnect)
        except (NewsclipError, OSError):
            return HTMLResponse(
                self.page(
                    "<p>The operation could not finish. A pending disconnect "
                    "stays blocked. "
                    "Return to connections and retry.</p>"
                    f'<a href="{self.home}">Back to connections</a>'
                ),
                status_code=409,
            )
        return RedirectResponse(self.home, status_code=303)

    def routes(self):
        routes = [
            Route("/connections/", self.index),
            Route("/connections/status", self.status),
            *self.auth.routes(),
            *(
                Route("/connections/" + action, self.action, methods=["POST"])
                for action in ("start", "cancel", "disconnect")
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
