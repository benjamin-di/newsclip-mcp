"""Server-rendered UI components for Newsclip Connections.

Pure HTML and scoped CSS (no external assets, no custom JavaScript) built on
signin-window's shared component kit and tokens so the page works inside
signin-window's strict Content-Security-Policy and degrades cleanly without
JavaScript. All dynamic text is escaped before rendering.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from signin_window.connections import badge as kit_badge

from .models import (
    RecoveryStatus,
    SessionHealth,
    SessionHealthState,
    SessionStatus,
    TerminalFailure,
)

PUBLISHER_NAMES: dict[str, str] = {
    "ft": "Financial Times",
    "economist": "The Economist",
    "wsj": "The Wall Street Journal",
    "nyt": "The New York Times",
    "bloomberg": "Bloomberg",
    "reuters": "Reuters",
    "cnbc": "CNBC",
}

_PUBLISHER_MONOGRAMS: dict[str, str] = {
    "ft": "FT",
    "economist": "EC",
    "wsj": "WSJ",
    "nyt": "NYT",
    "bloomberg": "BBG",
    "reuters": "RTR",
    "cnbc": "CNBC",
}

_PUBLISHER_THEMES: dict[str, str] = {
    "ft": "ft",
    "economist": "economist",
    "wsj": "wsj",
    "nyt": "nyt",
    "bloomberg": "bloomberg",
    "reuters": "reuters",
    "cnbc": "cnbc",
}

_FAILURE_EXPLANATIONS: dict[TerminalFailure, str] = {
    TerminalFailure.CREDENTIAL_REJECTED: (
        "The publisher rejected the saved sign-in. Reconnect to restore access."
    ),
    TerminalFailure.SECOND_FACTOR_REQUIRED: (
        "The publisher asked for a second-factor confirmation. "
        "Reconnect to complete it."
    ),
    TerminalFailure.ACCOUNT_ALERT: (
        "The publisher flagged an account alert. Sign in directly on the "
        "publisher site, then reconnect."
    ),
    TerminalFailure.CHALLENGE_BLOCKED: (
        "The publisher blocked automatic renewal with a verification "
        "challenge. Reconnect to refresh access."
    ),
    TerminalFailure.UNKNOWN_FLOW: (
        "The publisher sign-in flow changed and needs a manual sign-in."
    ),
    TerminalFailure.INFRASTRUCTURE_ERROR: (
        "The last sign-in check hit a temporary error. Check access or reconnect."
    ),
}

CONNECTIONS_STYLE = """
.nc-hero-headline{font-size:1.15rem;font-weight:650;margin:.15rem 0 .25rem}
.nc-cards{display:grid;gap:1rem;margin:1rem 0}
.nc-cards>article{margin:0}
.nc-pub{display:flex;align-items:center;gap:.75rem;min-width:0}
.nc-avatar{
  width:2.4rem;height:2.4rem;border-radius:var(--radius-sm);flex:none;
  display:grid;place-content:center;font-weight:750;font-size:.76rem;
  letter-spacing:.03em;background:var(--neutral-bg);color:var(--text);
  border:1px solid var(--neutral-border);
}
.nc-avatar--ft{background:#fce7d8;color:#7c2d12;border-color:#f3c4a4}
.nc-avatar--economist{background:#fee2e2;color:#991b1b;border-color:#fca5a5}
.nc-avatar--wsj{background:#e7e5e4;color:#1c1917;border-color:#d6d3d1}
.nc-avatar--nyt{background:#ede9fe;color:#3b0764;border-color:#d8b4fe}
.nc-avatar--bloomberg{background:#dbeafe;color:#1e3a8a;border-color:#93c5fd}
.nc-avatar--reuters{background:#ffedd5;color:#9a3412;border-color:#fdba74}
.nc-avatar--cnbc{background:#dcfce7;color:#14532d;border-color:#86efac}
@media(prefers-color-scheme:dark){
  .nc-avatar--ft{
    background:rgba(251,146,60,.18);color:#fdba74;border-color:rgba(251,146,60,.36);
  }
  .nc-avatar--economist{
    background:rgba(239,68,68,.18);color:#fca5a5;border-color:rgba(239,68,68,.38);
  }
  .nc-avatar--wsj{
    background:rgba(168,162,158,.18);color:#e7e5e4;border-color:rgba(168,162,158,.34);
  }
  .nc-avatar--nyt{
    background:rgba(168,85,247,.18);color:#e9d5ff;border-color:rgba(168,85,247,.36);
  }
  .nc-avatar--bloomberg{
    background:rgba(59,130,246,.2);color:#bfdbfe;border-color:rgba(59,130,246,.38);
  }
  .nc-avatar--reuters{
    background:rgba(249,115,22,.18);color:#fdba74;border-color:rgba(249,115,22,.36);
  }
  .nc-avatar--cnbc{
    background:rgba(34,197,94,.18);color:#bbf7d0;border-color:rgba(34,197,94,.36);
  }
}
.nc-pub-title{margin:0;font-size:1.1rem;line-height:1.25;letter-spacing:-.01em}
.nc-pub-sub{margin:.15rem 0 0;font-size:.84rem;color:var(--muted)}
.badge.nc-pulse::before{animation:nc-pulse 1.4s ease-in-out infinite}
@keyframes nc-pulse{
  0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.82)}
}
@media(prefers-reduced-motion:reduce){.badge.nc-pulse::before{animation:none}}
.nc-sharing{margin-top:1rem;padding-top:.9rem;border-top:1px solid var(--line)}
.nc-sharing-status{margin:0 0 .35rem;font-size:.9rem;font-weight:600;color:var(--text)}
.nc-offer-actions{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.nc-offer-actions form{margin:0}
.nc-footer-row{
  display:flex;align-items:center;justify-content:space-between;
  gap:.75rem 1.25rem;flex-wrap:wrap;margin-top:1.5rem;
}
.nc-footer-row p{
  margin:0;font-size:.84rem;color:var(--muted);line-height:1.5;flex:1 1 20rem;
}
.nc-footer-row form{margin:0}
@media(max-width:560px){
  .nc-offer-actions,.rows form{width:100%}
  .nc-offer-actions{display:grid}
  .nc-footer-row form{width:100%}
}
"""

_TONE_MAP: dict[str, str] = {
    "ok": "ok",
    "warn": "warn",
    "bad": "bad",
    "info": "info",
    "neutral": "neutral",
    "muted": "neutral",
}


def publisher_name(provider: str) -> str:
    return PUBLISHER_NAMES.get(provider, provider)


def publisher_monogram(provider: str) -> str:
    if provider in _PUBLISHER_MONOGRAMS:
        return _PUBLISHER_MONOGRAMS[provider]
    cleaned = "".join(ch for ch in provider if ch.isalnum()).upper()
    return cleaned[:3] or "?"


def format_relative_age(seconds: float | None) -> str | None:
    if seconds is None or seconds < 0:
        return None
    whole = int(seconds)
    if whole < 60:
        return "just now"
    if whole < 3600:
        return f"{whole // 60}m ago"
    if whole < 86400:
        hours = whole // 3600
        return f"{hours}h ago"
    days = whole // 86400
    return f"{days}d ago"


def format_utc_time(value: str | float | None) -> tuple[str, str] | None:
    if value is None:
        return None
    try:
        dt = (
            datetime.fromtimestamp(value, UTC)
            if isinstance(value, int | float)
            else datetime.fromisoformat(value)
        )
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return dt.isoformat(), f"{dt.day} {dt:%b %Y} at {dt:%H:%M} UTC"


def describe_access(
    *,
    state: str,
    health: SessionHealth | None,
    check: Mapping[str, object] | None = None,
    detail: str,
) -> tuple[str, str, str, str]:
    """Return ``(access_status, badge_label, tone, access_detail)``.

    ``tone`` is one of ``ok``, ``warn``, ``bad``, ``info``, ``muted``.
    """
    if check and check.get("state") == "checking":
        return (
            "checking",
            "Checking…",
            "info",
            "Running a live subscription check against the publisher…",
        )
    if state == "unavailable":
        return ("unavailable", "Unavailable", "bad", detail)
    if state == "disconnecting":
        return ("in_progress", "Disconnecting", "warn", detail)
    if state == "saving":
        return ("in_progress", "Saving…", "info", detail)
    if state == "connecting":
        return ("in_progress", "Sign-in open", "info", detail)
    if state == "recovering":
        return ("in_progress", "Finishing…", "warn", detail)
    if state == "disconnected":
        return (
            "disconnected",
            "Disconnected",
            "muted",
            "Connect this subscription to use it again.",
        )

    if health is None:
        return ("not_connected", "Not connected", "muted", detail)

    if state == "connected":
        derived = health.health
        recovery = health.recovery
        if (
            recovery is not None
            and recovery.status in (RecoveryStatus.PENDING, RecoveryStatus.RUNNING)
            and not recovery.session_verified
        ):
            return (
                "degraded",
                "Recovering",
                "warn",
                "Automatic recovery is in progress. "
                "Check access or reconnect if needed.",
            )
        if derived is SessionHealthState.DEGRADED:
            failures = health.consecutive_renewal_failures or 0
            if failures > 0:
                times = "1 time" if failures == 1 else f"{failures} times"
                return (
                    "degraded",
                    "Degraded",
                    "bad",
                    f"Automatic renewal failed {times}. Run a live check or reconnect.",
                )
            return (
                "degraded",
                "Degraded",
                "bad",
                "Access could not be confirmed recently. "
                "Run a live check or reconnect.",
            )
        if derived is SessionHealthState.STALE:
            age = format_relative_age(health.verified_age_seconds)
            age_note = f" (last verified {age})" if age else ""
            return (
                "stale",
                "Needs check",
                "warn",
                f"Connection is saved{age_note} and due for a fresh check.",
            )
        age = format_relative_age(health.verified_age_seconds)
        if age:
            return (
                "working",
                "Working",
                "ok",
                f"Access is verified and working (last checked {age}).",
            )
        return (
            "working",
            "Working",
            "ok",
            "Access is verified and working.",
        )

    # Not connected / failed / cooldown states from SessionStore
    if health.status is SessionStatus.OPERATOR_ACTION:
        explanation = (
            _FAILURE_EXPLANATIONS.get(
                health.last_failure,
                "Sign-in needs your attention before this subscription can be used.",
            )
            if health.last_failure is not None
            else "Sign-in needs your attention before this subscription can be used."
        )
        return ("action_required", "Action needed", "bad", explanation)
    if health.status is SessionStatus.COOLDOWN:
        until = format_utc_time(
            health.retry_not_before.isoformat() if health.retry_not_before else None
        )
        when = f" until {until[1]}" if until else ""
        return (
            "cooldown",
            "Paused",
            "warn",
            f"Temporarily paused after recent failures{when}. "
            "Reconnect to sign in now.",
        )
    return ("not_connected", "Not connected", "muted", detail)


def render_pill(label: str, tone: str, *, pulse: bool = False) -> str:
    kit_tone = _TONE_MAP.get(tone, "neutral")
    rendered = kit_badge(label, kit_tone)
    if pulse:
        return rendered.replace('class="badge', 'class="badge nc-pulse', 1)
    return rendered


def render_overview(
    effective_tones: Sequence[str],
    *,
    check_all_action: str | None,
    any_checking: bool,
) -> str:
    total = len(effective_tones)
    working = sum(1 for tone in effective_tones if tone == "ok")
    bad = sum(1 for tone in effective_tones if tone == "bad")
    warn = sum(1 for tone in effective_tones if tone == "warn")
    in_progress = sum(1 for tone in effective_tones if tone == "info")
    not_connected = sum(1 for tone in effective_tones if tone in ("muted", "neutral"))

    breakdown: list[str] = []
    if working:
        breakdown.append(f"{working} working")
    if bad:
        breakdown.append(f"{bad} action needed")
    if warn:
        breakdown.append(f"{warn} needs check")
    if in_progress:
        breakdown.append(f"{in_progress} in progress")
    if not_connected:
        breakdown.append(f"{not_connected} not connected")

    pulse = False
    if any_checking:
        badge_label, badge_tone, pulse = "Checking…", "info", True
        headline = "Checking your subscriptions…"
        subline = "Live checks are running against your connected publishers."
    elif total == 0:
        badge_label, badge_tone = "Not connected", "neutral"
        headline = "No subscriptions configured"
        subline = "Ask your administrator to enable a publisher."
    elif bad:
        badge_label, badge_tone = "Action needed", "bad"
        noun = "subscription needs" if bad == 1 else "subscriptions need"
        headline = f"{bad} {noun} attention"
        subline = " · ".join(breakdown)
    elif warn:
        badge_label, badge_tone = "Needs check", "warn"
        noun = "subscription needs" if warn == 1 else "subscriptions need"
        headline = f"{warn} {noun} a check"
        subline = " · ".join(breakdown)
    elif in_progress:
        badge_label, badge_tone, pulse = "Sign-in open", "info", True
        headline = "Sign-in in progress"
        subline = " · ".join(breakdown)
    elif working == total:
        badge_label, badge_tone = "Connected", "ok"
        headline = (
            "1 subscription working"
            if total == 1
            else f"All {total} subscriptions working"
        )
        subline = "Your assistant can read from your connected publishers."
    elif working:
        badge_label, badge_tone = "Connected", "ok"
        headline = f"{working} of {total} subscriptions working"
        subline = " · ".join(breakdown)
    else:
        badge_label, badge_tone = "Sign-in needed", "neutral"
        headline = "No subscriptions connected yet"
        subline = "Connect a publisher below to get started."

    actions = ""
    if any_checking:
        actions = (
            '<div class="actions">'
            '<button type="button" class="secondary" disabled>Checking…</button>'
            "</div>"
        )
    elif check_all_action:
        actions = (
            '<div class="actions">'
            f'<form method="post" action="{html.escape(check_all_action, quote=True)}">'
            "<button>Check all</button></form>"
            "</div>"
        )

    return (
        '<section class="panel hero" aria-label="Access summary">'
        '<div class="card-head">'
        "<h2>Your subscriptions</h2>"
        f"{render_pill(badge_label, badge_tone, pulse=pulse)}"
        "</div>"
        f'<p class="nc-hero-headline">{html.escape(headline)}</p>'
        f'<p class="muted">{html.escape(subline)}</p>'
        f"{actions}</section>"
    )


def render_avatar(provider: str) -> str:
    theme = _PUBLISHER_THEMES.get(provider, "")
    cls = f"nc-avatar nc-avatar--{theme}" if theme else "nc-avatar"
    return (
        f'<div class="{cls}" aria-hidden="true">'
        f"{html.escape(publisher_monogram(provider))}</div>"
    )


def render_meta(
    *,
    last_verified: str | None,
    verified_age_seconds: float | None,
    source_label: str | None = None,
) -> str:
    rows: list[str] = []
    formatted = format_utc_time(last_verified)
    if formatted is not None:
        iso, utc_text = formatted
        rel = format_relative_age(verified_age_seconds)
        if rel:
            rows.append(
                "<dt>Last verified</dt><dd>"
                f'<time datetime="{html.escape(iso, quote=True)}" '
                f'title="{html.escape(utc_text, quote=True)}">'
                f"{html.escape(rel)} ({html.escape(utc_text)})</time></dd>"
            )
        else:
            rows.append(
                "<dt>Last verified</dt><dd>"
                f'<time datetime="{html.escape(iso, quote=True)}">'
                f"{html.escape(utc_text)}</time></dd>"
            )
    if source_label:
        if ": " in source_label:
            label, value = source_label.split(": ", 1)
        else:
            label, value = "Active source", source_label
        rows.append(f"<dt>{html.escape(label)}</dt><dd>{html.escape(value)}</dd>")
    if not rows:
        return ""
    return f'<dl class="facts">{"".join(rows)}</dl>'


def render_check_banner(check: Mapping[str, object] | None) -> str:
    if not check:
        return ""
    check_state = str(check.get("state") or "")
    detail = str(check.get("detail") or "")
    if not check_state or not detail or check_state == "checking":
        return ""
    raw_checked = check.get("checked_at")
    checked_at = format_utc_time(raw_checked if isinstance(raw_checked, str) else None)
    time_html = (
        f' <time datetime="{html.escape(checked_at[0], quote=True)}">'
        f"({html.escape(checked_at[1])})</time>"
        if checked_at
        else ""
    )
    tone_by_state = {
        "passed": "ok",
        "failed": "bad",
        "inconclusive": "warn",
    }
    callout_tone = tone_by_state.get(check_state, "")
    cls = f"callout {callout_tone}" if callout_tone else "callout"
    role_attr = ' role="alert"' if check_state == "failed" else ""
    return (
        f'<div class="{cls}"{role_attr}><p>{html.escape(detail)}{time_html}</p></div>'
    )


def render_error_card(
    heading: str,
    badge_label: str,
    badge_tone: str,
    message: str,
    *,
    action_html: str = "",
) -> str:
    kit_tone = _TONE_MAP.get(badge_tone, "neutral")
    callout_cls = f"callout {kit_tone}" if kit_tone != "neutral" else "callout"
    actions = f'<div class="actions">{action_html}</div>' if action_html else ""
    return (
        "<article>"
        f'<div class="card-head"><h2>{html.escape(heading)}</h2>'
        f"{render_pill(badge_label, kit_tone)}</div>"
        f'<div class="{callout_cls}" role="alert"><p>{html.escape(message)}</p></div>'
        f"{actions}</article>"
    )
