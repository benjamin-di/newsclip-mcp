"""Best-in-class server-rendered UI components for Newsclip Connections.

Pure HTML and scoped CSS (no external assets, no custom JavaScript) so the page
works inside signin-window's strict Content-Security-Policy and degrades cleanly
without JavaScript. All dynamic text is escaped before rendering.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

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
:root{
  --bg:#f3f5f9;--surface:#ffffff;--surface-2:#f7f9fc;--text:#111c2d;--muted:#526175;
  --line:#dce3ee;--line-strong:#c4cfdf;--accent:#1d4ed8;--accent-hover:#1e40af;--on-accent:#ffffff;
  --danger:#b4232c;--danger-hover:#911b22;
  --ok:#117a43;--ok-bg:#eaf7ef;--ok-border:#b7e4c7;
  --warn:#9a5b00;--warn-bg:#fff6e5;--warn-border:#f3d28f;
  --bad:#b4232c;--bad-bg:#fdecec;--bad-border:#f5b8bc;
  --info:#1d4ed8;--info-bg:#ebf2ff;--info-border:#bfd5ff;
  --neutral-bg:#eef2f7;--neutral-border:#d5dde8;
  --shadow:0 1px 2px rgba(15,23,42,.04),0 6px 20px rgba(15,23,42,.05);
  --radius:1rem;--radius-sm:.65rem;
}
@media(prefers-color-scheme:dark){
  :root{
    --bg:#0d141f;--surface:#151f2e;--surface-2:#1b273a;--text:#edf2fa;--muted:#9fb0c7;
    --line:#2a3a52;--line-strong:#3b4f6e;--accent:#6ea8fe;--accent-hover:#8bb9fe;--on-accent:#0b1729;
    --danger:#e0525e;--danger-hover:#eb6b76;
    --ok:#4ade80;--ok-bg:rgba(34,197,94,.13);--ok-border:rgba(74,222,128,.32);
    --warn:#fbbf24;--warn-bg:rgba(245,158,11,.14);--warn-border:rgba(251,191,36,.34);
    --bad:#f87171;--bad-bg:rgba(239,68,68,.15);--bad-border:rgba(248,113,113,.35);
    --info:#7cb3ff;--info-bg:rgba(59,130,246,.16);--info-border:rgba(124,179,255,.35);
    --neutral-bg:rgba(148,163,184,.12);--neutral-border:rgba(148,163,184,.26);
    --shadow:0 1px 2px rgba(0,0,0,.28),0 10px 26px rgba(0,0,0,.28);
  }
}
main{max-width:54rem;margin:2rem auto;padding:1.25rem 1.5rem 3rem}
h1{font-size:clamp(1.65rem,4vw,2.1rem);letter-spacing:-.035em;margin:0 0 .35rem}
.eyebrow{letter-spacing:.1em;font-size:.74rem;color:var(--accent)}

/* Top account bar */
.nc-topbar{
  display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap;
  margin:0 0 1.25rem;padding-bottom:1rem;border-bottom:1px solid var(--line);
}
.nc-user-chip{
  display:inline-flex;align-items:center;gap:.5rem;margin:0;
  font-size:.92rem;color:var(--muted);
}
.nc-user-dot{
  width:.55rem;height:.55rem;border-radius:999px;background:var(--ok);flex:none;
}
.nc-topbar form{margin:0}
.nc-topbar button.quiet{
  min-height:36px;padding:.35rem .75rem;font-size:.88rem;border:1px solid var(--line);
  border-radius:.5rem;color:var(--muted);background:var(--surface);
}
.nc-topbar button.quiet:hover{border-color:var(--line-strong);color:var(--text)}

/* Health overview strip */
.nc-overview{
  display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;
  background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  padding:1rem 1.25rem;margin:0 0 1.35rem;box-shadow:var(--shadow);
}
.nc-stats{display:flex;align-items:center;gap:.65rem;flex-wrap:wrap}
.nc-stat{
  display:inline-flex;align-items:center;gap:.45rem;padding:.38rem .75rem;
  border-radius:999px;font-size:.86rem;font-weight:600;
  border:1px solid var(--neutral-border);background:var(--neutral-bg);
  color:var(--text);font-variant-numeric:tabular-nums;
}
.nc-stat--ok{background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok)}
.nc-stat--warn{
  background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn);
}
.nc-stat--bad{background:var(--bad-bg);border-color:var(--bad-border);color:var(--bad)}
.nc-stat--info{
  background:var(--info-bg);border-color:var(--info-border);color:var(--info);
}
.nc-stat-dot{
  width:.5rem;height:.5rem;border-radius:999px;background:currentColor;flex:none;
}
.nc-overview-actions{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.nc-overview-actions form{margin:0}
.nc-overview-actions button{
  min-height:38px;padding:.45rem .9rem;font-size:.88rem;font-weight:600;
}

/* Publisher cards */
.nc-cards{display:grid;gap:1rem}
article.nc-card{
  position:relative;background:var(--surface);border:1px solid var(--line);
  border-radius:var(--radius);padding:1.35rem 1.4rem 1.25rem;margin:0;
  box-shadow:var(--shadow);overflow:hidden;
}
article.nc-card::before{
  content:"";position:absolute;inset:0 auto 0 0;width:4px;
  background:var(--neutral-border);
}
article.nc-card.nc-tone-ok::before{background:var(--ok)}
article.nc-card.nc-tone-warn::before{background:var(--warn)}
article.nc-card.nc-tone-bad::before{background:var(--bad)}
article.nc-card.nc-tone-info::before{background:var(--info)}

.nc-card-head{
  display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap;
  margin-bottom:.85rem;
}
.nc-pub{display:flex;align-items:center;gap:.8rem;min-width:0}
.nc-avatar{
  width:2.55rem;height:2.55rem;border-radius:.7rem;flex:none;
  display:grid;place-items:center;font-weight:800;font-size:.78rem;letter-spacing:.03em;
  background:var(--neutral-bg);color:var(--text);border:1px solid var(--neutral-border);
}
.nc-avatar--ft{background:#fce7d8;color:#7c2d12;border-color:#f3c4a4}
.nc-avatar--economist{background:#fee2e2;color:#991b1b;border-color:#fca5a5}
.nc-avatar--wsj{background:#e2e8f0;color:#0f172a;border-color:#cbd5e1}
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
    background:rgba(148,163,184,.18);color:#e2e8f0;border-color:rgba(148,163,184,.34);
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
.nc-pub-title{margin:0;font-size:1.15rem;line-height:1.25;letter-spacing:-.015em}
.nc-pub-sub{margin:.15rem 0 0;font-size:.82rem;color:var(--muted)}

/* Status pill */
.nc-pill{
  display:inline-flex;align-items:center;gap:.45rem;padding:.3rem .72rem;
  border-radius:999px;font-size:.82rem;font-weight:700;line-height:1.2;
  border:1px solid var(--neutral-border);background:var(--neutral-bg);
  color:var(--muted);white-space:nowrap;
}
.nc-pill--ok{background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok)}
.nc-pill--warn{
  background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn);
}
.nc-pill--bad{background:var(--bad-bg);border-color:var(--bad-border);color:var(--bad)}
.nc-pill--info{
  background:var(--info-bg);border-color:var(--info-border);color:var(--info);
}
.nc-pill--muted{
  background:var(--neutral-bg);border-color:var(--neutral-border);color:var(--muted);
}
.nc-pill-dot{
  width:.5rem;height:.5rem;border-radius:999px;background:currentColor;flex:none;
}
.nc-pill--pulse .nc-pill-dot{animation:nc-pulse 1.4s ease-in-out infinite}
@keyframes nc-pulse{
  0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.82)}
}
@media(prefers-reduced-motion:reduce){.nc-pill--pulse .nc-pill-dot{animation:none}}

/* Callout & check banner */
.nc-callout{
  margin:.25rem 0 .75rem;padding:.65rem .85rem;border-radius:var(--radius-sm);
  font-size:.93rem;font-weight:500;line-height:1.45;
  background:var(--neutral-bg);border:1px solid var(--neutral-border);color:var(--text);
}
.nc-callout--ok{background:var(--ok-bg);border-color:var(--ok-border)}
.nc-callout--warn{background:var(--warn-bg);border-color:var(--warn-border)}
.nc-callout--bad{background:var(--bad-bg);border-color:var(--bad-border)}
.nc-callout--info{background:var(--info-bg);border-color:var(--info-border)}

.nc-check-result{
  margin:0 0 .75rem;padding:.55rem .8rem;border-radius:var(--radius-sm);
  font-size:.86rem;line-height:1.4;border:1px solid var(--line);
  background:var(--surface-2);color:var(--text);
}
.nc-check-result--passed{
  background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok);
}
.nc-check-result--failed{
  background:var(--bad-bg);border-color:var(--bad-border);color:var(--bad);
}
.nc-check-result--inconclusive{
  background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn);
}
.nc-check-result--checking{
  background:var(--info-bg);border-color:var(--info-border);color:var(--info);
}

/* Metadata strip */
.nc-meta{
  display:flex;align-items:center;gap:.5rem 1.15rem;flex-wrap:wrap;
  margin:0 0 .9rem;font-size:.83rem;color:var(--muted);
  font-variant-numeric:tabular-nums;
}
.nc-meta-item{display:inline-flex;align-items:center;gap:.35rem}
.nc-meta-sep{opacity:.4}

/* Action bar */
.nc-actions{
  display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;margin:.2rem 0 0;
}
.nc-actions form{margin:0}
.nc-actions button,.nc-actions .button{
  min-height:40px;padding:.5rem .95rem;font-size:.9rem;font-weight:600;
  border-radius:.55rem;transition:background-color .12s ease,border-color .12s ease;
}
.nc-actions button.primary,.nc-actions .button{
  background:var(--accent);border-color:var(--accent);color:var(--on-accent);
}
.nc-actions button.primary:hover,.nc-actions .button:hover{
  background:var(--accent-hover);border-color:var(--accent-hover);
}
.nc-actions button.secondary{
  background:var(--surface);border-color:var(--line-strong);color:var(--text);
}
.nc-actions button.secondary:hover{
  background:var(--surface-2);border-color:var(--accent);color:var(--accent);
}
.nc-actions button.quiet{color:var(--muted);border-color:transparent}
.nc-actions button.quiet:hover{color:var(--text);background:var(--surface-2)}

/* Sharing & account selection */
.nc-sharing{
  margin-top:1rem;padding-top:.9rem;border-top:1px solid var(--line);
}
.nc-sharing-head{
  display:flex;align-items:center;justify-content:space-between;gap:.6rem;flex-wrap:wrap;
  margin:0 0 .55rem;
}
.nc-sharing-summary{
  margin:0;padding:.35rem .65rem;border-radius:.5rem;font-size:.86rem;font-weight:600;
  background:var(--surface-2);border:1px solid var(--line);color:var(--text);
}
.nc-offer-list{display:grid;gap:.55rem;margin:.6rem 0}
.nc-offer-row{
  display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap;
  padding:.65rem .8rem;border-radius:var(--radius-sm);
  background:var(--surface-2);border:1px solid var(--line);
}
.nc-offer-info{min-width:0;flex:1 1 14rem}
.nc-offer-title{
  margin:0;font-size:.9rem;font-weight:600;display:flex;align-items:center;
  gap:.45rem;flex-wrap:wrap;
}
.nc-offer-detail{margin:.2rem 0 0;font-size:.82rem;color:var(--muted)}
.nc-offer-actions{display:flex;align-items:center;gap:.45rem;flex-wrap:wrap}
.nc-offer-actions form{margin:0}
.nc-offer-actions button{
  min-height:36px;padding:.35rem .75rem;font-size:.84rem;font-weight:600;
}

.nc-members{display:grid;gap:.45rem;margin:.65rem 0 0}
.nc-member-row{
  display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap;
  padding:.55rem .75rem;border-radius:.55rem;background:var(--surface-2);
  border:1px solid var(--line);
}
.nc-member-name{margin:0;font-size:.9rem;font-weight:600}
.nc-member-row form{margin:0}
.nc-member-row button{
  min-height:36px;padding:.35rem .75rem;font-size:.84rem;font-weight:600;
}

/* Disclosures */
article.nc-card details{
  margin-top:.85rem;padding-top:.2rem;border-top:1px solid var(--line);
}
article.nc-card details>summary{font-size:.88rem;min-height:38px;padding:.45rem 0}
article.nc-card details.manage{margin-top:.75rem}
article.nc-card details.manage p{font-size:.86rem;margin:.25rem 0 .65rem}

.nc-footer-note{
  margin:1.5rem 0 0;font-size:.84rem;color:var(--muted);line-height:1.5;
}

@media(max-width:540px){
  main{margin:.75rem auto;padding:.9rem 1rem 2rem}
  article.nc-card{padding:1.1rem 1.05rem}
  .nc-overview{padding:.9rem 1rem}
  .nc-actions{display:grid;grid-template-columns:1fr}
  .nc-actions button,.nc-actions .button{width:100%;text-align:center}
  .nc-offer-row,.nc-member-row{flex-direction:column;align-items:stretch}
  .nc-offer-actions button,.nc-member-row button{width:100%}
}
"""


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
        return ("disconnected", "Disconnected", "muted", detail)

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
    extra = " nc-pill--pulse" if pulse else ""
    return (
        f'<span class="nc-pill nc-pill--{html.escape(tone, quote=True)}{extra}">'
        f'<span class="nc-pill-dot" aria-hidden="true"></span>'
        f"{html.escape(label)}</span>"
    )


def render_topbar(display_name: str, logout_action: str) -> str:
    return (
        '<div class="nc-topbar">'
        '<p class="nc-user-chip">'
        '<span class="nc-user-dot" aria-hidden="true"></span>'
        f"<span>Signed in as <strong>{html.escape(display_name)}</strong></span>"
        "</p>"
        f'<form method="post" action="{html.escape(logout_action, quote=True)}">'
        '<button class="quiet">Sign out of Connections</button></form>'
        "</div>"
    )


def render_overview(
    effective_tones: Sequence[str],
    *,
    check_all_action: str | None,
    any_checking: bool,
) -> str:
    working = sum(1 for tone in effective_tones if tone == "ok")
    attention = sum(1 for tone in effective_tones if tone in ("warn", "bad"))
    in_progress = sum(1 for tone in effective_tones if tone == "info")
    not_connected = sum(1 for tone in effective_tones if tone == "muted")

    stats: list[str] = []
    if working:
        stats.append(
            '<span class="nc-stat nc-stat--ok">'
            '<span class="nc-stat-dot" aria-hidden="true"></span>'
            f"{working} Working</span>"
        )
    if attention:
        cls = "nc-stat--bad" if "bad" in effective_tones else "nc-stat--warn"
        stats.append(
            f'<span class="nc-stat {cls}">'
            '<span class="nc-stat-dot" aria-hidden="true"></span>'
            f"{attention} Needs attention</span>"
        )
    if in_progress:
        stats.append(
            '<span class="nc-stat nc-stat--info">'
            '<span class="nc-stat-dot" aria-hidden="true"></span>'
            f"{in_progress} In progress</span>"
        )
    if not_connected:
        stats.append(
            '<span class="nc-stat">'
            '<span class="nc-stat-dot" aria-hidden="true"></span>'
            f"{not_connected} Not connected</span>"
        )
    if not stats:
        stats.append('<span class="nc-stat">No subscriptions configured</span>')

    right = ""
    if any_checking:
        right = (
            '<div class="nc-overview-actions">'
            + render_pill("Checking access…", "info", pulse=True)
            + "</div>"
        )
    elif check_all_action:
        right = (
            '<div class="nc-overview-actions">'
            f'<form method="post" action="{html.escape(check_all_action, quote=True)}">'
            '<button class="secondary">Check all</button></form>'
            "</div>"
        )

    return (
        '<section class="nc-overview" aria-label="Access summary">'
        f'<div class="nc-stats">{"".join(stats)}</div>'
        f"{right}</section>"
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
    items: list[str] = []
    formatted = format_utc_time(last_verified)
    if formatted is not None:
        iso, utc_text = formatted
        rel = format_relative_age(verified_age_seconds)
        if rel:
            items.append(
                f'<span class="nc-meta-item">Last verified: '
                f'<time datetime="{html.escape(iso, quote=True)}" '
                f'title="{html.escape(utc_text, quote=True)}">'
                f"{html.escape(rel)} ({html.escape(utc_text)})</time></span>"
            )
        else:
            items.append(
                f'<span class="nc-meta-item">Last verified: '
                f'<time datetime="{html.escape(iso, quote=True)}">'
                f"{html.escape(utc_text)}</time></span>"
            )
    if source_label:
        items.append(f'<span class="nc-meta-item">{html.escape(source_label)}</span>')
    if not items:
        return ""
    sep = '<span class="nc-meta-sep" aria-hidden="true">·</span>'
    return f'<div class="nc-meta">{sep.join(items)}</div>'


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
    role = "alert" if check_state == "failed" else "status"
    state_cls = html.escape(check_state, quote=True)
    return (
        f'<p class="nc-check-result nc-check-result--{state_cls}" '
        f'role="{role}">{html.escape(detail)}{time_html}</p>'
    )
