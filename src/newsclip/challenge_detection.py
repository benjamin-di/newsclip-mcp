"""Side-effect-free vendor and surface classification."""

from __future__ import annotations

import math
from collections.abc import Mapping

from pydantic import ValidationError

from .challenges import (
    ChallengeDetection,
    ChallengeInfrastructureError,
    ChallengeState,
    ChallengeVendor,
)


class ChallengeDetectionError(ChallengeInfrastructureError):
    """The browser returned a malformed challenge classification."""


DETECTION_SCRIPT = r"""
() => {
  const visible = (element, minimum = 8) => {
    if (!element) return false;
    const box = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    const viewportWidth = window.innerWidth
      || document.documentElement?.clientWidth || 0;
    const viewportHeight = window.innerHeight
      || document.documentElement?.clientHeight || 0;
    return box.width >= minimum && box.height >= minimum
      && style.display !== 'none' && style.visibility !== 'hidden'
      && Number(style.opacity || 1) > 0
      && box.right > 0 && box.bottom > 0
      && box.left < viewportWidth && box.top < viewportHeight;
  };
  const source = (document.documentElement?.innerHTML || '').toLowerCase();
  const text = (document.body?.innerText || '').toLowerCase();
  const hostname = String(location.hostname || '').toLowerCase();
  const hcaptchaFrames = Array.from(document.querySelectorAll(
    'iframe[src*="hcaptcha.com"], iframe[src*="newassets.hcaptcha.com"]'
  ));
  const hcaptchaAsset = /hcaptcha\.com|newassets\.hcaptcha|h-captcha/.test(source);
  const hcaptchaInteractive = hcaptchaFrames.some((frame) => {
    const src = String(frame.getAttribute('src') || '');
    return visible(frame, 20)
      && (src.includes('frame=challenge') || src.includes('frame=checkbox'));
  });
  const hcaptchaSolved = Array.from(document.querySelectorAll(
    '[data-hcaptcha-state="solved"]'
  )).some((element) => visible(element));
  const datadomePage = hostname === 'captcha-delivery.com'
    || hostname.endsWith('.captcha-delivery.com');
  const datadomeAsset = datadomePage
    || /captcha-delivery\.com|datadome/.test(source);
  const datadomeInteractive = Array.from(document.querySelectorAll(
    'iframe[src*="captcha-delivery"], [data-captcha-provider="datadome"]'
  )).some((element) => visible(element, 20))
    || (
      datadomePage
      && Array.from(document.querySelectorAll('.slider, .sliderIcon'))
        .some((element) => visible(element))
      && Array.from(document.querySelectorAll('.sliderContainer, .sliderbg'))
        .some((element) => visible(element, 20))
    );
  const pxRuntimeAsset = !!document.querySelector(
    'script[src*="perimeterx"], script[src*="humansecurity"], '
      + 'script[src*="px-cdn"], iframe[src*="captcha.px-cdn.net"]'
  );
  const pxAsset = pxRuntimeAsset
    || /px-captcha|perimeterx|humansecurity/.test(source);
  const hasPxInstruction = (value) => {
    const normalized = String(value || '').toLowerCase();
    return normalized.includes('press and hold')
      || normalized.includes('press & hold');
  };
  const pxTextControl = Array.from(document.querySelectorAll(
    'button, [role="button"]'
  )).some((element) => visible(element, 20)
    && hasPxInstruction(element.innerText));
  const pxInteractive = Array.from(document.querySelectorAll(
    '#px-captcha, [data-px-captcha], iframe[src*="captcha.px-cdn.net"]'
  )).some((element) => visible(element, 20))
    || (pxRuntimeAsset && pxTextControl);
  const recaptchaAsset = /google\.com\/recaptcha|g-recaptcha|grecaptcha/.test(source);
  // The invisible/v3 badge is a visible 256x60 anchor iframe on served
  // pages (AP articles); only a checkbox anchor or a bframe asks a human.
  const recaptchaInteractive = Array.from(document.querySelectorAll(
    '.g-recaptcha:not([data-size="invisible"]), '
      + 'iframe[src*="recaptcha/api2/anchor"]:not([src*="size=invisible"]), '
      + 'iframe[src*="recaptcha/api2/bframe"]'
  )).some((element) => visible(element, 20)
    && !element.closest('.grecaptcha-badge'));
  const cloudflareInterstitial = (
    String(document.title || '').trim().toLowerCase() === 'just a moment...'
    && (
      source.includes('/cdn-cgi/challenge-platform/')
      || source.includes('_cf_chl_opt')
      || source.includes('challenges.cloudflare.com')
    )
  );
  const turnstileAsset =
    /challenges\.cloudflare\.com|cf-turnstile|turnstile/.test(source);
  const turnstileInteractive = Array.from(document.querySelectorAll(
    '.cf-turnstile, iframe[src*="challenges.cloudflare.com"]'
  )).some((element) => visible(element, 20));
  const explicitUnknownInteractive = Array.from(document.querySelectorAll(
    '[data-visible-challenge="true"]'
  )).some((element) => visible(element, 20));
  const hasGenericChallengeText = (value) => {
    const normalized = String(value || '').toLowerCase();
    return normalized.includes('complete the captcha')
      || normalized.includes('verify you are human');
  };
  const genericChallengeText = hasGenericChallengeText(text);
  const articleRootSelector = (
    'article, [role="article"], [data-article-body], '
      + '[class*="article-body" i], [class*="story-body" i]'
  );
  const visibleArticle = Array.from(document.querySelectorAll(
    articleRootSelector
  )).some((element) => visible(element, 20));
  const articleIdentity = visibleArticle || !!document.querySelector(
    'meta[property="og:type"][content*="article" i], '
      + '[data-article-body], [class*="article-body" i], '
      + '[class*="story-body" i]'
  );
  const modalUnknownInterstitial = Array.from(document.querySelectorAll(
    '[role="dialog"], [aria-modal="true"]'
  )).some((element) => (
    visible(element, 20) && hasGenericChallengeText(element.innerText)
  ));
  const namedUnknownInterstitial = Array.from(document.querySelectorAll(
    '[id*="captcha" i], [class*="captcha" i], '
      + '[id*="challenge" i], [class*="challenge" i]'
  )).some((element) => (
    visible(element, 20)
      && hasGenericChallengeText(element.innerText)
      && !element.closest(articleRootSelector)
  ));
  const ambiguousUnknownInterstitial = genericChallengeText
    && !articleIdentity
    && text.trim().length <= 1200
    && Array.from(document.querySelectorAll('main, form')).some((element) => (
      visible(element, 20) && hasGenericChallengeText(element.innerText)
    ));
  const unknownInteractive = explicitUnknownInteractive
    || modalUnknownInterstitial
    || namedUnknownInterstitial
    || ambiguousUnknownInterstitial;
  if (hcaptchaInteractive) return {vendor: 'hcaptcha', state: 'interactive'};
  if (datadomeInteractive) return {vendor: 'datadome', state: 'interactive'};
  if (pxInteractive) return {vendor: 'perimeterx', state: 'interactive'};
  if (recaptchaInteractive) return {vendor: 'recaptcha', state: 'interactive'};
  // A full-page Cloudflare passage can require only JavaScript and waiting,
  // but it is still an active blocking surface that needs the resolver path.
  if (cloudflareInterstitial) {
    return {vendor: 'cloudflare_interstitial', state: 'interactive'};
  }
  if (turnstileInteractive) return {vendor: 'turnstile', state: 'interactive'};
  if (unknownInteractive) return {vendor: 'unsupported', state: 'interactive'};
  if (hcaptchaSolved) return {vendor: 'hcaptcha', state: 'solved'};
  if (hcaptchaAsset) return {vendor: 'hcaptcha', state: 'asset_only'};
  if (datadomeAsset) return {vendor: 'datadome', state: 'asset_only'};
  if (pxAsset) return {vendor: 'perimeterx', state: 'asset_only'};
  if (recaptchaAsset) return {vendor: 'recaptcha', state: 'asset_only'};
  if (turnstileAsset) return {vendor: 'turnstile', state: 'asset_only'};
  return {vendor: 'none', state: 'none'};
}
"""

_NATIVE_INTERACTIVE_SELECTORS = (
    (
        ChallengeVendor.HCAPTCHA,
        (
            'iframe[src*="hcaptcha.com"][src*="frame=challenge"]',
            'iframe[src*="hcaptcha.com"][src*="frame=checkbox"]',
            '[data-hcaptcha-state="interactive"]',
        ),
    ),
    (
        ChallengeVendor.DATADOME,
        (
            'iframe[src*="captcha-delivery"]',
            '[data-captcha-provider="datadome"]',
            ".sliderContainer:has(.slider), .sliderContainer:has(.sliderIcon)",
        ),
    ),
    (
        ChallengeVendor.PERIMETERX,
        (
            "#px-captcha",
            "[data-px-captcha]",
            'iframe[src*="captcha.px-cdn.net"]',
            '#px-captcha button:has-text("Press & Hold")',
            '#px-captcha button:has-text("Press and Hold")',
            '[data-px-captcha] [role="button"]:has-text("Press & Hold")',
            '[data-px-captcha] [role="button"]:has-text("Press and Hold")',
        ),
    ),
    (
        ChallengeVendor.RECAPTCHA,
        (
            '.g-recaptcha:not([data-size="invisible"])',
            'iframe[src*="recaptcha/api2/anchor"]:not([src*="size=invisible"])'
            ":not(.grecaptcha-badge iframe)",
            'iframe[src*="recaptcha/api2/bframe"]',
        ),
    ),
    (
        ChallengeVendor.TURNSTILE,
        (
            ".cf-turnstile",
            'iframe[src*="challenges.cloudflare.com"]',
        ),
    ),
    (
        ChallengeVendor.UNSUPPORTED,
        ('[data-visible-challenge="true"]',),
    ),
)
_NATIVE_MATCH_LIMIT = 10
_NATIVE_PREFILTER_SELECTOR = ", ".join(
    selector for _, selectors in _NATIVE_INTERACTIVE_SELECTORS for selector in selectors
)
_CONTEXT_REPLACEMENT_ATTEMPTS = 2
_VIEWPORT_SCRIPT = """
() => ({
  width: window.innerWidth || document.documentElement?.clientWidth || 0,
  height: window.innerHeight || document.documentElement?.clientHeight || 0,
})
"""


def detect_challenge(browser: object) -> ChallengeDetection:
    """Classify a page without clicking, writing, or exposing DOM text."""

    for attempt in range(_CONTEXT_REPLACEMENT_ATTEMPTS):
        try:
            return _detect_challenge_once(browser)
        except ChallengeDetectionError as error:
            if attempt + 1 == _CONTEXT_REPLACEMENT_ATTEMPTS or not _context_replaced(
                error
            ):
                raise
    raise AssertionError("challenge detection retry loop exhausted")  # pragma: no cover


def detect_challenge_for_reads(browser: object) -> ChallengeDetection:
    """Classify like :func:`detect_challenge`, prefiltering the native sweep.

    Retrieval pages are usually challenge-free, yet the per-selector native
    sweep still costs dozens of driver roundtrips that queue behind a busy
    just-navigated main thread. One shadow-piercing union count skips the sweep
    when no native challenge surface exists at all; any match — or any doubt —
    falls back to the full sweep, so classification outcomes are unchanged.
    """

    for attempt in range(_CONTEXT_REPLACEMENT_ATTEMPTS):
        try:
            return _detect_challenge_once(browser, native_prefilter=True)
        except ChallengeDetectionError as error:
            if attempt + 1 == _CONTEXT_REPLACEMENT_ATTEMPTS or not _context_replaced(
                error
            ):
                raise
    raise AssertionError("challenge detection retry loop exhausted")  # pragma: no cover


def _detect_challenge_once(
    browser: object,
    *,
    native_prefilter: bool = False,
) -> ChallengeDetection:
    try:
        raw = browser.evaluate(DETECTION_SCRIPT)  # type: ignore[attr-defined]
    except Exception as error:
        raise ChallengeDetectionError("challenge detector evaluation failed") from error
    if not isinstance(raw, Mapping):
        raise ChallengeDetectionError("challenge detector returned a non-object")
    try:
        detection = ChallengeDetection.model_validate(raw)
    except ValidationError as error:
        raise ChallengeDetectionError(
            "challenge detector returned an invalid classification"
        ) from error
    if detection.state is ChallengeState.INTERACTIVE:
        return detection
    if native_prefilter and _native_surface_absent(browser):
        return detection
    native = _native_interactive_challenge(browser)
    return native if native is not None else detection


def _native_surface_absent(browser: object) -> bool:
    """Count every native candidate in one roundtrip; sweep on any doubt."""

    try:
        page = browser.page  # type: ignore[attr-defined]
        count = page.locator(_NATIVE_PREFILTER_SELECTOR).count()
    except Exception:
        return False
    return isinstance(count, int) and not isinstance(count, bool) and count == 0


def _context_replaced(error: BaseException) -> bool:
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in chain and len(chain) < 6:
        chain.append(current)
        current = current.__cause__ or current.__context__
    material = " ".join(f"{type(item).__name__} {item}".lower() for item in chain)
    return any(
        marker in material
        for marker in (
            "execution context",
            "context was destroyed",
            "frame was detached",
            "frame detached",
            "most likely because of a navigation",
        )
    )


def _native_interactive_challenge(browser: object) -> ChallengeDetection | None:
    """See generic controls hidden from document.querySelector by open roots."""

    try:
        page = browser.page  # type: ignore[attr-defined]
        locate = page.locator
        if not callable(locate):
            raise TypeError("browser page has no locator engine")
        for vendor, selectors in _NATIVE_INTERACTIVE_SELECTORS:
            for selector in selectors:
                locator = locate(selector)
                count = locator.count()
                if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                    raise TypeError("browser locator returned an invalid count")
                for index in range(min(count, _NATIVE_MATCH_LIMIT)):
                    if _native_locator_is_visible(page, locator.nth(index)):
                        return ChallengeDetection(
                            vendor=vendor,
                            state=ChallengeState.INTERACTIVE,
                        )
    except Exception as error:
        raise ChallengeDetectionError(
            "challenge native-locator fallback failed"
        ) from error
    return None


def _native_locator_is_visible(page: object, locator: object) -> bool:
    if not locator.is_visible():  # type: ignore[attr-defined]
        return False
    box = locator.bounding_box()  # type: ignore[attr-defined]
    viewport = page.evaluate(_VIEWPORT_SCRIPT)  # type: ignore[attr-defined]
    if not isinstance(box, Mapping) or not isinstance(viewport, Mapping):
        raise TypeError("browser locator geometry is unavailable")
    try:
        x, y, width, height = (float(box[key]) for key in ("x", "y", "width", "height"))
        viewport_width, viewport_height = (
            float(viewport[key]) for key in ("width", "height")
        )
    except (KeyError, TypeError, ValueError) as error:
        raise TypeError("browser locator geometry is invalid") from error
    geometry = (x, y, width, height, viewport_width, viewport_height)
    if not all(math.isfinite(value) for value in geometry):
        raise TypeError("browser locator geometry is invalid")
    return (
        width >= 8
        and height >= 8
        and viewport_width > 0
        and viewport_height > 0
        and x + width > 0
        and y + height > 0
        and x < viewport_width
        and y < viewport_height
    )
