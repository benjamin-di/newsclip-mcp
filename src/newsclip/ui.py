"""Pass the host artifact identity to compatible shared page renderers."""

import inspect

from signin_window import connections as renderer

from .build_identity import BUILD


def renderer_options(factory):
    """Use the public identity API when present, keeping older releases usable."""
    identity_type = getattr(renderer, "PageIdentity", None)
    if identity_type is None or "identity" not in inspect.signature(factory).parameters:
        return {}
    return {
        "identity": identity_type(BUILD.service, BUILD.version, BUILD.source_revision)
    }
