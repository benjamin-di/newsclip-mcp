"""Provider contracts plus lazy compatibility exports for built-in implementations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import ProviderSearchPage
from .base import Provider
from .registry import ProviderRegistry

if TYPE_CHECKING:
    from .bloomberg import BloombergProvider
    from .cnbc import CNBCProvider
    from .economist import EconomistProvider
    from .ft import FTProvider
    from .nyt import NYTProvider
    from .reuters import ReutersProvider
    from .wsj import WSJProvider

__all__ = [
    "BloombergProvider",
    "CNBCProvider",
    "EconomistProvider",
    "FTProvider",
    "NYTProvider",
    "Provider",
    "ProviderSearchPage",
    "ProviderRegistry",
    "ReutersProvider",
    "WSJProvider",
]


def __getattr__(name: str) -> object:
    value: object
    if name == "BloombergProvider":
        from .bloomberg import BloombergProvider

        value = BloombergProvider
    elif name == "CNBCProvider":
        from .cnbc import CNBCProvider

        value = CNBCProvider
    elif name == "EconomistProvider":
        from .economist import EconomistProvider

        value = EconomistProvider
    elif name == "FTProvider":
        from .ft import FTProvider

        value = FTProvider
    elif name == "NYTProvider":
        from .nyt import NYTProvider

        value = NYTProvider
    elif name == "ReutersProvider":
        from .reuters import ReutersProvider

        value = ReutersProvider
    elif name == "WSJProvider":
        from .wsj import WSJProvider

        value = WSJProvider
    else:
        raise AttributeError(name)
    globals()[name] = value
    return value
