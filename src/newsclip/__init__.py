"""Personal subscription-news retrieval and archiving."""

__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    if name == "__version__":
        from importlib.metadata import version

        value = version("newsclip")
        globals()["__version__"] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
