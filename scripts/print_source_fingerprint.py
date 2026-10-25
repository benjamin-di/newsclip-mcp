"""Print the canonical fingerprint for the current behavior source."""

from pathlib import Path

from newsclip.provenance import build_source_identity


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    print(build_source_identity(repository).source_fingerprint)


if __name__ == "__main__":
    main()
