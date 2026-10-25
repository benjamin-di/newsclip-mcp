from __future__ import annotations

import pytest
from pydantic import ValidationError

from newsclip.account_keys import is_account_key, require_account_key
from newsclip.models import SessionHealth, SessionStatus


@pytest.mark.parametrize(
    "account_key",
    (
        "default",
        "A",
        "account-01_primary",
        "x" * 64,
    ),
)
def test_account_key_contract_accepts_only_bounded_path_safe_values(
    account_key: str,
) -> None:
    assert is_account_key(account_key)
    assert require_account_key(account_key) == account_key
    assert (
        SessionHealth(
            provider="ft",
            account_key=account_key,
            status=SessionStatus.REQUIRED,
        ).account_key
        == account_key
    )


@pytest.mark.parametrize(
    "account_key",
    (
        None,
        "",
        ".",
        "..",
        "../escape",
        "nested/account",
        "back\\slash",
        "white space",
        "é",
        "x" * 65,
    ),
)
def test_account_key_contract_rejects_ambiguous_or_unbounded_values(
    account_key: object,
) -> None:
    assert not is_account_key(account_key)
    with pytest.raises(ValueError, match="invalid account key"):
        require_account_key(account_key)
    with pytest.raises(ValidationError):
        SessionHealth(
            provider="ft",
            account_key=account_key,  # type: ignore[arg-type]
            status=SessionStatus.REQUIRED,
        )
