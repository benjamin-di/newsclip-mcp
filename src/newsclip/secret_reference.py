"""Explicit secret-store identity; no implicit privilege escalation."""

from signin_window.automation.secrets import OpSecretReader as OpSecretReader
from signin_window.automation.secrets import (
    SecretResolutionError as SecretResolutionError,
)
from signin_window.automation.secrets import subprocess as subprocess
