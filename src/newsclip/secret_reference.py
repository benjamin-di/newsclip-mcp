"""Explicit secret-store identity; no implicit privilege escalation."""

import subprocess as subprocess

from signin_window.automation.secrets import OpSecretReader as OpSecretReader
from signin_window.automation.secrets import (
    SecretResolutionError as SecretResolutionError,
)
