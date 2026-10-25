"""``python -m newsclip`` — the same CLI as the console script.

The ops MCP surface shells out to the CLI via the interpreter so repair verbs
work in any environment where the package is importable, PATH or not.
"""

from newsclip.cli import run

run()
