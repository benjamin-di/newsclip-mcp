.PHONY: check check-mcp check-standalone check-runtime-lock

# Keep local and CI verification identical. Live providers are always explicit.
check: check-runtime-lock
	uv run --locked --extra local ruff check .
	uv run --locked --extra local ruff format --check .
	uv run --locked --extra local mypy src/newsclip
	uv run --locked --extra local pytest -q -m "not live"
	git diff --check

# Keep image dependencies independent of the application's release version.
check-runtime-lock:
	@test ! -f deploy/requirements.runtime.txt || { expected=$$(mktemp); trap 'rm -f "$$expected"' EXIT; \
	uv export --locked --extra local --no-dev --extra mcp --no-emit-project --no-header --output-file "$$expected" >/dev/null && \
	diff -u deploy/requirements.runtime.txt "$$expected"; }

check-mcp:
	uv run --locked --extra local --extra mcp pytest -q -m "not live" tests/test_mcp.py tests/test_mcp_http.py tests/test_drift.py tests/test_serving_recovery_workflow.py

check-standalone:
	uv run --locked --extra local --extra mcp --extra signin pytest -q tests/test_standalone.py tests/test_remote_cli.py
