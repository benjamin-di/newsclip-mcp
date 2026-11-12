# Build identity

Release images, wheels and source distributions carry `newsclip/build_identity.json`.
The stamp contains the service name, product version, full source revision,
bounded source fingerprint and dirty state. Runtime reads this installed resource
and the installed distribution version. Git and environment variables cannot
relabel it. Missing stamps are allowed only for an editable installation, which
reports an explicit `unknown` revision; invalid or conflicting stamps fail.

The fingerprint uses the existing provenance manifest of application Python,
provider definitions, `pyproject.toml` and `uv.lock`. The stamp itself is excluded
from that manifest. Historical environment, checkout, unavailable and legacy
trace identity states remain readable, including their original fingerprints.
Reading an old record never assigns it the current process identity.

Live acceptance requires a stamp matching the selected source fingerprint and,
when Git is available, its revision. Stamp the editable tree explicitly with
`uv run python scripts/embed-build-identity.py <product-version> <full-revision>`
after changing behavior. The private candidate runner stamps its copied tree
and installs matching distribution metadata before running acceptance.

| Surface | Attribution and verification |
| --- | --- |
| Application and SDK logging | Build and process instance added after existing formatters and filters; JSON values retain their types. Handler severity, streams, redaction and Rich console quiet state are preserved. |
| Executable startup failures | Closed error type and build/instance on stderr; raw exception inputs are omitted. |
| Uvicorn diagnostics | Identity formatter in each server's logging configuration; access logs remain disabled. |
| Browser and timing JSONL | Writers add producing identity; older records retain absent identity fields and original provenance evidence. |
| Recovery watcher | Closed scheduler outcomes gain the watcher's build/instance on their existing stream. Captured child command output remains suppressed. |
| MCP | SDK-native product version, tested with legacy initialization and current connection modes. Stdio stdout contains only protocol messages. |
| CLI/article/search/archive output | Content and result contracts remain unchanged; these are not diagnostic logs. |
| Connections and browser authentication HTML | Forward installed host identity through signin-window's public `PageIdentity` API when the factory accepts it. Older renderers keep their existing HTML. |
| Relay and direct viewer shells | Forward the same host identity through compatible `PageText` and `build_app` factories. Publisher pages and noVNC files remain dependency-owned. |

Both release workflows stamp before `uv build --no-sources`, check the actual
wheel and sdist against the selected source fingerprint, compare their packaged
application bytes, and probe an isolated wheel installation. The download-only
package upload path repeats these checks on the existing release assets without
restamping them. Docker installs a noneditable package, probes its identity and
native MCP version during build, and repeats acceptance on each candidate image.

These source checks do not establish that a registry image, published package or
running replica has adopted the change. Those artifacts require their normal
release and installed acceptance. Synthetic rendered-page tests exercise both
older renderers and compatible candidate renderers without opening a publisher
browser. The lock remains unchanged; installed adoption requires a compatible
renderer release.
