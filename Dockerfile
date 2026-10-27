# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS browser-node
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS base
COPY --from=browser-node /usr/local/bin/node /usr/local/bin/browser-node
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy \
    PATH=/app/.venv/bin:$PATH PLAYWRIGHT_BROWSERS_PATH=/opt/chromium \
    HOME=/tmp/newsclip-home NEWSCLIP_STATE_HOME=/state NEWSCLIP_DATA_HOME=/data \
    PLAYWRIGHT_NODEJS_PATH=/usr/local/bin/browser-node
COPY --from=uv /uv /uvx /usr/local/bin/
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends ca-certificates curl dumb-init libxtst6 xvfb \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
RUN uv sync --locked --no-dev --extra mcp --extra signin --no-install-project \
 && patchright install --with-deps chromium \
 && /app/.venv/bin/python -c "from pathlib import Path; import patchright; p = Path(patchright.__file__).parent / 'driver' / 'node'; p.unlink(); p.symlink_to('/usr/local/bin/browser-node')" \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 1000 newsclip \
 && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin newsclip
COPY src ./src
RUN uv sync --locked --no-dev --extra mcp --extra signin
ARG VCS_REF=unknown
ARG IMAGE_VERSION=development
ARG VERSION=${IMAGE_VERSION}
ARG SOURCE_URL=https://github.com/benjamin-di/newsclip-mcp
ARG BUILD_SOURCE_FINGERPRINT=
ENV NEWSCLIP_BUILD_REVISION=${VCS_REF} NEWSCLIP_BUILD_DIRTY=0 \
    NEWSCLIP_BUILD_SOURCE_FINGERPRINT=${BUILD_SOURCE_FINGERPRINT}
RUN if [ -n "$BUILD_SOURCE_FINGERPRINT" ]; then \
      test "$(python -c 'from pathlib import Path; from newsclip.provenance import build_source_identity; print(build_source_identity(Path("/app")).source_fingerprint)')" = "$BUILD_SOURCE_FINGERPRINT"; \
    fi
LABEL org.opencontainers.image.title="Newsclip" \
      org.opencontainers.image.description="Private news search, reading and archiving with human sign-in" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["dumb-init", "--"]

FROM base AS login
ENV NOVNC_DIR=/opt/novnc
ARG NOVNC_VERSION=1.6.0
ARG NOVNC_SHA256=5066103959ef4e9b10f37e5a148627360dd8414e4cf8a7db92bdbd022e728aaa
RUN apt-get update \
 && apt-get install -y --no-install-recommends x11vnc fonts-noto-cjk openssh-client \
 && curl --fail --silent --show-error --location \
      "https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.tar.gz" -o /tmp/novnc.tar.gz \
 && printf '%s  /tmp/novnc.tar.gz\n' "$NOVNC_SHA256" | sha256sum --check --status \
 && mkdir -p /opt/novnc \
 && tar -xzf /tmp/novnc.tar.gz -C /opt/novnc --strip-components=1 \
      "noVNC-${NOVNC_VERSION}/app" "noVNC-${NOVNC_VERSION}/core" \
      "noVNC-${NOVNC_VERSION}/vendor" "noVNC-${NOVNC_VERSION}/vnc.html" \
      "noVNC-${NOVNC_VERSION}/LICENSE.txt" "noVNC-${NOVNC_VERSION}/AUTHORS" \
      "noVNC-${NOVNC_VERSION}/docs/LICENSE.MPL-2.0" \
      "noVNC-${NOVNC_VERSION}/docs/LICENSE.OFL-1.1" \
      "noVNC-${NOVNC_VERSION}/docs/LICENSE.BSD-3-Clause" \
      "noVNC-${NOVNC_VERSION}/docs/LICENSE.BSD-2-Clause" \
 && python -m signin_window.browser install-policy \
 && rm -rf /tmp/novnc.tar.gz /var/lib/apt/lists/*
USER 1000:1000
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=2m --start-interval=2s --retries=3 \
 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8080/health"]
CMD ["newsclip", "signin-service", "--host", "0.0.0.0"]

FROM base AS server
USER 1000:1000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=2m --start-interval=2s --retries=3 \
 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8000/health"]
CMD ["newsclip", "serve", "--host", "0.0.0.0"]
