# Native Linux/amd64 only has been validated. Tags/apt packages float: not a
# reproducible-digest promise. Rebuild regularly for browser/security updates.
FROM node:24-bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium ca-certificates curl fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

FROM golang:1.26-bookworm AS build
ARG TARGETARCH
RUN test "$TARGETARCH" = amd64
WORKDIR /src
COPY --from=runtime-base /usr/local/bin/node /usr/local/bin/node
ENV PLAYWRIGHT_NODEJS_PATH=/usr/local/bin/node \
    PLAYWRIGHT_DRIVER_PATH=/opt/playwright
COPY go.mod go.sum ./
RUN go mod download && go mod verify
RUN module_version=$(go list -m -f '{{.Version}}' github.com/mxschmitt/playwright-go) \
    && go run "github.com/mxschmitt/playwright-go/cmd/playwright@$module_version" --version
COPY Makefile ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE
RUN CGO_ENABLED=0 make build VERSION="$VERSION" COMMIT="$COMMIT" DATE="$BUILD_DATE"

FROM runtime-base AS runtime
RUN groupadd --gid 10001 indago && useradd --uid 10001 --gid 10001 \
    --home-dir /var/cache/indago --no-create-home --shell /usr/sbin/nologin indago \
    && install -d -o 10001 -g 10001 -m 0750 /var/lib/indago /var/cache/indago
COPY --from=build /src/bin/indago /usr/local/bin/indago
COPY --from=build /opt/playwright/ /opt/playwright/
COPY --chmod=0755 deploy/docker/healthcheck.sh /usr/local/bin/indago-healthcheck
ENV HOME=/var/cache/indago \
    XDG_CACHE_HOME=/var/cache/indago \
    PLAYWRIGHT_NODEJS_PATH=/usr/local/bin/node \
    PLAYWRIGHT_DRIVER_PATH=/opt/playwright \
    INDAGO_CHROMIUM_PATH=/usr/bin/chromium \
    INDAGO_HEALTH_CA=/tls/ca.crt
WORKDIR /var/lib/indago
USER 10001:10001
VOLUME ["/var/lib/indago"]
EXPOSE 8750
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/indago-healthcheck"]
ENTRYPOINT ["/usr/local/bin/indago"]
# Fails closed without an environment token and a mounted TLS pair.
# -browser-no-sandbox is an EXPLICIT, knowing opt-out: Docker's default seccomp
# profile blocks the user namespaces Chromium's process sandbox needs, so the
# browser would not start at all. This lowers isolation from hostile pages; see
# docs/browser-sandbox.md for running sandboxed (relaxed seccomp) instead.
CMD ["serve", "-data", "/var/lib/indago", "-addr", "0.0.0.0:8750", "-allow-remote", "-tls-cert", "/tls/server.crt", "-tls-key", "/tls/server.key", "-browser", "-browser-no-sandbox"]
