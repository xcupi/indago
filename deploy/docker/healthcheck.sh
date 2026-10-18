#!/bin/sh
set -eu
# The certificate must have IP:127.0.0.1 in its SAN, regardless of external DNS.
# A private CA bundle is mounted separately from the leaf certificate/key.
exec curl --fail --silent --show-error --connect-timeout 2 --max-time 4 \
  --cacert "${INDAGO_HEALTH_CA:?set healthcheck CA bundle path}" \
  https://127.0.0.1:8750/healthz >/dev/null
