#!/usr/bin/env bash
# snout_oauth end to end on this machine: psql 18 signs in to a
# Postgres 18 (our real :18 pod image) through the OAuth device flow, against a throwaway issuer,
# and snout_oauth, built with scripts/build-dist.sh, decides. Nothing live is touched.
#
#   bash e2e/run.sh                   # writes e2e/results/run.txt; exits non-zero on any failure
#   E2E_LOGINS=60 bash e2e/run.sh     # more logins for the login-cost measurement
#
# Needs Docker (or STACK_ENGINE=podman) and Node 22 on the host.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
engine="${STACK_ENGINE:-docker}"
port=9998
issuer="http://host.docker.internal:$port"
mkdir -p "$here/results"

ISSUER="$issuer" PORT=$port node "$here/issuer.mjs" >"$here/results/issuer.log" 2>&1 &
issuer_pid=$!
trap 'kill $issuer_pid 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do
	curl -s "http://127.0.0.1:$port/.well-known/openid-configuration" >/dev/null && break
	sleep 0.25
done

"$engine" build -q -t snout-oauth-e2e -f "$here/Containerfile" "$root" >/dev/null
"$engine" run --rm --add-host=host.docker.internal:host-gateway \
	-e E2E_LOGINS="${E2E_LOGINS:-30}" \
	-v "$root:/src:ro" \
	-v snout-oauth-e2e-target:/cache/target \
	-v snout-oauth-e2e-registry:/opt/cargo/registry \
	snout-oauth-e2e bash /src/e2e/inside.sh "$issuer" 2>&1 | tee "$here/results/run.txt"
exit "${PIPESTATUS[0]}"
