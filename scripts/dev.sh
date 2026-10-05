#!/usr/bin/env bash
# Run one command inside snout_oauth's dev container.
#
#   bash scripts/dev.sh cargo pgrx test pg18
#   bash scripts/dev.sh cargo test --lib --no-default-features --features pg18 token
#
# The image is tagged by a hash of its Containerfile, so editing it rebuilds on the next run and an
# unchanged one is reused. Build output and the cargo registry live in named volumes, because a
# bind-mounted target directory on Windows is slow enough to matter.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
engine="${STACK_ENGINE:-docker}"

hash_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
image="snout-oauth-dev:$(hash_of "$root/container/Containerfile" | cut -c1-12)"

if ! "$engine" image inspect "$image" >/dev/null 2>&1; then
	echo "building $image (the first run after a Containerfile change takes a while)" >&2
	"$engine" build -t "$image" -f "$root/container/Containerfile" "$root/container" >&2
fi

# Docker Desktop on Windows wants a Windows path for a bind mount.
src="$root"
if command -v cygpath >/dev/null 2>&1; then
	src="$(cygpath -w "$root")"
fi

tty=()
if [ -t 0 ] && [ -t 1 ]; then
	tty=(-it)
fi

read -r -a extra <<<"${STACK_DEV_ARGS:-}"

MSYS_NO_PATHCONV=1 exec "$engine" run --rm "${tty[@]}" "${extra[@]}" \
	-v "$src:/work" \
	-v snout-oauth-target:/cache/target \
	-v snout-oauth-registry:/usr/local/cargo/registry \
	"$image" "$@"
