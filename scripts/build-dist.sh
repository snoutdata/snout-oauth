#!/usr/bin/env bash
# Builds snout_oauth for Postgres 18, in two steps so a container build can cache the first:
#
#   bash scripts/build-dist.sh tools 18            # the pgdg server headers and libclang
#   bash scripts/build-dist.sh build 18 /out       # <out>/lib/snout_oauth.so, stripped
#                                                  # <out>/debug/snout_oauth.so.debug, its symbols
#
# The one recipe for a build that ships: a database image runs both steps in a build stage with
# this folder as a named build context, so the image depends on this package's output and never the
# reverse. It expects Debian bookworm with the Rust toolchain Cargo.toml's rust-version names.
#
# Only the library is shipped. snout_oauth has no SQL objects: Postgres loads it through
# `oauth_validator_libraries`, so there is no control file or script to install, and it is not
# something a database can CREATE EXTENSION. Postgres 18 only: the validator interface is new in 18.
set -euo pipefail

step="${1:?usage: scripts/build-dist.sh tools <major> | build <major> <out dir>}"
major="${2:?the Postgres major}"
src="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$major" in
	18) ;;
	*) echo "snout_oauth is an OAuth validator, an interface Postgres 18 introduced; there is no build for $major" >&2; exit 2 ;;
esac

pg_config="/usr/lib/postgresql/${major}/bin/pg_config"

if [ "$step" = tools ]; then
	# A different rustc builds a different binary from the same source, and nothing downstream
	# would notice.
	want="$(tr -d '\r' <"$src/Cargo.toml" | sed -n 's/^rust-version *= *"\(.*\)"/\1/p')"
	have="$(rustc --version | awk '{print $2}')"
	if [ "$want" != "$have" ]; then
		echo "Cargo.toml pins rust $want; this image has rustc $have" >&2
		exit 1
	fi

	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends build-essential clang libclang-dev pkg-config ca-certificates curl gnupg
	install -d /usr/share/postgresql-common/pgdg
	curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
	echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
		>/etc/apt/sources.list.d/pgdg.list
	apt-get update
	apt-get install -y --no-install-recommends "postgresql-server-dev-${major}"
	rm -rf /var/lib/apt/lists/*
	exit 0
fi

[ "$step" = build ] || { echo "unknown step: $step" >&2; exit 2; }
out="${3:?the out dir}"

# The validator ABI is a struct Postgres declares in libpq/oauth.h and pgrx does not bind, so
# src/lib.rs declares it. Refuse to build against headers whose magic is not the one it was
# written for, rather than ship a library Postgres would refuse at the first login.
header="$("$pg_config" --includedir-server)/libpq/oauth.h"
magic="$(sed -n 's/^#define PG_OAUTH_VALIDATOR_MAGIC[[:space:]]*\(0x[0-9a-fA-F]*\).*/\1/p' "$header")"
if [ "$magic" != 0x20250220 ]; then
	echo "$header declares validator magic '${magic:-none}', and src/lib.rs was written for 0x20250220" >&2
	exit 1
fi

# A copy to build in, so the build context stays read-only.
#
# A plain `cargo build`, not `cargo pgrx install`: this library has no SQL objects, so there is no
# schema to generate. pgrx finds the server's headers through PGRX_PG_CONFIG_PATH, so cargo-pgrx is
# not needed at all.
work="$(mktemp -d)"
cp -r "$src/Cargo.toml" "$src/Cargo.lock" "$src/src" "$work/"
export PGRX_PG_CONFIG_PATH="$pg_config"
(cd "$work" && cargo build --release --locked --lib --no-default-features --features "pg${major}")

mkdir -p "$out/lib" "$out/debug"
so="${CARGO_TARGET_DIR:-$work/target}/release/libsnout_oauth.so"
objcopy --only-keep-debug "$so" "$out/debug/snout_oauth.so.debug"
strip --strip-unneeded -o "$out/lib/snout_oauth.so" "$so"
ls -l "$out/lib"
