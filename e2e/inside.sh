#!/usr/bin/env bash
# Runs INSIDE the e2e box (run.sh starts it). Builds snout_oauth with the shipping recipe
# (scripts/build-dist.sh), starts a Postgres 18 with it, drives every case through psql 18's real
# device flow, and measures what a login costs. Exits non-zero if any case fails.
set -uo pipefail
ISSUER="$1"
AUD=e2eprojref1
KEYS=/var/lib/snout_oauth/jwks.json
LOG=/tmp/pg.log
N="${E2E_LOGINS:-30}"
failures=0

echo "=== versions"
postgres --version
psql --version
dpkg -l libpq5 libpq-oauth | awk '/^ii/{print $2, $3}'

echo "=== build with scripts/build-dist.sh"
CARGO_TARGET_DIR=/cache/target bash /src/scripts/build-dist.sh build 18 /out >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
install -m 0755 /out/lib/snout_oauth.so "$(pg_config --pkglibdir)/snout_oauth.so"
echo "snout_oauth.so: $(stat -c %s /out/lib/snout_oauth.so) bytes, stripped"

# The key file, installed the way the platform does: fetched, then renamed into place.
install -d -m 0755 /var/lib/snout_oauth
publish() {
	curl -sf "$ISSUER/jwks?kids=$1" >/var/lib/snout_oauth/.jwks.tmp && mv -f /var/lib/snout_oauth/.jwks.tmp "$KEYS"
	chmod 0644 "$KEYS"
}
publish k1

echo "=== a Postgres 18, started WITHOUT OAuth"
rm -rf /tmp/pg && install -d -o postgres /tmp/pg
su postgres -c "initdb -D /tmp/pg --auth-local=trust >/dev/null" || exit 1
cat >>/tmp/pg/postgresql.conf <<CONF
listen_addresses = '127.0.0.1'
log_connections = 'all'
CONF
cat >/tmp/pg/pg_hba.conf <<HBA
local all all trust
host all all 127.0.0.1/32 scram-sha-256
HBA
start() { su postgres -c "pg_ctl -D /tmp/pg -l $LOG -w start" >/dev/null || { cat $LOG; exit 1; }; }
stop() { su postgres -c "pg_ctl -D /tmp/pg -w stop" >/dev/null; }
start
su postgres -c "psql -X -q" <<SQL
create role snout_oauth nologin;
create role alice login in role snout_oauth;
create role bob login password 'bob-pw' in role snout_oauth;
create role carol login password 'carol-pw';
SQL

# OAuth switched on in the running server: oauth_validator_libraries is a sighup setting in 18, and
# the validator is loaded by each backend at its first OAuth login, so a reload is enough.
echo "=== OAuth switched on with a reload, no restart"
cat >>/tmp/pg/postgresql.conf <<CONF
oauth_validator_libraries = 'snout_oauth'
snout_oauth.issuer = '$ISSUER'
snout_oauth.audience = '$AUD'
snout_oauth.keys_file = '$KEYS'
CONF
cat >/tmp/pg/pg_hba.conf <<HBA
local all all trust
host all +snout_oauth 127.0.0.1/32 oauth issuer="$ISSUER" scope="openid db:$AUD" delegate_ident_mapping=1
host all all 127.0.0.1/32 scram-sha-256
HBA
started="$(su postgres -c "psql -X -At -c 'select pg_postmaster_start_time()'")"
su postgres -c "pg_ctl -D /tmp/pg reload" >/dev/null
sleep 1
su postgres -c "psql -X -At -c \"select name || '=' || setting || ' (' || context || ')' from pg_settings where name like 'oauth%'\""

mark=0
since() { tail -n +"$((mark + 1))" "$LOG"; }
remember() { mark="$(wc -l <"$LOG")"; }

verdict() {
	local name="$1" got="$2" expect="$3" detail="$4"
	local v=PASS
	if [ "$got" != "$expect" ]; then
		v=FAIL
		failures=$((failures + 1))
	fi
	echo "$v  $name: $got  ($detail)"
}

# One OAuth login through psql's device flow. $why, when given, must appear in the validator's
# LOG line for a refusal; $named=no means the server must NOT log an identity for it.
oauth() {
	local label="$1" mode="$2" sign="$3" user="$4" expect="$5" why="${6:-}" named="${7:-}"
	curl -sf "$ISSUER/mode?next=$mode&sign=$sign" >/dev/null
	remember
	local out
	out="$(PGOAUTHDEBUG=UNSAFE timeout 60 psql -X -At "host=127.0.0.1 user=$user dbname=postgres oauth_issuer=$ISSUER oauth_client_id=e2e-client" \
		-c "select current_user || ' as ' || system_user" 2>&1 </dev/null)"
	sleep 0.2
	local got=refused
	case "$out" in *" as oauth:"*) got=admitted ;; esac
	local logged
	logged="$(since | grep -o 'snout_oauth: refused.*' | head -1)"
	if [ "$expect" = refused ] && [ -n "$why" ] && ! printf '%s' "$logged" | grep -qF -- "$why"; then
		got="refused-without-the-reason"
	fi
	if [ "$named" = no ] && since | grep -q 'connection authenticated: identity='; then
		got="$got-but-named"
	fi
	verdict "oauth  $label (user=$user)" "$got" "$expect" "${logged:-$(echo "$out" | grep -v '^Visit' | tail -1)}"
}

password() {
	local user="$1" pw="$2" expect="$3"
	local out
	out="$(PGPASSWORD="$pw" psql -X -At "host=127.0.0.1 user=$user dbname=postgres" -c "select current_user" 2>&1 </dev/null)"
	local got=refused
	[ "$out" = "$user" ] && got=admitted
	verdict "passwd user=$user" "$got" "$expect" "$(echo "$out" | tail -1)"
}

echo "=== cases"
oauth "a database token" ok k1 alice admitted
oauth "expired" expired k1 alice refused "expired"
oauth "another project's aud" otheraud k1 alice refused "not for this project"
oauth "a token naming another role" otherrole k1 alice refused 'for role "bob"'
oauth "signed by an unpublished key under a published kid" otherkey k1 alice refused "does not verify" no
oauth "an unknown kid" unknownkid k1 alice refused 'no key "k9"' no
oauth "another issuer" otherissuer k1 alice refused "evil.example" no
oauth "no token_use" notokenuse k1 alice refused "no token_use"
oauth "session-shaped: role, no db_role" session k1 alice refused "a session token"
oauth "role beside db_role" rolebeside k1 alice refused "never carries role"
oauth "alice's token presented by bob" ok k1 bob refused 'the client asked for "bob"'

echo "=== rotation, the server running throughout"
publish k1,k2
oauth "k2 published beside k1, signed by k2" ok k2 alice admitted
oauth "k1 still accepted during the overlap" ok k1 alice admitted
publish k2
oauth "k1 removed from the file, signed by k1" ok k1 alice refused 'no key "k1"'
oauth "k2 alone" ok k2 alice admitted

echo "=== the key file missing or broken"
rm -f "$KEYS"
oauth "key file missing" ok k2 alice refused "cannot be opened"
printf '{ "keys": [ this is not json' >"$KEYS"
oauth "key file not JSON" ok k2 alice refused "not a JWKS document"
publish k2
oauth "key file restored" ok k2 alice admitted

echo "=== passwords (O8)"
password carol carol-pw admitted
password bob bob-pw refused
password alice '' refused

echo "=== the same postmaster throughout (no restart since it started without OAuth)"
verdict "pg_postmaster_start_time" "$(su postgres -c "psql -X -At -c 'select pg_postmaster_start_time()'")" "$started" "unchanged"

echo "=== the server's scope reached the issuer (O10)"
scope="$(curl -sf "$ISSUER/seen" | grep -o '"scope":"[^"]*"' | sort -u | tr '\n' ' ')"
verdict "device authorization scope" "$scope" "\"scope\":\"openid db:$AUD\" " "every device request carried the pod's scope"

echo "=== no token ever reached the server log"
tokens="$(grep -c 'eyJ' $LOG)"
verdict "base64url JSON in the log" "$tokens" "0" "a JWT header always starts eyJ"

# What a login costs the server. log_connections = 'all' includes Postgres 18's setup
# durations, and its "authentication" figure is the time from the start of authentication to its
# end inside the backend: for OAuth that is loading the validator (unless preloaded), the SASL
# exchange and the check; for a password, the SCRAM exchange.
auth_ms() { since | sed -n 's/.*connection ready: setup total=\([0-9.]*\) ms.*authentication=\([0-9.]*\) ms.*/\2/p' | sort -n; }
median() { awk '{ a[NR] = $1 } END { if (NR == 0) { print "n/a"; exit } m = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2; printf "%.3f", m }'; }
p90() { awk '{ a[NR] = $1 } END { if (NR == 0) { print "n/a"; exit } i = int(NR * 0.9 + 0.999); if (i > NR) i = NR; printf "%.3f", a[i] }'; }
walls() { sort -n | median; }

measure() {
	local label="$1"
	curl -sf "$ISSUER/mode?next=ok&sign=k2" >/dev/null
	remember
	local w=()
	for _ in $(seq 1 "$N"); do
		local t0 t1
		t0="$(date +%s%N)"
		PGOAUTHDEBUG=UNSAFE psql -X -At "host=127.0.0.1 user=alice dbname=postgres oauth_issuer=$ISSUER oauth_client_id=e2e-client" -c "select 1" >/dev/null 2>&1 </dev/null
		t1="$(date +%s%N)"
		w+=("$(((t1 - t0) / 1000000))")
	done
	sleep 0.3
	local a
	a="$(auth_ms)"
	echo "x9  oauth, $label: server authentication median $(echo "$a" | median) ms, p90 $(echo "$a" | p90) ms over $(echo "$a" | grep -c .) logins; psql wall median $(printf '%s\n' "${w[@]}" | walls) ms (device flow included)"
	remember
	w=()
	for _ in $(seq 1 "$N"); do
		local t0 t1
		t0="$(date +%s%N)"
		PGPASSWORD=carol-pw psql -X -At "host=127.0.0.1 user=carol dbname=postgres" -c "select 1" >/dev/null 2>&1 </dev/null
		t1="$(date +%s%N)"
		w+=("$(((t1 - t0) / 1000000))")
	done
	sleep 0.3
	a="$(auth_ms)"
	echo "x9  scram-sha-256, same server: server authentication median $(echo "$a" | median) ms, p90 $(echo "$a" | p90) ms over $(echo "$a" | grep -c .) logins; psql wall median $(printf '%s\n' "${w[@]}" | walls) ms"
}

echo "=== X9: a login, measured ($N each)"
measure "validator loaded at the first login (oauth_validator_libraries only)"
stop
echo "shared_preload_libraries = 'snout_oauth'" >>/tmp/pg/postgresql.conf
start
measure "validator preloaded (shared_preload_libraries too)"
stop

echo "=== what the server logged"
# Every OAuth login opens two connections and the first ends in a FATAL, success included (spike
# finding 1), so the FATALs are counted rather than listed.
echo "  $(grep -c 'FATAL:  OAuth bearer authentication failed' $LOG) 'OAuth bearer authentication failed' FATALs, $(grep -c 'method=oauth' $LOG) 'connection authenticated ... method=oauth' lines"
echo "  the validator's own lines, one per refusal:"
grep -o 'LOG:  snout_oauth: .*' $LOG | sed -e 's/^LOG:  /    /' -e 's/[0-9]* s ago/N s ago/'

echo "=== $failures failed"
[ "$failures" -eq 0 ]
