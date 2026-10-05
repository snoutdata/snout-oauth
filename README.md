# snout_oauth

An OAuth validator for Postgres 18. With it, a person signs in to the database itself (psql, a
migration script, anything on libpq 18) as themselves, with a short-lived token from an issuer,
instead of with a role password that is shared and never expires. A Postgres library written in
Rust with [pgrx](https://github.com/pgcentralfoundation/pgrx), built to run in every SnoutData
Cloud project on Postgres 18.

Postgres 18 added the `oauth` authentication method: the client fetches a bearer token from an
issuer (libpq runs the device flow: it prints a URL and a code, the person approves in a browser)
and presents it, and the server hands the token to a VALIDATOR library, which decides. This is
that library.

- **No network call, ever.** Tokens are checked against the issuer's public keys in a file on the
  database host, so a login never waits on HTTP, the issuer being down never blocks a login for
  the life of a key, and a database with no egress works.
- **A token opens one project and one role.** Its `aud` must be this project and its `db_role`
  the exact role the client asked for; the library, not `pg_ident.conf`, decides
  (`delegate_ident_mapping=1`).
- **A database token is never a session token.** It must say `"token_use": "db"` and name its role
  in `db_role`; a token carrying `role` (what HTTP session tokens carry) is refused, so a token
  meant for an API can never open the database, signed by any key.
- **Refused means refused.** A missing, unreadable or malformed key file, an unset setting, or a
  bug in the library (a caught panic) refuses every login with a log line saying why. Nothing
  ever falls back to accepting.
- **Rotation without a restart.** The key file holds several keys by `kid`, and is read again
  the moment it changes.

## The token

A compact JWS, `alg` `ES256` (P-256), with a `kid` naming a key in the key file. Claims:

| Claim | Must be |
|---|---|
| `iss` | exactly `snout_oauth.issuer` |
| `aud` | `snout_oauth.audience`, or an array containing it |
| `sub` | present, 1 to 255 bytes, no control characters. It becomes the connection's identity |
| `token_use` | `"db"` |
| `db_role` | the role the client is logging in as, compared exactly |
| `role` | ABSENT. With no `db_role` the token is a session token; beside `db_role` it is refused too |
| `exp` | later than now, less `snout_oauth.leeway` |
| `nbf` | if present, no later than now plus the leeway |
| `iat` | if present, no later than now plus the leeway |

And `exp` minus `iat` (or minus now, without `iat`) must not exceed `snout_oauth.max_lifetime`.
A header or claims object that names any field twice is refused, as is a header with `crit`.
Unknown claims are ignored. A token is at most 16 KiB.

The checks run in this order: header, key, SIGNATURE, issuer, and only then the rest. Nothing in a
token is believed before its signature verifies, and a refusal names a person only when the token
was really the issuer's.

**The authenticated identity** (what `system_user` shows, as `oauth:<sub>`, and what the server
logs as `connection authenticated: identity="<sub>"`) is the token's `sub`, verbatim. It is
reported for a token that was refused after its signature and issuer checked out (expired, another
project, another role), so a DBA can match a person to a failure, and never for a token that
failed its signature. **It is safe, and intended, to use this library with
`delegate_ident_mapping=1`**: it authorizes the role itself. Without delegation, map `oauth:<sub>`
values in `pg_ident.conf` as usual; the role check still applies.

**Scopes.** Postgres asks a validator to check that the person consented to database access. Here
that is what `token_use` and `aud` are: the issuer mints a database token only for the `db:<ref>`
scope the server announces (see the `pg_hba` line below), after the person approved it, so a token
for this project with `token_use: "db"` is that consent. The library does not read a `scope` claim.

## The key file

A JWKS document, `{"keys": [...]}`, holding the issuer's PUBLIC keys:

```json
{"keys": [
  {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "2026-10", "x": "...", "y": "..."},
  {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "2026-11", "x": "...", "y": "..."}
]}
```

- Entries that are not ES256 P-256 signing keys with a `kid` are skipped. A file in which an EC
  P-256 entry has coordinates that are not 32 bytes, or ANY entry carries a private key (`d`), is
  refused whole: the database must hold public keys only.
- The file is checked with one `stat` on every login and read again when its size, modification
  time, inode or change time differs. Write it by renaming a complete file into place (write
  `jwks.json.tmp`, then rename), so a login never reads half a file.
- **Rotation**: publish the new key beside the old, sign with the new, and remove the old once the
  last token it signed has expired (its `exp`, at most `max_lifetime` later). Each step takes
  effect on the next login; nothing restarts.
- It must be readable by the server's OS user. At most 256 KiB.

## Configuration

| Setting | Default | What |
|---|---|---|
| `snout_oauth.issuer` | empty | The `iss` a token must carry, character for character: the `issuer` of the issuer's discovery document. Empty refuses every login |
| `snout_oauth.audience` | empty | The `aud` a token must carry: this database's project ref. Empty refuses every login |
| `snout_oauth.keys_file` | empty | Path to the key file. Empty refuses every login |
| `snout_oauth.leeway` | `30s` | Clock difference allowed around `exp`, `nbf` and `iat` (0 to 600 s) |
| `snout_oauth.max_lifetime` | `1d` | The longest life a token may claim; `0` for no limit |

All are `sighup`: postgresql.conf or the command line sets them, a reload changes them, no session
can. None is secret.

**How a validator library has settings.** It is not in `shared_preload_libraries`: Postgres loads
it with `load_external_function` in a backend the first time an `oauth` login reaches that backend,
which runs its `_PG_init`, which defines the settings. Until then, a `snout_oauth.*` line in
postgresql.conf is a placeholder Postgres keeps for any dotted name it does not know yet, and
defining the real setting adopts the placeholder's value, so nothing is lost and the library does
not need preloading. A client cannot influence them during its login: startup-packet options are
applied after authentication, and by then the setting refuses `SET`. The `snout_oauth` prefix is
reserved, so a misspelt `snout_oauth.isuer` is a warning and is dropped.

Preloading is optional (`shared_preload_libraries = 'snout_oauth'` as well as
`oauth_validator_libraries`): the postmaster then loads the library and reads the key file once,
and every backend starts with both, which takes about a tenth of a millisecond off each login (see
Performance).

## Setting up a database

```
# postgresql.conf
oauth_validator_libraries = 'snout_oauth'
snout_oauth.issuer   = 'https://accounts.example.com'
snout_oauth.audience = 'abcd1234'
snout_oauth.keys_file = '/var/lib/snout_oauth/jwks.json'
```

```
# pg_hba.conf: the oauth line FIRST, for a group, then the password lines
host all +snout_oauth 0.0.0.0/0 oauth issuer="https://accounts.example.com" scope="openid db:abcd1234" delegate_ident_mapping=1
host all all          0.0.0.0/0 scram-sha-256
```

```sql
create role snout_oauth nologin;               -- the group the oauth line matches
create role alice login in role snout_oauth;   -- one role per person
```

`pg_hba.conf` is first-match with no fallback: a line that says `oauth` for a role refuses that
role's password. So OAuth roles are a GROUP, matched by `+snout_oauth` on a line before the
password lines, and every other role keeps its password exactly as before. A role in the group can
sign in only with a token.

`oauth_validator_libraries` is `sighup` in Postgres 18, and the library is loaded at a login rather
than at start, so switching OAuth on in a running server is a reload, not a restart (the
end-to-end run does exactly that).

The `scope` the line announces is passed by libpq to the issuer's device authorization request, so
the issuer learns which project the person is signing in to without them typing it.

## Signing in

```sh
psql "host=db.example.com dbname=postgres user=alice oauth_issuer=https://accounts.example.com oauth_client_id=<client id>"
```

- The client needs libpq 18 built with OAuth support. On Debian and Ubuntu (PGDG) that is a separate
  package, **`libpq-oauth`**; without it libpq says OAuth is not supported.
- `oauth_issuer` and `oauth_client_id` must BOTH be in the connection string, or libpq refuses
  before trying: the server tells the client which issuer it trusts, but libpq will not send a
  person anywhere the connection string did not name. The client id is public; there is no secret.
- `oauth_issuer` must match the `pg_hba` line's `issuer` exactly, and libpq refuses an `http://`
  issuer unless `PGOAUTHDEBUG=UNSAFE` is set in the client's environment (a test setting only).
- **Every OAuth sign-in opens two connections.** libpq first connects without a token, the server
  answers with its issuer and scope and fails that attempt (the log shows `FATAL: OAuth bearer
  authentication failed`), then libpq runs the device flow and connects again with the token. The
  first FATAL is part of a SUCCESSFUL sign-in; anything counting failed logins must expect it.

## Operations

- **Logs.** Each refusal is one line at COMMERROR (printed as `LOG`, never sent to the client, as
  the Postgres documentation asks of a validator), for example
  `snout_oauth: refused a sign-in as role "alice" (identity "user-0001"): the token expired 61 s ago`,
  followed by Postgres's own FATAL. No line ever quotes a token or part of one. Strings from a token
  are quoted, escaped and cut at 64 characters, so a token cannot write a line of its own into the
  log. A key file problem is the reason on every login it refuses (`no keys to check it with: the
  key file "..." cannot be opened (...)`), and, when preloaded, once at server start.
- **Health.** With the key file in place and the settings set, a sign-in works; nothing else runs.
  There is no background worker and no shared memory.
- **Upgrade.** Replace the library. Each new backend loads the new one, so no restart is needed,
  unless it is preloaded, when the postmaster's copy is the one that runs until a restart.

## Performance

Measured 2026-10-04 on an Apple-silicon Mac in Docker (arm64), Postgres 18.6 from PGDG, the
release build:

| | |
|---|---|
| The check (signature, claims, a 4-key set), in process | 34.5 µs; a forged signature costs the same; a non-JWT is refused in 51 ns |
| Parsing a 4-key JWKS | 2.4 µs |
| Server authentication time per OAuth login (Postgres 18's `log_connections` setup durations), library loaded at the login | median 0.338 ms, p90 0.376 ms |
| The same, preloaded | median 0.199 ms, p90 0.279 ms |
| A `scram-sha-256` login on the same server | median 3.39 ms, p90 3.44 ms |

The login figures are 30 logins each through psql 18 (`e2e/results/run.txt`); the server's
"authentication" duration covers loading the library (when not preloaded), the SASL exchange and
the check, and for OAuth it is the second, token-bearing connection.

The signature check is nearly all of it. An OAuth login costs the SERVER less than a password login
does (SCRAM's key derivation is deliberately slow); what costs the person time is the device flow.

## Building and testing

Postgres 18 only. Everything runs in the crate's own container (`container/Containerfile`: Rust,
cargo-pgrx and a Postgres 18 built with assertions), so nothing depends on the machine it runs from.

```sh
bash scripts/dev.sh cargo pgrx test pg18                  # unit tests and the in-server tests
bash scripts/dev.sh cargo clippy --lib --tests --features pg_test -- -D warnings
bash scripts/dev.sh cargo deny --locked check              # licences, bans, advisories, sources
bash scripts/dev.sh cargo test --release --lib token::tests::bench -- --ignored --nocapture
bash e2e/run.sh                                            # psql 18's device flow, end to end
bash scripts/build-dist.sh tools 18 && bash scripts/build-dist.sh build 18 /out   # the shipped library
```

The token check and the key file parser (`src/token.rs`, `src/keys.rs`) are pure Rust that forbids
`unsafe` and never touches Postgres; `src/lib.rs` is the C boundary (the validator ABI from
`libpq/oauth.h`, declared by hand since pgrx does not bind it, with every call into Rust inside
`catch_unwind`), and `src/settings.rs` the settings. Both pure modules are fuzzed by the stack's
`oauth_token` target (`packages/stack/fuzz`).

`e2e/run.sh` builds the library with `build-dist.sh` inside the SnoutData Cloud Postgres 18 image,
starts a throwaway issuer (`e2e/issuer.mjs`, Node, no dependencies), and signs in with psql 18 through
the real device flow: a database token is admitted, and refused are an expired token, another
project's, another role's, a forged signature, an unknown `kid`, another issuer, no `token_use`, a
session-shaped token, `role` beside `db_role`, and one person's token presented as another role;
keys are rotated while the server runs; the key file is removed and broken; and the password roles
are untouched.

`build-dist.sh` refuses to build against headers whose `PG_OAUTH_VALIDATOR_MAGIC` is not the one
`src/lib.rs` was written for (`0x20250220`).

Licensed under the [Apache License 2.0](./LICENSE). Security reports: [SECURITY.md](./SECURITY.md).
