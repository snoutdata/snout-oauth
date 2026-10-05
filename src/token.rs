//! Whether a bearer token may open the role a client asked for. Pure: no `unsafe`, no Postgres,
//! tested with plain `#[test]`s and fuzzed. The C boundary (lib.rs) hands it the token,
//! the role, the settings, the key set and the time, and turns the answer into Postgres's.
//!
//! A database token is a compact JWS signed ES256 by the issuer's
//! DATABASE key, which no HTTP service trusts, with these claims:
//!
//! - `iss`: exactly the configured issuer;
//! - `aud`: the project ref (a string, or an array containing it);
//! - `sub`: the person, which becomes the connection's authenticated identity;
//! - `token_use`: `"db"`;
//! - `db_role`: the Postgres role the issuer provisioned for that person on that project;
//! - `exp`, and optionally `nbf` and `iat`.
//!
//! It never carries `role`: that is a session token's claim, and a token with it is refused, so a
//! session token cannot pass for a database token even if it were signed with the right key.
//!
//! The checks run in an order that matters: nothing in the claims is believed until the signature
//! has verified and the issuer matched, so an identity is reported only for a token our issuer
//! really signed. Every refusal is a [`Reason`] with a sentence for the server log; no sentence
//! ever quotes the token.
#![forbid(unsafe_code)]

use crate::keys::KeySet;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use std::fmt;

/// The longest token looked at. libpq and the server allow far more; an ES256 database token is
/// well under a kilobyte, and a cap bounds the work an unauthenticated client can ask for.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// The longest `sub` accepted as an identity, and the longest `db_role` (Postgres's NAMEDATALEN
/// is 64, so a longer role cannot exist).
pub const MAX_SUBJECT_BYTES: usize = 255;

/// What a token is checked against: the settings, already read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
	/// `iss` must equal this, character for character.
	pub issuer: String,
	/// `aud` must be, or contain, this: the project ref.
	pub audience: String,
	/// Seconds of clock difference allowed around `exp`, `nbf` and `iat`.
	pub leeway: i64,
	/// The longest life a token may claim (`exp` minus `iat`, or minus now without `iat`), in
	/// seconds; 0 for no limit.
	pub max_lifetime: i64,
}

/// Why a token was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
	/// A setting the check needs is empty.
	NotConfigured(&'static str),
	/// There are no keys to check with (the key file's sentence).
	NoKeys(String),
	TooLong(usize),
	NotUtf8,
	/// Not three base64url segments separated by dots.
	NotCompact,
	/// The named part is not base64url, or not the JSON it should be.
	Unreadable(&'static str),
	Algorithm(String),
	/// The header names extensions (`crit`) that must be understood, and none is.
	Critical,
	NoKeyId,
	UnknownKeyId(String),
	BadSignature,
	Issuer(Option<String>),
	NoSubject,
	TokenUse(Option<String>),
	Audience,
	NoExpiry,
	Expired {
		ago: i64,
	},
	NotYetValid {
		in_secs: i64,
	},
	IssuedInFuture {
		in_secs: i64,
	},
	TooLongLived {
		lifetime: i64,
		max: i64,
	},
	/// `role` without `db_role`: a session token.
	SessionToken,
	/// `role` beside `db_role`: a database token never carries `role`.
	RoleClaim,
	NoDbRole,
	WrongRole {
		token: String,
		asked: String,
	},
}

/// A string from a token or a client, made safe for one log line: at most 64 characters, quoted,
/// control characters escaped.
fn quoted(s: &str) -> String {
	let mut short: String = s.chars().take(64).collect();
	if short.len() < s.len() {
		short.push('…');
	}
	format!("{short:?}")
}

impl fmt::Display for Reason {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Reason::NotConfigured(setting) => {
				write!(f, "{setting} is not set, so no token can be accepted")
			}
			Reason::NoKeys(why) => write!(f, "no keys to check it with: {why}"),
			Reason::TooLong(n) => write!(
				f,
				"the token is {n} bytes, more than the {MAX_TOKEN_BYTES} accepted"
			),
			Reason::NotUtf8 => write!(f, "the token or the role is not UTF-8"),
			Reason::NotCompact => {
				write!(f, "the token is not a signed JWT (three base64url parts)")
			}
			Reason::Unreadable(part) => write!(f, "the token's {part} cannot be read"),
			Reason::Algorithm(alg) => {
				write!(f, "the token is signed with {}, not ES256", quoted(alg))
			}
			Reason::Critical => write!(
				f,
				"the token's header lists critical extensions (crit), which are not supported"
			),
			Reason::NoKeyId => write!(f, "the token's header has no kid"),
			Reason::UnknownKeyId(kid) => write!(f, "no key {} in the key file", quoted(kid)),
			Reason::BadSignature => write!(f, "the signature does not verify"),
			Reason::Issuer(Some(iss)) => write!(
				f,
				"the token was issued by {}, not the configured issuer",
				quoted(iss)
			),
			Reason::Issuer(None) => write!(f, "the token names no issuer"),
			Reason::NoSubject => write!(f, "the token has no usable sub"),
			Reason::TokenUse(Some(u)) => {
				write!(f, "the token's token_use is {}, not \"db\"", quoted(u))
			}
			Reason::TokenUse(None) => write!(
				f,
				"the token has no token_use, so it is not a database token"
			),
			Reason::Audience => write!(f, "the token is not for this project (aud)"),
			Reason::NoExpiry => write!(f, "the token has no exp"),
			Reason::Expired { ago } => write!(f, "the token expired {ago} s ago"),
			Reason::NotYetValid { in_secs } => {
				write!(f, "the token is not valid for another {in_secs} s (nbf)")
			}
			Reason::IssuedInFuture { in_secs } => {
				write!(f, "the token was issued {in_secs} s in the future (iat)")
			}
			Reason::TooLongLived { lifetime, max } => {
				write!(
					f,
					"the token claims a life of {lifetime} s, more than snout_oauth.max_lifetime ({max} s)"
				)
			}
			Reason::SessionToken => write!(
				f,
				"the token has role but no db_role: a session token, not a database token"
			),
			Reason::RoleClaim => write!(
				f,
				"the token has role beside db_role; a database token never carries role"
			),
			Reason::NoDbRole => write!(f, "the token has no db_role"),
			Reason::WrongRole { token, asked } => {
				write!(
					f,
					"the token is for role {}, and the client asked for {}",
					quoted(token),
					quoted(asked)
				)
			}
		}
	}
}

/// A refusal: why, and the identity (`sub`) when the token was one our issuer really signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
	pub identity: Option<String>,
	pub reason: Reason,
}

impl Refused {
	fn anonymous(reason: Reason) -> Refused {
		Refused {
			identity: None,
			reason,
		}
	}
}

/// A JWT NumericDate: seconds since the epoch. RFC 7519 allows a fraction; it is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NumericDate(i64);

impl<'de> Deserialize<'de> for NumericDate {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		let n = serde_json::Number::deserialize(d)?;
		if let Some(i) = n.as_i64() {
			return Ok(NumericDate(i));
		}
		match n.as_f64() {
			Some(f) if f.is_finite() && f.abs() < 1e15 => Ok(NumericDate(f.floor() as i64)),
			_ => Err(serde::de::Error::custom("a date out of range")),
		}
	}
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
	One(String),
	Many(Vec<String>),
}

/// The header fields read. serde's derive refuses a field that appears twice, so `{"alg":"none",
/// "alg":"ES256"}` is unreadable rather than whichever came last.
#[derive(Deserialize)]
struct Header {
	alg: String,
	#[serde(default)]
	kid: Option<String>,
	#[serde(default)]
	crit: Option<serde_json::Value>,
}

/// The claims read, under the same duplicate rule. Unknown claims are ignored.
#[derive(Deserialize)]
struct Claims {
	#[serde(default)]
	iss: Option<String>,
	#[serde(default)]
	sub: Option<String>,
	#[serde(default)]
	aud: Option<Audience>,
	#[serde(default)]
	exp: Option<NumericDate>,
	#[serde(default)]
	nbf: Option<NumericDate>,
	#[serde(default)]
	iat: Option<NumericDate>,
	#[serde(default)]
	token_use: Option<String>,
	#[serde(default)]
	db_role: Option<String>,
	#[serde(default)]
	role: Option<serde_json::Value>,
}

fn decode<T: for<'de> Deserialize<'de>>(segment: &str, part: &'static str) -> Result<T, Reason> {
	let bytes = URL_SAFE_NO_PAD
		.decode(segment)
		.map_err(|_| Reason::Unreadable(part))?;
	serde_json::from_slice(&bytes).map_err(|_| Reason::Unreadable(part))
}

/// The settings a check cannot run without, named for the log.
pub fn missing_setting(policy: &Policy) -> Option<&'static str> {
	if policy.issuer.is_empty() {
		Some("snout_oauth.issuer")
	} else if policy.audience.is_empty() {
		Some("snout_oauth.audience")
	} else {
		None
	}
}

/// Checks `token` for a client asking to log in as `role`, at `now` (seconds since the epoch).
/// `Ok` is the identity (`sub`) to log in with; everything else is a refusal.
pub fn check(
	token: &str,
	role: &str,
	policy: &Policy,
	keys: &KeySet,
	now: i64,
) -> Result<String, Refused> {
	if let Some(setting) = missing_setting(policy) {
		return Err(Refused::anonymous(Reason::NotConfigured(setting)));
	}
	if token.len() > MAX_TOKEN_BYTES {
		return Err(Refused::anonymous(Reason::TooLong(token.len())));
	}
	let mut parts = token.split('.');
	let (Some(head), Some(body), Some(sig), None) =
		(parts.next(), parts.next(), parts.next(), parts.next())
	else {
		return Err(Refused::anonymous(Reason::NotCompact));
	};

	// The header: only what picks the key.
	let header: Header = decode(head, "header").map_err(Refused::anonymous)?;
	if header.alg != "ES256" {
		return Err(Refused::anonymous(Reason::Algorithm(header.alg)));
	}
	if header.crit.as_ref().is_some_and(|c| !c.is_null()) {
		return Err(Refused::anonymous(Reason::Critical));
	}
	let kid = header
		.kid
		.filter(|k| !k.is_empty())
		.ok_or(Refused::anonymous(Reason::NoKeyId))?;

	// The signature, over the two segments exactly as they arrived.
	let signature = URL_SAFE_NO_PAD
		.decode(sig)
		.map_err(|_| Refused::anonymous(Reason::Unreadable("signature")))?;
	let signed = &token[..head.len() + 1 + body.len()];
	let mut candidates = keys.find(&kid).peekable();
	if candidates.peek().is_none() {
		return Err(Refused::anonymous(Reason::UnknownKeyId(kid.clone())));
	}
	let verified = candidates.any(|key| {
		UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key.point[..])
			.verify(signed.as_bytes(), &signature)
			.is_ok()
	});
	if !verified {
		return Err(Refused::anonymous(Reason::BadSignature));
	}

	// The claims, now that they are known to be the issuer's.
	let claims: Claims = decode(body, "claims").map_err(Refused::anonymous)?;
	if claims.iss.as_deref() != Some(policy.issuer.as_str()) {
		return Err(Refused::anonymous(Reason::Issuer(claims.iss)));
	}
	let sub = claims
		.sub
		.filter(|s| {
			!s.is_empty() && s.len() <= MAX_SUBJECT_BYTES && !s.chars().any(char::is_control)
		})
		.ok_or(Refused::anonymous(Reason::NoSubject))?;

	// From here on the token authenticates `sub`, so a refusal names them (the header asks for
	// that, so a DBA can match a person to a failure).
	let refuse = |reason: Reason| Refused {
		identity: Some(sub.clone()),
		reason,
	};

	match claims.token_use.as_deref() {
		Some("db") => {}
		_ => return Err(refuse(Reason::TokenUse(claims.token_use))),
	}
	let for_us = match &claims.aud {
		Some(Audience::One(a)) => *a == policy.audience,
		Some(Audience::Many(list)) => list.contains(&policy.audience),
		None => false,
	};
	if !for_us {
		return Err(refuse(Reason::Audience));
	}

	let leeway = policy.leeway.max(0);
	let exp = claims.exp.ok_or(refuse(Reason::NoExpiry))?.0;
	if now >= exp.saturating_add(leeway) {
		return Err(refuse(Reason::Expired {
			ago: now.saturating_sub(exp),
		}));
	}
	if let Some(NumericDate(nbf)) = claims.nbf
		&& nbf > now.saturating_add(leeway)
	{
		return Err(refuse(Reason::NotYetValid {
			in_secs: nbf.saturating_sub(now),
		}));
	}
	if let Some(NumericDate(iat)) = claims.iat
		&& iat > now.saturating_add(leeway)
	{
		return Err(refuse(Reason::IssuedInFuture {
			in_secs: iat.saturating_sub(now),
		}));
	}
	if policy.max_lifetime > 0 {
		let start = claims.iat.map_or(now, |d| d.0);
		let lifetime = exp.saturating_sub(start);
		if lifetime > policy.max_lifetime {
			return Err(refuse(Reason::TooLongLived {
				lifetime,
				max: policy.max_lifetime,
			}));
		}
	}

	let has_role = claims.role.as_ref().is_some_and(|r| !r.is_null());
	let db_role = match (claims.db_role, has_role) {
		(Some(_), true) => return Err(refuse(Reason::RoleClaim)),
		(None, true) => return Err(refuse(Reason::SessionToken)),
		(None, false) => return Err(refuse(Reason::NoDbRole)),
		(Some(r), false) => r,
	};
	if db_role != role {
		return Err(refuse(Reason::WrongRole {
			token: db_role,
			asked: role.to_owned(),
		}));
	}
	Ok(sub)
}

/// Test fixtures, shared with the Postgres-side tests in lib.rs: a key made for the run and the
/// claims a database token carries.
#[cfg(any(test, feature = "pg_test"))]
pub mod fixtures {
	use super::*;
	use crate::keys::Key;
	use ring::rand::SystemRandom;
	use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
	use serde_json::{Value, json};

	pub const NOW: i64 = 1_800_000_000;
	pub const ISSUER: &str = "https://accounts.example.test";
	pub const AUD: &str = "projref1";

	/// A signing key made for the test run; nothing private is ever written into the repository.
	pub struct Signer {
		pub kid: String,
		pub pair: EcdsaKeyPair,
	}

	impl Signer {
		pub fn new(kid: &str) -> Signer {
			let rng = SystemRandom::new();
			let pkcs8 =
				EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
			let pair =
				EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
					.unwrap();
			Signer {
				kid: kid.to_owned(),
				pair,
			}
		}

		pub fn key(&self) -> Key {
			Key {
				kid: self.kid.clone(),
				point: self.pair.public_key().as_ref().try_into().unwrap(),
			}
		}

		/// The key as a JWKS entry.
		pub fn jwk(&self) -> Value {
			let p = self.pair.public_key().as_ref();
			json!({ "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
				"x": URL_SAFE_NO_PAD.encode(&p[1..33]), "y": URL_SAFE_NO_PAD.encode(&p[33..]) })
		}

		pub fn sign_raw(&self, header: &Value, claims: &Value) -> String {
			let input = format!(
				"{}.{}",
				URL_SAFE_NO_PAD.encode(header.to_string()),
				URL_SAFE_NO_PAD.encode(claims.to_string())
			);
			let sig = self
				.pair
				.sign(&SystemRandom::new(), input.as_bytes())
				.unwrap();
			format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
		}

		pub fn sign(&self, claims: &Value) -> String {
			self.sign_raw(
				&json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid }),
				claims,
			)
		}
	}

	/// The claims the issuer puts in a database token.
	pub fn claims() -> Value {
		json!({ "iss": ISSUER, "aud": AUD, "sub": "user-0001", "token_use": "db", "db_role": "alice",
			"iat": NOW - 10, "exp": NOW + 3600 })
	}

	pub fn policy() -> Policy {
		Policy {
			issuer: ISSUER.into(),
			audience: AUD.into(),
			leeway: 30,
			max_lifetime: 86_400,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::fixtures::*;
	use super::*;
	use crate::keys::KeySet;
	use ring::rand::SystemRandom;
	use serde_json::{Value, json};

	fn with(change: impl FnOnce(&mut Value)) -> Value {
		let mut c = claims();
		change(&mut c);
		c
	}

	fn keys(signers: &[&Signer]) -> KeySet {
		KeySet {
			keys: signers.iter().map(|s| s.key()).collect(),
			skipped: 0,
		}
	}

	fn run(signer: &Signer, claims: &Value) -> Result<String, Refused> {
		check(
			&signer.sign(claims),
			"alice",
			&policy(),
			&keys(&[signer]),
			NOW,
		)
	}

	fn reason(r: Result<String, Refused>) -> Reason {
		r.unwrap_err().reason
	}

	#[test]
	fn a_database_token_for_this_role_is_accepted() {
		let s = Signer::new("k1");
		assert_eq!(run(&s, &claims()).unwrap(), "user-0001");
		let array_aud = with(|c| c["aud"] = json!(["other", AUD]));
		assert_eq!(run(&s, &array_aud).unwrap(), "user-0001");
		let no_iat = with(|c| {
			c.as_object_mut()
				.unwrap()
				.remove("iat")
				.map(|_| ())
				.unwrap()
		});
		assert!(run(&s, &no_iat).is_ok());
		let fractional = with(|c| c["exp"] = json!((NOW + 60) as f64 + 0.5));
		assert!(run(&s, &fractional).is_ok());
	}

	#[test]
	fn rotation_picks_the_key_by_kid() {
		let old = Signer::new("old");
		let new = Signer::new("new");
		let set = keys(&[&old, &new]);
		assert!(check(&old.sign(&claims()), "alice", &policy(), &set, NOW).is_ok());
		assert!(check(&new.sign(&claims()), "alice", &policy(), &set, NOW).is_ok());
		let without_old = keys(&[&new]);
		let r = check(&old.sign(&claims()), "alice", &policy(), &without_old, NOW);
		assert_eq!(reason(r), Reason::UnknownKeyId("old".into()));
	}

	#[test]
	fn an_unknown_kid_or_another_key_is_refused_without_an_identity() {
		let s = Signer::new("k1");
		let stranger = Signer::new("k1");
		let r = check(
			&stranger.sign(&claims()),
			"alice",
			&policy(),
			&keys(&[&s]),
			NOW,
		);
		assert_eq!(
			r,
			Err(Refused {
				identity: None,
				reason: Reason::BadSignature
			}),
			"a forged sub is never reported"
		);
		let other = Signer::new("k2");
		let r = check(
			&other.sign(&claims()),
			"alice",
			&policy(),
			&keys(&[&s]),
			NOW,
		);
		assert_eq!(reason(r), Reason::UnknownKeyId("k2".into()));
	}

	#[test]
	fn a_duplicated_kid_verifies_against_each_key() {
		let a = Signer::new("same");
		let b = Signer::new("same");
		assert!(
			check(
				&b.sign(&claims()),
				"alice",
				&policy(),
				&keys(&[&a, &b]),
				NOW
			)
			.is_ok()
		);
	}

	#[test]
	fn the_header_must_be_es256_with_a_kid_and_no_crit() {
		let s = Signer::new("k1");
		let set = keys(&[&s]);
		let go = |h: Value| {
			reason(check(
				&s.sign_raw(&h, &claims()),
				"alice",
				&policy(),
				&set,
				NOW,
			))
		};
		assert_eq!(
			go(json!({ "alg": "none", "kid": "k1" })),
			Reason::Algorithm("none".into())
		);
		assert_eq!(
			go(json!({ "alg": "HS256", "kid": "k1" })),
			Reason::Algorithm("HS256".into())
		);
		assert_eq!(
			go(json!({ "alg": "RS256", "kid": "k1" })),
			Reason::Algorithm("RS256".into())
		);
		assert_eq!(
			go(json!({ "alg": "es256", "kid": "k1" })),
			Reason::Algorithm("es256".into())
		);
		assert_eq!(go(json!({ "alg": "ES256" })), Reason::NoKeyId);
		assert_eq!(go(json!({ "alg": "ES256", "kid": "" })), Reason::NoKeyId);
		assert_eq!(
			go(json!({ "alg": "ES256", "kid": "k1", "crit": ["b64"] })),
			Reason::Critical
		);
		assert_eq!(go(json!({ "kid": "k1" })), Reason::Unreadable("header"));
		assert_eq!(
			go(json!({ "alg": 7, "kid": "k1" })),
			Reason::Unreadable("header")
		);
	}

	#[test]
	fn a_duplicated_header_or_claim_is_unreadable() {
		let s = Signer::new("k1");
		let set = keys(&[&s]);
		let head = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","alg":"ES256","kid":"k1"}"#);
		let body = URL_SAFE_NO_PAD.encode(claims().to_string());
		let token = format!("{head}.{body}.AAAA");
		assert_eq!(
			reason(check(&token, "alice", &policy(), &set, NOW)),
			Reason::Unreadable("header")
		);

		// A signed body naming db_role twice: refused, not "whichever came last".
		let raw = format!(
			r#"{{"iss":"{ISSUER}","aud":"{AUD}","sub":"u","token_use":"db","db_role":"bob","db_role":"alice","exp":{}}}"#,
			NOW + 60
		);
		let head = URL_SAFE_NO_PAD.encode(json!({ "alg": "ES256", "kid": "k1" }).to_string());
		let input = format!("{head}.{}", URL_SAFE_NO_PAD.encode(raw));
		let sig = s.pair.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
		let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
		assert_eq!(
			reason(check(&token, "alice", &policy(), &set, NOW)),
			Reason::Unreadable("claims")
		);
	}

	#[test]
	fn not_a_jwt_is_refused() {
		let set = keys(&[&Signer::new("k1")]);
		for t in ["", "a", "a.b", "a.b.c.d", "..", "a..b", "x.y.z"] {
			assert!(check(t, "alice", &policy(), &set, NOW).is_err(), "{t:?}");
		}
		assert_eq!(
			reason(check("a.b", "alice", &policy(), &set, NOW)),
			Reason::NotCompact
		);
		let long = "a".repeat(MAX_TOKEN_BYTES + 1);
		assert_eq!(
			reason(check(&long, "alice", &policy(), &set, NOW)),
			Reason::TooLong(MAX_TOKEN_BYTES + 1)
		);
	}

	#[test]
	fn a_tampered_token_is_refused() {
		let s = Signer::new("k1");
		let token = s.sign(&claims());
		let (input, sig) = token.rsplit_once('.').unwrap();
		let (head, _) = input.split_once('.').unwrap();
		let forged = URL_SAFE_NO_PAD.encode(with(|c| c["db_role"] = json!("postgres")).to_string());
		let t = format!("{head}.{forged}.{sig}");
		assert_eq!(
			reason(check(&t, "postgres", &policy(), &keys(&[&s]), NOW)),
			Reason::BadSignature
		);
		let t = format!("{input}.{}", &sig[..sig.len() - 2]);
		assert!(check(&t, "alice", &policy(), &keys(&[&s]), NOW).is_err());
		let t = format!("{input}=.{sig}");
		assert!(check(&t, "alice", &policy(), &keys(&[&s]), NOW).is_err());
	}

	#[test]
	fn the_issuer_must_match_exactly() {
		let s = Signer::new("k1");
		let r = run(&s, &with(|c| c["iss"] = json!("https://evil.example")));
		assert_eq!(
			r,
			Err(Refused {
				identity: None,
				reason: Reason::Issuer(Some("https://evil.example".into()))
			})
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["iss"] = json!(format!("{ISSUER}/"))))),
			Reason::Issuer(Some(format!("{ISSUER}/")))
		);
		assert_eq!(
			reason(run(
				&s,
				&with(|c| c.as_object_mut().unwrap().retain(|k, _| k != "iss"))
			)),
			Reason::Issuer(None)
		);
	}

	#[test]
	fn a_subject_is_required() {
		let s = Signer::new("k1");
		assert_eq!(
			reason(run(&s, &with(|c| c["sub"] = json!("")))),
			Reason::NoSubject
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["sub"] = json!("a\nb")))),
			Reason::NoSubject
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["sub"] = json!("x".repeat(256))))),
			Reason::NoSubject
		);
		assert_eq!(
			reason(run(
				&s,
				&with(|c| c.as_object_mut().unwrap().retain(|k, _| k != "sub"))
			)),
			Reason::NoSubject
		);
	}

	#[test]
	fn token_use_must_be_db() {
		let s = Signer::new("k1");
		let r = run(
			&s,
			&with(|c| c.as_object_mut().unwrap().retain(|k, _| k != "token_use")),
		);
		assert_eq!(
			r,
			Err(Refused {
				identity: Some("user-0001".into()),
				reason: Reason::TokenUse(None)
			})
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["token_use"] = json!("session")))),
			Reason::TokenUse(Some("session".into()))
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["token_use"] = json!("DB")))),
			Reason::TokenUse(Some("DB".into()))
		);
	}

	#[test]
	fn a_session_token_is_never_a_database_token() {
		let s = Signer::new("k1");
		// What snout-auth's session tokens look like (src/jwt.rs): role, aud "authenticated".
		let session = json!({ "iss": ISSUER, "aud": "authenticated", "sub": "user-0001", "role": "authenticated",
			"exp": NOW + 3600, "iat": NOW });
		assert_eq!(reason(run(&s, &session)), Reason::TokenUse(None));
		// Even dressed with token_use and this project's aud, `role` without `db_role` is refused.
		let dressed = with(|c| {
			c.as_object_mut().unwrap().remove("db_role");
			c["role"] = json!("alice");
		});
		assert_eq!(reason(run(&s, &dressed)), Reason::SessionToken);
		assert_eq!(
			reason(run(&s, &with(|c| c["role"] = json!("alice")))),
			Reason::RoleClaim
		);
		assert_eq!(
			reason(run(
				&s,
				&with(|c| c.as_object_mut().unwrap().retain(|k, _| k != "db_role"))
			)),
			Reason::NoDbRole
		);
	}

	#[test]
	fn the_audience_must_be_this_project() {
		let s = Signer::new("k1");
		assert_eq!(
			reason(run(&s, &with(|c| c["aud"] = json!("otherref")))),
			Reason::Audience
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["aud"] = json!([])))),
			Reason::Audience
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["aud"] = json!(["otherref"])))),
			Reason::Audience
		);
		assert_eq!(
			reason(run(
				&s,
				&with(|c| c.as_object_mut().unwrap().retain(|k, _| k != "aud"))
			)),
			Reason::Audience
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["aud"] = json!(7)))),
			Reason::Unreadable("claims")
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["aud"] = json!("PROJREF1")))),
			Reason::Audience
		);
	}

	#[test]
	fn time_is_checked_with_leeway() {
		let s = Signer::new("k1");
		assert_eq!(
			reason(run(&s, &with(|c| c["exp"] = json!(NOW - 31)))),
			Reason::Expired { ago: 31 }
		);
		assert!(
			run(&s, &with(|c| c["exp"] = json!(NOW - 29))).is_ok(),
			"within the leeway"
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["exp"] = json!(NOW - 30)))),
			Reason::Expired { ago: 30 }
		);
		assert_eq!(
			reason(run(
				&s,
				&with(|c| c.as_object_mut().unwrap().retain(|k, _| k != "exp"))
			)),
			Reason::NoExpiry
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["exp"] = json!("tomorrow")))),
			Reason::Unreadable("claims")
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["nbf"] = json!(NOW + 120)))),
			Reason::NotYetValid { in_secs: 120 }
		);
		assert!(run(&s, &with(|c| c["nbf"] = json!(NOW + 20))).is_ok());
		assert_eq!(
			reason(run(&s, &with(|c| c["iat"] = json!(NOW + 120)))),
			Reason::IssuedInFuture { in_secs: 120 }
		);
		assert_eq!(
			reason(run(&s, &with(|c| c["exp"] = json!(1e300)))),
			Reason::Unreadable("claims")
		);
	}

	#[test]
	fn a_token_may_not_claim_too_long_a_life() {
		let s = Signer::new("k1");
		let long = with(|c| c["exp"] = json!(NOW + 2 * 86_400));
		assert_eq!(
			reason(run(&s, &long)),
			Reason::TooLongLived {
				lifetime: 2 * 86_400 + 10,
				max: 86_400
			}
		);
		let unlimited = Policy {
			max_lifetime: 0,
			..policy()
		};
		assert!(check(&s.sign(&long), "alice", &unlimited, &keys(&[&s]), NOW).is_ok());
	}

	#[test]
	fn the_role_must_be_the_one_asked_for() {
		let s = Signer::new("k1");
		let t = s.sign(&claims());
		let r = check(&t, "bob", &policy(), &keys(&[&s]), NOW);
		assert_eq!(
			r,
			Err(Refused {
				identity: Some("user-0001".into()),
				reason: Reason::WrongRole {
					token: "alice".into(),
					asked: "bob".into()
				}
			})
		);
		assert!(
			check(&t, "Alice", &policy(), &keys(&[&s]), NOW).is_err(),
			"roles compare exactly"
		);
		assert!(check(&t, "", &policy(), &keys(&[&s]), NOW).is_err());
	}

	#[test]
	fn an_unconfigured_validator_refuses_everything() {
		let s = Signer::new("k1");
		let t = s.sign(&claims());
		let set = keys(&[&s]);
		let no_issuer = Policy {
			issuer: String::new(),
			..policy()
		};
		assert_eq!(
			reason(check(&t, "alice", &no_issuer, &set, NOW)),
			Reason::NotConfigured("snout_oauth.issuer")
		);
		let no_aud = Policy {
			audience: String::new(),
			..policy()
		};
		assert_eq!(
			reason(check(&t, "alice", &no_aud, &set, NOW)),
			Reason::NotConfigured("snout_oauth.audience")
		);
		assert!(check(&t, "alice", &policy(), &KeySet::default(), NOW).is_err());
	}

	#[test]
	fn no_sentence_quotes_the_token_and_control_characters_are_escaped() {
		let s = Signer::new("k1");
		let t = s.sign(&with(|c| c["db_role"] = json!("bob\nLOG:  forged line")));
		let why = check(&t, "alice", &policy(), &keys(&[&s]), NOW)
			.unwrap_err()
			.reason
			.to_string();
		assert!(!why.contains('\n'), "{why}");
		assert!(!why.contains(t.split('.').nth(2).unwrap()), "{why}");
		let long = Reason::Algorithm("x".repeat(500)).to_string();
		assert!(long.len() < 120, "{long}");
	}

	/// The per-login cost of the check itself. Run:
	/// `cargo test --release --lib token::tests::bench -- --ignored --nocapture`.
	#[test]
	#[ignore]
	fn bench() {
		let s = Signer::new("k1");
		let others: Vec<Signer> = (0..3).map(|i| Signer::new(&format!("old{i}"))).collect();
		let mut all: Vec<&Signer> = others.iter().collect();
		all.push(&s);
		let set = keys(&all);
		let t = s.sign(&claims());
		let n = 20_000;
		for _ in 0..1000 {
			assert!(check(&t, "alice", &policy(), &set, NOW).is_ok());
		}
		let start = std::time::Instant::now();
		for _ in 0..n {
			assert!(check(&t, "alice", &policy(), &set, NOW).is_ok());
		}
		let accept = start.elapsed() / n;
		let bad = Signer::new("k1").sign(&claims());
		let start = std::time::Instant::now();
		for _ in 0..n {
			assert!(check(&bad, "alice", &policy(), &set, NOW).is_err());
		}
		let forged = start.elapsed() / n;
		let start = std::time::Instant::now();
		for _ in 0..n {
			assert!(check("a.b.c", "alice", &policy(), &set, NOW).is_err());
		}
		let garbage = start.elapsed() / n;
		let jwks = json!({ "keys": all.iter().map(|s| s.jwk()).collect::<Vec<_>>() }).to_string();
		let start = std::time::Instant::now();
		for _ in 0..n {
			assert_eq!(KeySet::parse(&jwks).unwrap().keys.len(), 4);
		}
		let parse = start.elapsed() / n;
		println!(
			"bench: accept {accept:?}, forged signature {forged:?}, not a JWT {garbage:?}, parse a 4-key JWKS {parse:?} (each the mean of {n})"
		);
	}
}
