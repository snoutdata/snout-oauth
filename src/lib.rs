//! snout_oauth: a Postgres 18 OAuth validator.
//!
//! A `pg_hba` line with method `oauth` makes the client fetch a bearer token from an issuer and
//! present it; Postgres hands the token and the role asked for to the library named in
//! `oauth_validator_libraries`, and this library decides. A token is accepted only when it is a
//! DATABASE token (token.rs says exactly what that is) signed by a key in the key file (keys.rs),
//! for this project, unexpired, and for the very role asked for. README.md is the reference.
//!
//! This file is the C boundary and the only place `unsafe` is written: the module magic, the
//! entry point Postgres looks up, the callback, and the settings (settings.rs). The decision itself
//! is pure Rust that never touches Postgres, called inside `catch_unwind`.
pub mod keys;
mod settings;
pub mod token;

use pgrx::pg_sys;
use pgrx::{PgLogLevel, PgSqlErrorCode, ereport};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Mutex;

pgrx::pg_module_magic!();

/// `ValidatorModuleState` from libpq/oauth.h (Postgres 18), which pgrx's bindings do not carry.
#[repr(C)]
pub struct ValidatorModuleState {
	pub sversion: c_int,
	pub private_data: *mut c_void,
}

/// `ValidatorModuleResult` from libpq/oauth.h.
#[repr(C)]
pub struct ValidatorModuleResult {
	pub authorized: bool,
	pub authn_id: *mut c_char,
}

type ValidateCb = unsafe extern "C-unwind" fn(
	*const ValidatorModuleState,
	*const c_char,
	*const c_char,
	*mut ValidatorModuleResult,
) -> bool;

/// `OAuthValidatorCallbacks` from libpq/oauth.h.
#[repr(C)]
pub struct OAuthValidatorCallbacks {
	pub magic: u32,
	pub startup_cb: Option<unsafe extern "C-unwind" fn(*mut ValidatorModuleState)>,
	pub shutdown_cb: Option<unsafe extern "C-unwind" fn(*mut ValidatorModuleState)>,
	pub validate_cb: Option<ValidateCb>,
}

/// `PG_OAUTH_VALIDATOR_MAGIC`: the validator ABI this was built for (18.0 through 18.6 at least).
pub const PG_OAUTH_VALIDATOR_MAGIC: u32 = 0x2025_0220;

static CALLBACKS: OAuthValidatorCallbacks = OAuthValidatorCallbacks {
	magic: PG_OAUTH_VALIDATOR_MAGIC,
	startup_cb: None,
	shutdown_cb: None,
	validate_cb: Some(validate),
};

/// The key file, cached per process (keys.rs).
static KEYS: Mutex<Option<keys::KeyCache>> = Mutex::new(None);

#[pgrx::pg_guard]
pub extern "C-unwind" fn _PG_init() {
	settings::init();
	// Preloaded (shared_preload_libraries), the postmaster reads the key file once and every
	// backend starts with it, checking it with one stat per login. Loaded at the first login (the
	// usual way), each backend reads it once. A problem with the file is said here and again on
	// every login it refuses.
	if unsafe { pg_sys::process_shared_preload_libraries_in_progress }
		&& let Ok(Err(why)) = std::panic::catch_unwind(|| with_keys(|k| k.map(|_| ())))
	{
		ereport!(
			PgLogLevel::LOG_SERVER_ONLY,
			PgSqlErrorCode::ERRCODE_CONFIG_FILE_ERROR,
			format!("snout_oauth: {why}; every OAuth login will be refused until it can be read")
		);
	}
}

/// The entry point Postgres looks up by name after loading the library.
#[unsafe(no_mangle)]
pub extern "C-unwind" fn _PG_oauth_validator_module_init() -> *const OAuthValidatorCallbacks {
	&raw const CALLBACKS
}

fn with_keys<T>(f: impl FnOnce(Result<&keys::KeySet, String>) -> T) -> T {
	let mut guard = KEYS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	let cache = guard.get_or_insert_with(keys::KeyCache::default);
	f(cache.get(&settings::keys_file()))
}

fn now() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |d| d.as_secs() as i64)
}

/// The whole decision, in Rust: the settings as they are, the key file as it is, the clock.
fn decide(token: &[u8], role: &[u8]) -> Result<String, token::Refused> {
	let (Ok(token), Ok(role)) = (std::str::from_utf8(token), std::str::from_utf8(role)) else {
		return Err(token::Refused {
			identity: None,
			reason: token::Reason::NotUtf8,
		});
	};
	let policy = settings::policy();
	if let Some(setting) = token::missing_setting(&policy) {
		return Err(token::Refused {
			identity: None,
			reason: token::Reason::NotConfigured(setting),
		});
	}
	with_keys(|set| match set {
		Ok(set) => token::check(token, role, &policy, set, now()),
		Err(why) => Err(token::Refused {
			identity: None,
			reason: token::Reason::NoKeys(why),
		}),
	})
}

/// `validate_cb`. Every refusal is one server log line with its reason (never the token) and
/// `authorized = false`. The line is COMMERROR (`LOG_SERVER_ONLY`: printed as LOG, never sent to
/// the client), the level the Postgres docs ask a validator to use, so an unauthenticated client
/// learns nothing about why. The identity is set whenever the token was our issuer's, refused or
/// not, so the server's own "connection authenticated" line names the person.
#[pgrx::pg_guard]
unsafe extern "C-unwind" fn validate(
	_state: *const ValidatorModuleState,
	token: *const c_char,
	role: *const c_char,
	result: *mut ValidatorModuleResult,
) -> bool {
	if token.is_null() || role.is_null() || result.is_null() {
		return false;
	}
	// SAFETY: Postgres passes NUL-terminated strings that live for the call.
	let (token, role) = unsafe {
		(
			CStr::from_ptr(token).to_bytes(),
			CStr::from_ptr(role).to_bytes(),
		)
	};
	let asked = String::from_utf8_lossy(role).into_owned();

	let (authorized, identity) = match std::panic::catch_unwind(|| decide(token, role)) {
		Ok(Ok(sub)) => (true, Some(sub)),
		Ok(Err(refused)) => {
			let who = refused
				.identity
				.as_deref()
				.map(|s| format!(" (identity {s:?})"))
				.unwrap_or_default();
			ereport!(
				PgLogLevel::LOG_SERVER_ONLY,
				PgSqlErrorCode::ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION,
				format!(
					"snout_oauth: refused a sign-in as role {asked:?}{who}: {}",
					refused.reason
				)
			);
			(false, refused.identity)
		}
		Err(_) => {
			// Postgres logs "internal error in OAuth validator module" for a false return, and
			// refuses the login.
			ereport!(
				PgLogLevel::LOG_SERVER_ONLY,
				PgSqlErrorCode::ERRCODE_INTERNAL_ERROR,
				format!(
					"snout_oauth: refused a sign-in as role {asked:?}: the validator failed unexpectedly"
				)
			);
			unsafe { (*result).authorized = false };
			return false;
		}
	};
	unsafe {
		(*result).authorized = authorized;
		if let Some(id) = identity.and_then(|s| CString::new(s).ok()) {
			// palloc'd in the current context, as the header asks; Postgres copies it.
			(*result).authn_id = pg_sys::pstrdup(id.as_ptr());
		}
	}
	true
}

/// Postgres-side tests: the library loaded into a real server, its entry point and its callback
/// driven the way auth-oauth.c drives them.
#[cfg(any(test, feature = "pg_test"))]
#[pgrx::pg_schema]
mod tests {
	use super::*;
	use crate::token::fixtures::{AUD, ISSUER, Signer, claims};
	use pgrx::prelude::*;
	use serde_json::json;

	pub const KEYS_FILE: &str = "/tmp/snout_oauth_pg_test/jwks.json";

	fn write_keys(body: &str) {
		let path = std::path::Path::new(KEYS_FILE);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		let tmp = path.with_extension("tmp");
		std::fs::write(&tmp, body).unwrap();
		std::fs::rename(&tmp, path).unwrap();
	}

	fn jwks(signers: &[&Signer]) -> String {
		json!({ "keys": signers.iter().map(|s| s.jwk()).collect::<Vec<_>>() }).to_string()
	}

	/// Calls the callback exactly as auth-oauth.c does: a palloc0'd result, the token, the role.
	fn login(token: &str, role: &str) -> (bool, bool, Option<String>) {
		let callbacks = unsafe { &*_PG_oauth_validator_module_init() };
		assert_eq!(callbacks.magic, PG_OAUTH_VALIDATOR_MAGIC);
		let validate = callbacks.validate_cb.expect("validate_cb");
		let state = ValidatorModuleState {
			sversion: 180_000,
			private_data: std::ptr::null_mut(),
		};
		let mut result = ValidatorModuleResult {
			authorized: false,
			authn_id: std::ptr::null_mut(),
		};
		let (t, r) = (CString::new(token).unwrap(), CString::new(role).unwrap());
		let ok = unsafe { validate(&state, t.as_ptr(), r.as_ptr(), &mut result) };
		let id = (!result.authn_id.is_null()).then(|| {
			unsafe { CStr::from_ptr(result.authn_id) }
				.to_string_lossy()
				.into_owned()
		});
		(ok, result.authorized, id)
	}

	fn now() -> i64 {
		super::now()
	}

	fn fresh(c: &mut serde_json::Value) {
		c["iat"] = json!(now() - 5);
		c["exp"] = json!(now() + 600);
	}

	#[pg_test]
	fn the_settings_exist_and_a_session_cannot_change_them() {
		assert_eq!(
			Spi::get_one::<String>("show snout_oauth.issuer")
				.unwrap()
				.unwrap(),
			ISSUER
		);
		assert_eq!(
			Spi::get_one::<String>("show snout_oauth.audience")
				.unwrap()
				.unwrap(),
			AUD
		);
		assert_eq!(
			Spi::get_one::<String>("show snout_oauth.leeway")
				.unwrap()
				.unwrap(),
			"30s"
		);
		assert_eq!(
			Spi::get_one::<String>("show snout_oauth.max_lifetime")
				.unwrap()
				.unwrap(),
			"1d"
		);
		let context = Spi::get_one::<String>(
			"select context from pg_settings where name = 'snout_oauth.issuer'",
		);
		assert_eq!(context.unwrap().unwrap(), "sighup");
	}

	#[pg_test(error = "parameter \"snout_oauth.audience\" cannot be changed now")]
	fn set_is_refused() {
		Spi::run("set snout_oauth.audience = 'someone-else'").unwrap();
	}

	#[pg_test]
	fn the_callback_accepts_refuses_and_follows_the_key_file() {
		let k1 = Signer::new("k1");
		let k2 = Signer::new("k2");
		let mut c = claims();
		fresh(&mut c);

		// No key file yet: refused, never accepted.
		let _ = std::fs::remove_file(KEYS_FILE);
		assert_eq!(login(&k1.sign(&c), "alice"), (true, false, None));

		write_keys(&jwks(&[&k1]));
		assert_eq!(
			login(&k1.sign(&c), "alice"),
			(true, true, Some("user-0001".into()))
		);
		// The right person asking for someone else's role: refused, and named.
		assert_eq!(
			login(&k1.sign(&c), "bob"),
			(true, false, Some("user-0001".into()))
		);
		// A key that is not published yet: refused, and nobody is named.
		assert_eq!(login(&k2.sign(&c), "alice"), (true, false, None));
		// A session token, signed with the right key even: refused.
		let mut session = c.clone();
		session.as_object_mut().unwrap().remove("db_role");
		session["role"] = json!("alice");
		assert_eq!(
			login(&k1.sign(&session), "alice"),
			(true, false, Some("user-0001".into()))
		);

		// Rotation, in the same process: k2 joins and works at once, then k1 leaves and stops.
		write_keys(&jwks(&[&k1, &k2]));
		assert!(login(&k2.sign(&c), "alice").1);
		write_keys(&jwks(&[&k2]));
		assert!(!login(&k1.sign(&c), "alice").1);
		assert!(login(&k2.sign(&c), "alice").1);

		// A broken file refuses everything, and fixing it is seen on the next login.
		write_keys("{ this is not json");
		assert!(!login(&k2.sign(&c), "alice").1);
		write_keys(&jwks(&[&k2]));
		assert!(login(&k2.sign(&c), "alice").1);

		// Not a token at all.
		assert_eq!(login("not-a-token", "alice"), (true, false, None));
	}
}

/// Required by `cargo pgrx test`; must sit at the crate root.
#[cfg(test)]
pub mod pg_test {
	pub fn setup(_options: Vec<&str>) {}

	pub fn postgresql_conf_options() -> Vec<&'static str> {
		vec![
			"snout_oauth.issuer = 'https://accounts.example.test'",
			"snout_oauth.audience = 'projref1'",
			"snout_oauth.keys_file = '/tmp/snout_oauth_pg_test/jwks.json'",
		]
	}
}
