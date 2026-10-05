//! The settings. Every one is `sighup`: postgresql.conf (or the command line) sets it, a reload
//! changes it, no session can.
//!
//! How a validator library has settings at all: Postgres loads it with `load_external_function`
//! when the first `oauth` login reaches a backend, which runs `_PG_init`, which defines these.
//! Before that, a `snout_oauth.*` line in postgresql.conf is a PLACEHOLDER the server keeps for any
//! dotted name it does not know yet; defining the real setting adopts the placeholder's value. So
//! the library does not have to be in `shared_preload_libraries`, and a value is never lost. A
//! client cannot reach them during a login either: the options in a startup packet are applied
//! after authentication, and by then the library is loaded and the setting refuses `SET`.
use crate::token::Policy;
use pgrx::pg_sys;
use std::ffi::{CStr, c_char, c_int};

static mut ISSUER: *mut c_char = std::ptr::null_mut();
static mut AUDIENCE: *mut c_char = std::ptr::null_mut();
static mut KEYS_FILE: *mut c_char = std::ptr::null_mut();
static mut LEEWAY: c_int = 30;
static mut MAX_LIFETIME: c_int = 86_400;

fn read(setting: *const *mut c_char) -> String {
	// SAFETY: Postgres owns the string and replaces the pointer only between statements, and a
	// backend is single-threaded.
	let value = unsafe { *setting };
	if value.is_null() {
		return String::new();
	}
	unsafe { CStr::from_ptr(value) }
		.to_str()
		.unwrap_or("")
		.trim()
		.to_owned()
}

/// What a token is checked against, as the settings say now.
pub fn policy() -> Policy {
	Policy {
		issuer: read(&raw const ISSUER),
		audience: read(&raw const AUDIENCE),
		leeway: i64::from(unsafe { LEEWAY }),
		max_lifetime: i64::from(unsafe { MAX_LIFETIME }),
	}
}

/// The path of the key file.
pub fn keys_file() -> String {
	read(&raw const KEYS_FILE)
}

pub fn init() {
	unsafe {
		string(
			c"snout_oauth.issuer",
			c"The issuer a token must name in iss, exactly (the issuer of its discovery document)",
			&raw mut ISSUER,
		);
		string(
			c"snout_oauth.audience",
			c"The audience a token must name in aud: this database's project ref",
			&raw mut AUDIENCE,
		);
		string(
			c"snout_oauth.keys_file",
			c"Path to the issuer's public keys, a JWKS file; read again whenever it changes",
			&raw mut KEYS_FILE,
		);
		int(
			c"snout_oauth.leeway",
			c"Clock difference allowed around a token's exp, nbf and iat",
			&raw mut LEEWAY,
			30,
			0,
			600,
		);
		int(
			c"snout_oauth.max_lifetime",
			c"The longest life a token may claim (exp minus iat); 0 for no limit",
			&raw mut MAX_LIFETIME,
			86_400,
			0,
			366 * 86_400,
		);
		pg_sys::MarkGUCPrefixReserved(c"snout_oauth".as_ptr());
	}
}

unsafe fn string(name: &'static CStr, description: &'static CStr, variable: *mut *mut c_char) {
	unsafe {
		pg_sys::DefineCustomStringVariable(
			name.as_ptr(),
			description.as_ptr(),
			std::ptr::null(),
			variable,
			c"".as_ptr(),
			pg_sys::GucContext::PGC_SIGHUP,
			0,
			None,
			None,
			None,
		)
	};
}

unsafe fn int(
	name: &'static CStr,
	description: &'static CStr,
	variable: *mut c_int,
	boot: c_int,
	min: c_int,
	max: c_int,
) {
	unsafe {
		pg_sys::DefineCustomIntVariable(
			name.as_ptr(),
			description.as_ptr(),
			std::ptr::null(),
			variable,
			boot,
			min,
			max,
			pg_sys::GucContext::PGC_SIGHUP,
			pg_sys::GUC_UNIT_S as c_int,
			None,
			None,
			None,
		)
	};
}
