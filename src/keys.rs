//! The issuer's public keys, read from a JWKS file the platform writes (DB-OAUTH.md O6: the
//! validator never makes a network call). Pure: no `unsafe`, no Postgres, tested with plain
//! `#[test]`s and fuzzed (fuzz/). It reads the file with `std::fs` and nothing else.
//!
//! A file holds several keys by `kid`, so an issuer rotates by publishing the new key beside the
//! old one, signing with the new one, and removing the old one once every token it signed has
//! expired. The file is cached and read again only when it changes ([`KeyCache`]).
//!
//! A file that cannot be read or does not parse is an `Err`, and the caller refuses every login
//! while it is. Nothing here ever falls back to accepting.
#![forbid(unsafe_code)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use std::fs::{File, Metadata};
use std::io::Read;

/// The largest key file read. A JWKS of a few keys is well under a kilobyte.
pub const MAX_FILE_BYTES: u64 = 256 * 1024;

/// One ES256 public key: its `kid` and the uncompressed P-256 point (`04 || x || y`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
	pub kid: String,
	pub point: [u8; 65],
}

/// The usable keys in a file, and how many of its entries were not ES256 keys and were left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeySet {
	pub keys: Vec<Key>,
	pub skipped: usize,
}

impl KeySet {
	/// Every key published under `kid`. Usually one; a file that repeats a `kid` is not refused,
	/// since each of its keys is one the issuer published.
	pub fn find<'a>(&'a self, kid: &'a str) -> impl Iterator<Item = &'a Key> + 'a {
		self.keys.iter().filter(move |k| k.kid == kid)
	}

	/// A JWKS document (`{"keys": [...]}`). Entries that are not EC P-256 signing keys for ES256
	/// (another `kty`, `crv`, `alg` or `use`, or no `kid`) are skipped and counted. The whole file
	/// is refused when it is not that shape, when an EC P-256 entry's coordinates are not 32 bytes
	/// each, when any entry carries a PRIVATE key (`d`: the pod must hold public keys only, O5), or
	/// when nothing usable is left.
	pub fn parse(text: &str) -> Result<KeySet, String> {
		#[derive(Deserialize)]
		struct Document {
			keys: Vec<serde_json::Map<String, serde_json::Value>>,
		}
		let doc: Document =
			serde_json::from_str(text).map_err(|e| format!("is not a JWKS document ({e})"))?;
		let mut set = KeySet::default();
		for (i, entry) in doc.keys.iter().enumerate() {
			let text = |name: &str| entry.get(name).and_then(serde_json::Value::as_str);
			if entry.contains_key("d") {
				return Err(format!(
					"key {} holds a private key (\"d\"); the file must hold public keys only",
					i + 1
				));
			}
			let usable = text("kty") == Some("EC")
				&& text("crv") == Some("P-256")
				&& entry.get("alg").is_none_or(|a| a.as_str() == Some("ES256"))
				&& entry.get("use").is_none_or(|u| u.as_str() == Some("sig"));
			let Some(kid) = text("kid").filter(|k| !k.is_empty()) else {
				set.skipped += 1;
				continue;
			};
			if !usable {
				set.skipped += 1;
				continue;
			}
			let coordinate = |name: &str| -> Result<[u8; 32], String> {
				let bytes = text(name)
					.and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
					.ok_or_else(|| format!("key {} ({kid:?}) has no readable \"{name}\"", i + 1))?;
				<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
					format!(
						"key {} ({kid:?}) has a \"{name}\" of {} bytes, not 32",
						i + 1,
						bytes.len()
					)
				})
			};
			let (x, y) = (coordinate("x")?, coordinate("y")?);
			let mut point = [0u8; 65];
			point[0] = 4;
			point[1..33].copy_from_slice(&x);
			point[33..].copy_from_slice(&y);
			set.keys.push(Key {
				kid: kid.to_owned(),
				point,
			});
		}
		if set.keys.is_empty() {
			return Err(format!(
				"holds no ES256 P-256 signing key with a kid ({} entries skipped)",
				set.skipped
			));
		}
		Ok(set)
	}
}

/// What identifies one version of the file: when a field changes, the file is read again. A
/// platform that writes the file by rename (write a temporary file, then rename it over) changes
/// the inode every time, so even a rewrite within one clock tick is seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
	len: u64,
	modified_ns: i128,
	#[cfg(unix)]
	dev: u64,
	#[cfg(unix)]
	ino: u64,
	#[cfg(unix)]
	ctime_ns: i128,
}

impl Stamp {
	fn of(meta: &Metadata) -> Stamp {
		let modified_ns = meta
			.modified()
			.ok()
			.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
			.map_or(0, |d| d.as_nanos() as i128);
		#[cfg(unix)]
		{
			use std::os::unix::fs::MetadataExt;
			Stamp {
				len: meta.len(),
				modified_ns,
				dev: meta.dev(),
				ino: meta.ino(),
				ctime_ns: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
			}
		}
		#[cfg(not(unix))]
		Stamp {
			len: meta.len(),
			modified_ns,
		}
	}
}

/// The key file, read once and again only when it changes. One per process: a Postgres backend
/// validates one login, so in a backend this is read at most once, and a server that preloads the
/// library reads it in the postmaster and every backend starts with it (it is still checked on
/// every login, by one `stat`).
#[derive(Debug, Default)]
pub struct KeyCache {
	path: String,
	stamp: Option<Stamp>,
	state: Option<Result<KeySet, String>>,
	reads: u64,
}

impl KeyCache {
	/// The keys in `path` as they are now. `Err` is a sentence saying why there are none, and the
	/// caller must refuse.
	pub fn get(&mut self, path: &str) -> Result<&KeySet, String> {
		if path.is_empty() {
			return Err("snout_oauth.keys_file is not set".to_owned());
		}
		let current = std::fs::metadata(path).map(|m| Stamp::of(&m));
		let fresh = self.path == path
			&& self.state.is_some()
			&& current.as_ref().ok() == self.stamp.as_ref();
		if !fresh {
			let (stamp, state) = Self::read(path);
			self.path = path.to_owned();
			self.stamp = stamp;
			self.state = Some(state);
			self.reads += 1;
		}
		match self.state.as_ref() {
			Some(Ok(set)) => Ok(set),
			Some(Err(e)) => Err(e.clone()),
			None => Err("the key file was never read".to_owned()),
		}
	}

	/// How many times the file has been read (for tests and the benchmark).
	pub fn reads(&self) -> u64 {
		self.reads
	}

	fn read(path: &str) -> (Option<Stamp>, Result<KeySet, String>) {
		let fail = |why: String| (None, Err(format!("the key file {path:?} {why}")));
		let mut file = match File::open(path) {
			Ok(f) => f,
			Err(e) => return fail(format!("cannot be opened ({e})")),
		};
		// The stamp of the file actually opened, so a rename between the stat and the open is
		// seen on the next login rather than cached under the old stamp.
		let meta = match file.metadata() {
			Ok(m) => m,
			Err(e) => return fail(format!("cannot be read ({e})")),
		};
		if !meta.is_file() {
			return fail("is not a regular file".to_owned());
		}
		if meta.len() > MAX_FILE_BYTES {
			return fail(format!(
				"is {} bytes, more than the {MAX_FILE_BYTES} a key file may be",
				meta.len()
			));
		}
		let mut text = String::new();
		if let Err(e) = (&mut file)
			.take(MAX_FILE_BYTES + 1)
			.read_to_string(&mut text)
		{
			return fail(format!("cannot be read ({e})"));
		}
		// A stamp is kept for a file that does not parse too: it is not read again until it
		// changes, and every login meanwhile is refused with the same sentence.
		let stamp = Some(Stamp::of(&meta));
		match KeySet::parse(&text) {
			Ok(set) => (stamp, Ok(set)),
			Err(e) => (stamp, Err(format!("the key file {path:?} {e}"))),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn b64(bytes: &[u8]) -> String {
		URL_SAFE_NO_PAD.encode(bytes)
	}

	fn ec(kid: &str) -> serde_json::Value {
		serde_json::json!({ "kty": "EC", "crv": "P-256", "kid": kid, "x": b64(&[1; 32]), "y": b64(&[2; 32]), "alg": "ES256", "use": "sig" })
	}

	#[test]
	fn several_keys_by_kid() {
		let doc = serde_json::json!({ "keys": [ec("a"), ec("b")] }).to_string();
		let set = KeySet::parse(&doc).unwrap();
		assert_eq!(set.keys.len(), 2);
		assert_eq!(set.find("b").count(), 1);
		assert_eq!(set.find("c").count(), 0);
		assert_eq!(set.keys[0].point[0], 4);
		assert_eq!(&set.keys[0].point[1..33], &[1; 32]);
	}

	#[test]
	fn other_kinds_of_key_are_skipped() {
		let rsa = serde_json::json!({ "kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB" });
		let p384 = serde_json::json!({ "kty": "EC", "crv": "P-384", "kid": "p", "x": b64(&[1; 48]), "y": b64(&[2; 48]) });
		let enc = serde_json::json!({ "kty": "EC", "crv": "P-256", "kid": "e", "use": "enc", "x": b64(&[1; 32]), "y": b64(&[2; 32]) });
		let no_kid = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": b64(&[1; 32]), "y": b64(&[2; 32]) });
		let doc = serde_json::json!({ "keys": [rsa, p384, enc, no_kid, ec("ok")] }).to_string();
		let set = KeySet::parse(&doc).unwrap();
		assert_eq!(set.keys.len(), 1);
		assert_eq!(set.skipped, 4);
	}

	#[test]
	fn a_file_without_a_usable_key_is_refused() {
		assert!(
			KeySet::parse(r#"{"keys": []}"#)
				.unwrap_err()
				.contains("no ES256")
		);
		assert!(KeySet::parse(r#"{"keys": [{"kty": "RSA", "kid": "r"}]}"#).is_err());
		assert!(KeySet::parse("").unwrap_err().contains("not a JWKS"));
		assert!(KeySet::parse(r#"{"keys": {}}"#).is_err());
		assert!(KeySet::parse("[]").is_err());
	}

	#[test]
	fn a_private_key_refuses_the_file() {
		let mut key = ec("a");
		key["d"] = serde_json::json!(b64(&[3; 32]));
		let doc = serde_json::json!({ "keys": [key] }).to_string();
		assert!(KeySet::parse(&doc).unwrap_err().contains("private key"));
	}

	#[test]
	fn a_short_coordinate_refuses_the_file() {
		let mut key = ec("a");
		key["x"] = serde_json::json!(b64(&[1; 31]));
		let doc = serde_json::json!({ "keys": [key, ec("b")] }).to_string();
		assert!(KeySet::parse(&doc).unwrap_err().contains("31 bytes"));
		let mut key = ec("a");
		key["y"] = serde_json::json!("not base64url!");
		let doc = serde_json::json!({ "keys": [key] }).to_string();
		assert!(KeySet::parse(&doc).unwrap_err().contains("no readable"));
	}

	fn scratch(name: &str) -> std::path::PathBuf {
		let dir =
			std::env::temp_dir().join(format!("snout_oauth_keys_{}_{name}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir.join("jwks.json")
	}

	fn write_by_rename(path: &std::path::Path, body: &str) {
		let tmp = path.with_extension("tmp");
		std::fs::write(&tmp, body).unwrap();
		std::fs::rename(&tmp, path).unwrap();
	}

	#[test]
	fn the_cache_reads_again_only_when_the_file_changes() {
		let path = scratch("cache");
		let p = path.to_str().unwrap();
		write_by_rename(&path, &serde_json::json!({ "keys": [ec("a")] }).to_string());
		let mut cache = KeyCache::default();
		assert_eq!(cache.get(p).unwrap().keys.len(), 1);
		assert_eq!(cache.get(p).unwrap().keys.len(), 1);
		assert_eq!(cache.reads(), 1, "an unchanged file is not read again");

		write_by_rename(
			&path,
			&serde_json::json!({ "keys": [ec("a"), ec("b")] }).to_string(),
		);
		assert_eq!(
			cache.get(p).unwrap().find("b").count(),
			1,
			"a rotated file is seen at once"
		);
		assert_eq!(cache.reads(), 2);

		write_by_rename(&path, &serde_json::json!({ "keys": [ec("b")] }).to_string());
		assert_eq!(
			cache.get(p).unwrap().find("a").count(),
			0,
			"a removed key is gone at once"
		);
	}

	#[test]
	fn a_missing_or_broken_file_is_an_error_until_it_is_fixed() {
		let path = scratch("missing");
		let p = path.to_str().unwrap();
		let mut cache = KeyCache::default();
		assert!(cache.get(p).unwrap_err().contains("cannot be opened"));
		assert!(cache.get("").unwrap_err().contains("not set"));

		write_by_rename(&path, "{ not json");
		assert!(cache.get(p).unwrap_err().contains("not a JWKS"));
		let reads = cache.reads();
		assert!(cache.get(p).is_err());
		assert_eq!(
			cache.reads(),
			reads,
			"a broken file is not read again until it changes"
		);

		write_by_rename(&path, &serde_json::json!({ "keys": [ec("a")] }).to_string());
		assert!(cache.get(p).is_ok());

		std::fs::remove_file(&path).unwrap();
		assert!(
			cache.get(p).unwrap_err().contains("cannot be opened"),
			"a deleted file refuses at once"
		);
	}

	#[test]
	fn a_directory_or_a_huge_file_is_refused() {
		let path = scratch("dir");
		let mut cache = KeyCache::default();
		assert!(cache.get(path.parent().unwrap().to_str().unwrap()).is_err());
		std::fs::write(&path, vec![b' '; (MAX_FILE_BYTES + 1) as usize]).unwrap();
		assert!(
			cache
				.get(path.to_str().unwrap())
				.unwrap_err()
				.contains("more than")
		);
	}
}
