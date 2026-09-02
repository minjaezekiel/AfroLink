//! Keys on disk.
//!
//! # Two keys, never one
//!
//! A node holds a **network key**, which identifies it to peers, and a
//! **consensus key**, which signs proposals and votes. They are separate files
//! because they are separate jobs: relaying blocks requires no stake and signs
//! nothing that can be slashed, so running a relay must not require the key that
//! can be. Keeping them apart is also what makes a remote signer possible later —
//! the consensus key can move to another machine without the network key going
//! with it.
//!
//! # What this does not do
//!
//! **No encryption at rest.** A key file is hex, protected by file permissions
//! and nothing else, and it is worth saying so plainly rather than implying
//! otherwise. A validator key that matters belongs in an HSM or behind a remote
//! signer; a passphrase on a file that a daemon must read unattended at boot
//! protects against someone reading the disk and not against someone who has the
//! machine. This is the honest version of what is actually implemented.
//!
//! Permissions are set to `0600` on Unix, and a key file readable by anyone else
//! is **refused** rather than warned about.

use std::path::Path;

use afrolink_crypto::SecretKey;

/// Why a key could not be loaded or created.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The file could not be read or written.
    #[error("cannot access {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The file did not contain 32 hex bytes.
    #[error("{path} is not a 32-byte hex key")]
    Malformed {
        /// The file.
        path: String,
    },
    /// The file is readable by somebody other than its owner.
    #[error("{path} is readable by other users (mode {mode:o}); refusing to use it")]
    TooOpen {
        /// The file.
        path: String,
        /// The permission bits found.
        mode: u32,
    },
    /// A key already exists where one was about to be written.
    #[error("{path} already exists; refusing to overwrite a key")]
    Exists {
        /// The file.
        path: String,
    },
    /// The operating system entropy source failed.
    #[error("no entropy available to generate a key")]
    NoEntropy,
}

/// Read a key, refusing one the rest of the machine can read.
///
/// # Errors
/// Returns a [`KeyError`] if the file is missing, malformed, or too permissive.
pub fn load(path: &Path) -> Result<SecretKey, KeyError> {
    check_permissions(path)?;
    let text = std::fs::read_to_string(path).map_err(|source| KeyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let bytes = hex::decode(text.trim()).map_err(|_| KeyError::Malformed {
        path: path.display().to_string(),
    })?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| KeyError::Malformed {
        path: path.display().to_string(),
    })?;
    Ok(SecretKey::from_bytes(&seed))
}

/// Generate a key and write it, refusing to replace one that exists.
///
/// # Errors
/// Returns [`KeyError::Exists`] rather than overwriting. A key file is the one
/// thing in a data directory that cannot be regenerated: replacing a validator's
/// consensus key silently is how a node loses its identity, its stake and, if the
/// old key is still live elsewhere, its slashing protection all at once.
pub fn create(path: &Path) -> Result<SecretKey, KeyError> {
    if path.exists() {
        return Err(KeyError::Exists {
            path: path.display().to_string(),
        });
    }
    let key = SecretKey::generate().map_err(|_| KeyError::NoEntropy)?;
    let text = hex::encode(key.to_bytes());
    write_private(path, &text)?;
    Ok(key)
}

/// Write a file only its owner can read.
fn write_private(path: &Path, contents: &str) -> Result<(), KeyError> {
    let io = |source: std::io::Error| KeyError::Io {
        path: path.display().to_string(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    std::fs::write(path, contents).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set after writing rather than before: a file created with default
        // permissions and narrowed afterwards is readable for the length of one
        // write, which is a race worth naming even though it is small.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    }
    Ok(())
}

/// Refuse a key file the rest of the machine can read.
fn check_permissions(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|source| KeyError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mode = meta.permissions().mode() & 0o777;
        // Refused rather than warned about. A warning about a signing key's
        // permissions is a line an operator scrolls past once and never again,
        // and by then every other account on the machine can sign as this node.
        if mode & 0o077 != 0 {
            return Err(KeyError::TooOpen {
                path: path.display().to_string(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            path.push(format!("afrolink-key-{label}-{unique}"));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_generated_key_reads_back_as_itself() {
        let dir = TempDir::new("roundtrip");
        let path = dir.join("node_key");
        let made = create(&path).unwrap();
        let read = load(&path).unwrap();
        assert_eq!(read.to_bytes(), made.to_bytes());
    }

    #[test]
    fn an_existing_key_is_never_overwritten() {
        // The one file in a data directory that cannot be regenerated. Replacing
        // a validator's key silently loses its identity, its stake, and — if the
        // old key is still live elsewhere — its slashing protection at once.
        let dir = TempDir::new("no-overwrite");
        let path = dir.join("node_key");
        let first = create(&path).unwrap();
        assert!(matches!(create(&path), Err(KeyError::Exists { .. })));
        assert_eq!(load(&path).unwrap().to_bytes(), first.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_the_rest_of_the_machine_can_read_is_refused() {
        // Refused rather than warned about: a warning about a signing key's
        // permissions is a line an operator scrolls past once, and by then every
        // other account on the box can sign as this node.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("permissions");
        let path = dir.join("node_key");
        create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&path), Err(KeyError::TooOpen { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn a_key_is_written_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        let path = dir.join("node_key");
        create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_file_that_is_not_a_key_is_refused_rather_than_hashed_into_one() {
        // The tempting shortcut is to accept anything and derive a key from it,
        // which turns a truncated file into a different, silently valid identity.
        let dir = TempDir::new("malformed");
        let path = dir.join("node_key");
        std::fs::write(&path, "not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(load(&path), Err(KeyError::Malformed { .. })));
    }
}
