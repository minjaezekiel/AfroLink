//! The peers this node was connected to when it last stopped.
//!
//! # Why a restart is the dangerous moment
//!
//! A node's address book is a seed list plus hours of gossip. An attacker who
//! has been feeding it addresses does not get to choose this node's peers while
//! it is running — the outbound slots are taken and the group rule holds them —
//! but a restart hands every one of those slots back at once, and the book they
//! are drawn from is the book the attacker spent those hours shaping. That is
//! the cheapest moment to eclipse a node, and nothing else in the crate covers
//! it: the group rule bounds how *many* slots one subnet can take, not who is in
//! the running when they are all empty.
//!
//! Bitcoin's answer (PR #17428) is `anchors.dat`: write down two outbound peers
//! on shutdown, dial them before anything else on startup. This is that, sized
//! to our eight outbound slots — see [`afrolink_p2p::manager::ANCHOR_COUNT`] for
//! why two and not eight.
//!
//! # Read once, then deleted
//!
//! The file is removed as soon as it is read, before any dial is attempted, and
//! a later Bitcoin change made the same choice for the same reason: a node that
//! crash-loops must not be pinned to the same two peers forever. If those peers
//! are the reason it is crashing, or have gone away, one restart is all they
//! get. Writing it again is the *successful* run's job.
//!
//! # It is a hint, never an authority
//!
//! An anchor is dialled, not trusted. It still has to complete the handshake as
//! the identity written down, still passes the ban check and the group rule, and
//! still enters the address book by the ordinary route. A corrupt or hostile
//! anchor file costs this node at most two dials that fail.

use std::io::Write;
use std::path::Path;

use afrolink_p2p::peer::PeerAddr;
use afrolink_primitives::codec::{Decode, Encode, Reader};

/// Read the anchors and delete the file.
///
/// Never fails: this is an optimisation over the address book, and a node that
/// refused to start because it could not parse a hint would have turned a
/// hardening measure into an outage. A file that cannot be read yields no
/// anchors, which is exactly where the node was before this existed.
#[must_use]
pub fn take(path: &Path) -> Vec<PeerAddr> {
    let bytes = std::fs::read(path).unwrap_or_default();
    // Before parsing, and before dialling. A crash between here and the first
    // connection must not leave the same file to be read again.
    drop(std::fs::remove_file(path));

    let mut reader = Reader::new(&bytes);
    let mut anchors = Vec::new();
    while !reader.is_empty() {
        match PeerAddr::decode(&mut reader) {
            Ok(addr) => anchors.push(addr),
            // A truncated tail is a shutdown that was interrupted. Keep what was
            // whole and stop; the alternative is discarding good anchors because
            // the last one was cut off mid-write.
            Err(_) => break,
        }
    }
    anchors
}

/// Write the anchors for the next run, replacing whatever was there.
///
/// Best effort, and the caller is stopping: a node that failed to close cleanly
/// simply starts from its address book next time.
pub fn put(path: &Path, addrs: &[PeerAddr]) -> std::io::Result<()> {
    if addrs.is_empty() {
        drop(std::fs::remove_file(path));
        return Ok(());
    }
    let mut bytes = Vec::new();
    for addr in addrs {
        addr.encode(&mut bytes);
    }
    // Temp and rename, as with the signing record: a half-written anchor file is
    // read at exactly the moment the node is least able to check it.
    let temp = path.with_extension("next");
    let mut file = std::fs::File::create(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)
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
    use afrolink_crypto::SecretKey;
    use afrolink_p2p::peer::PeerId;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            path.push(format!("afrolink-anchors-{label}-{unique}"));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("anchors")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    fn addr(seed: u8, ip: &str) -> PeerAddr {
        PeerAddr::new(
            PeerId::new(SecretKey::from_bytes(&[seed; 32]).public_key()),
            format!("{ip}:26656").parse().unwrap(),
        )
    }

    #[test]
    fn anchors_survive_a_restart() {
        let dir = TempDir::new("restart");
        let written = vec![addr(1, "203.0.113.1"), addr(2, "198.51.100.1")];
        put(&dir.file(), &written).unwrap();
        assert_eq!(take(&dir.file()), written);
    }

    #[test]
    fn a_crash_loop_cannot_be_pinned_to_the_same_two_peers() {
        // The reason the file is deleted on read rather than on shutdown. If
        // these two peers are why the node is failing to stay up, or have gone
        // away, one restart is all they get — the second start draws from the
        // address book like any other.
        let dir = TempDir::new("crashloop");
        put(&dir.file(), &[addr(1, "203.0.113.1")]).unwrap();
        assert_eq!(take(&dir.file()).len(), 1);
        assert!(
            take(&dir.file()).is_empty(),
            "the file must not survive being read"
        );
        assert!(!dir.file().exists());
    }

    #[test]
    fn a_missing_file_is_a_node_with_no_anchors_rather_than_an_error() {
        let dir = TempDir::new("missing");
        assert!(take(&dir.file()).is_empty());
    }

    #[test]
    fn a_corrupt_file_costs_nothing_and_stops_the_node_from_nothing() {
        // An anchor is a hint. Refusing to start over an unparseable hint would
        // turn a hardening measure into an outage, and the worst a hostile file
        // can do is waste two dials.
        let dir = TempDir::new("corrupt");
        std::fs::write(dir.file(), b"not a peer address at all").unwrap();
        assert!(take(&dir.file()).is_empty());
        assert!(!dir.file().exists(), "and it is still cleared away");
    }

    #[test]
    fn a_truncated_tail_does_not_discard_the_anchors_before_it() {
        let dir = TempDir::new("truncated");
        let mut bytes = Vec::new();
        addr(1, "203.0.113.1").encode(&mut bytes);
        addr(2, "198.51.100.1").encode(&mut bytes);
        bytes.truncate(bytes.len() - 3);
        std::fs::write(dir.file(), &bytes).unwrap();
        assert_eq!(take(&dir.file()), vec![addr(1, "203.0.113.1")]);
    }

    #[test]
    fn writing_nothing_clears_the_file() {
        // A node that stopped with no outbound peers must not leave the previous
        // run's anchors behind: they are stale by definition, and dialling them
        // first would be preferring the oldest information this node has.
        let dir = TempDir::new("empty");
        put(&dir.file(), &[addr(1, "203.0.113.1")]).unwrap();
        put(&dir.file(), &[]).unwrap();
        assert!(take(&dir.file()).is_empty());
    }
}
