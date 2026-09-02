//! The signing record, on a disk.
//!
//! [`afrolink_node::SignRecord`] says what the rule is; this makes it survive a
//! restart, which is the only reason the rule exists.
//!
//! # Written before the signature, and `fsync`ed
//!
//! The order is the whole point. A record written *after* the signature is
//! released is a record that a crash in between turns into a lie: the node comes
//! back believing it never signed, votes again, and equivocates — now
//! punishably, because evidence reporting exists.
//!
//! So `claim` writes and flushes to stable storage before it returns, and the
//! caller signs only on `Ok`. It costs an `fsync` per vote, which is two per
//! block. On the storage a validator should be using that is far below the cost
//! of verifying the block's signatures; on storage where it is not, the honest
//! answer is that the machine is not fit to hold a validator key.
//!
//! # Temp file and rename
//!
//! The record is written to a sibling file and renamed over the real one, so a
//! crash leaves either the old state or the new one and never half of either. A
//! torn signing record is worse than none, because it looks like a state.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use afrolink_consensus::Step;
use afrolink_node::{SignRecord, SignRefusal, signing::check_after};
use afrolink_primitives::{Height, Round};

/// A signing record kept in a file.
#[derive(Debug)]
pub struct FileSignRecord {
    path: PathBuf,
    /// The cached value, so the common case is one write rather than a read and
    /// a write. The file is the truth; this is what was last written to it.
    last: Mutex<Option<(Height, Round, Step)>>,
}

impl FileSignRecord {
    /// Open the record at `path`, reading whatever is already there.
    ///
    /// A missing file is a validator that has never signed. A file that cannot be
    /// *parsed* is not: it is a validator whose history is unknown, and this
    /// refuses to open rather than guessing that it signed nothing — guessing
    /// that is exactly the assumption that produces a double-sign.
    ///
    /// # Errors
    /// Returns a message if the file exists and cannot be read or understood.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let last = match std::fs::read_to_string(&path) {
            Ok(text) => Some(parse(&text).map_err(|why| {
                format!(
                    "{} is not a signing record ({why}); refusing to start rather than \
                     assume this validator has signed nothing",
                    path.display()
                )
            })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        Ok(Self {
            path,
            last: Mutex::new(last.flatten()),
        })
    }

    /// Write `state` and return only once it is on stable storage.
    fn persist(&self, state: (Height, Round, Step)) -> Result<(), String> {
        let temp = self.path.with_extension("next");
        let text = format!("{} {} {}\n", state.0.0, state.1.0, step_code(state.2));

        let mut file = std::fs::File::create(&temp)
            .map_err(|e| format!("cannot create {}: {e}", temp.display()))?;
        file.write_all(text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        // Before the rename, so the rename cannot publish a file whose contents
        // are still in a buffer somewhere.
        file.sync_all()
            .map_err(|e| format!("cannot flush {}: {e}", temp.display()))?;
        drop(file);

        std::fs::rename(&temp, &self.path)
            .map_err(|e| format!("cannot replace {}: {e}", self.path.display()))?;
        // Best effort: on most filesystems the rename is durable once the
        // directory entry is flushed. A failure here is not fatal — the data is
        // already flushed and the rename is atomic — so it is not worth refusing
        // to sign over.
        if let Some(dir) = self.path.parent()
            && let Ok(handle) = std::fs::File::open(dir)
        {
            drop(handle.sync_all());
        }
        Ok(())
    }
}

impl SignRecord for FileSignRecord {
    fn claim(&self, height: Height, round: Round, step: Step) -> Result<(), SignRefusal> {
        let mut held = self
            .last
            .lock()
            .map_err(|_| SignRefusal::NotDurable("signing record lock is poisoned".to_owned()))?;
        check_after(*held, (height, round, step))?;
        // Durable *before* the caller is told it may sign.
        self.persist((height, round, step))
            .map_err(SignRefusal::NotDurable)?;
        *held = Some((height, round, step));
        Ok(())
    }

    fn last(&self) -> Option<(Height, Round, Step)> {
        self.last.lock().ok().and_then(|held| *held)
    }
}

const fn step_code(step: Step) -> u8 {
    match step {
        Step::Propose => 0,
        Step::Prevote => 1,
        Step::Precommit => 2,
    }
}

const fn step_of(code: u8) -> Option<Step> {
    match code {
        0 => Some(Step::Propose),
        1 => Some(Step::Prevote),
        2 => Some(Step::Precommit),
        _ => None,
    }
}

/// `height round step`, or empty for "has never signed".
fn parse(text: &str) -> Result<Option<(Height, Round, Step)>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let mut parts = text.split_whitespace();
    let mut next = |what: &str| -> Result<u64, String> {
        parts
            .next()
            .ok_or_else(|| format!("missing {what}"))?
            .parse::<u64>()
            .map_err(|_| format!("{what} is not a number"))
    };
    let height = next("height")?;
    let round = u32::try_from(next("round")?).map_err(|_| "round is out of range".to_owned())?;
    let code = u8::try_from(next("step")?).map_err(|_| "step is out of range".to_owned())?;
    let step = step_of(code).ok_or_else(|| format!("step {code} is not a step"))?;
    if parts.next().is_some() {
        return Err("trailing junk".to_owned());
    }
    Ok(Some((Height(height), Round(round), step)))
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

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            path.push(format!("afrolink-sign-{label}-{unique}"));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("sign_state")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn what_was_signed_survives_a_restart() {
        // The whole reason this file exists. Everything else is correct in memory
        // already; only this survives the process going away.
        let dir = TempDir::new("restart");
        {
            let record = FileSignRecord::open(dir.file()).unwrap();
            record.claim(Height(12), Round(1), Step::Precommit).unwrap();
        }
        let reopened = FileSignRecord::open(dir.file()).unwrap();
        assert_eq!(
            reopened.last(),
            Some((Height(12), Round(1), Step::Precommit))
        );
        assert!(
            reopened
                .claim(Height(12), Round(1), Step::Precommit)
                .is_err(),
            "a restarted node must not sign what it already signed"
        );
        assert!(
            reopened.claim(Height(12), Round(0), Step::Prevote).is_err(),
            "nor anything before it"
        );
        assert!(reopened.claim(Height(13), Round(0), Step::Propose).is_ok());
    }

    #[test]
    fn a_node_that_has_never_signed_starts_from_nothing() {
        let dir = TempDir::new("fresh");
        let record = FileSignRecord::open(dir.file()).unwrap();
        assert_eq!(record.last(), None);
        assert!(record.claim(Height(1), Round(0), Step::Propose).is_ok());
    }

    #[test]
    fn an_unreadable_record_stops_the_node_rather_than_being_ignored() {
        // The dangerous reading is "no usable record, so assume nothing was
        // signed" — which is precisely the assumption that produces a
        // double-sign. A validator whose history cannot be read has an unknown
        // history, and the safe thing to do with an unknown history is stop.
        let dir = TempDir::new("corrupt");
        std::fs::write(dir.file(), "not a signing record").unwrap();
        let refused = FileSignRecord::open(dir.file()).unwrap_err();
        assert!(refused.contains("refusing to start"), "{refused}");
    }

    #[test]
    fn the_record_round_trips_through_its_own_format() {
        for state in [
            (Height(0), Round(0), Step::Propose),
            (Height(1), Round(7), Step::Prevote),
            (Height(u64::MAX), Round(u32::MAX), Step::Precommit),
        ] {
            let text = format!("{} {} {}\n", state.0.0, state.1.0, step_code(state.2));
            assert_eq!(parse(&text).unwrap(), Some(state));
        }
        assert_eq!(parse("   \n").unwrap(), None);
        assert!(parse("1 2").is_err(), "a truncated record is not a record");
        assert!(parse("1 2 9").is_err(), "9 is not a step");
        assert!(parse("1 2 0 extra").is_err());
    }

    #[test]
    fn a_temp_file_is_never_left_where_the_record_should_be() {
        let dir = TempDir::new("atomic");
        let record = FileSignRecord::open(dir.file()).unwrap();
        record.claim(Height(3), Round(0), Step::Prevote).unwrap();
        let text = std::fs::read_to_string(dir.file()).unwrap();
        assert_eq!(
            parse(&text).unwrap(),
            Some((Height(3), Round(0), Step::Prevote))
        );
    }
}
