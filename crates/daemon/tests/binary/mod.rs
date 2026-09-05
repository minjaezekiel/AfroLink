//! Running `afrolinkd` the way an operator runs it.
//!
//! Shared by every test that puts the **entry point** under test rather than
//! the library behind it — the generalisation of the eight defects in this
//! workspace that were correct, tested, and reachable from no caller
//! ([10 §16](../../../../docs/10-network-hardening.md)).
//!
//! It lives here, once, for the reason §16.1 gives about the daemon loop: two
//! copies of a thing are two things, and they drift. A second test file that
//! spawned the binary its own way would eventually spawn a *different* binary
//! — different ports, different config, different idea of when the node is up
//! — and the difference would present as a defect in the node.

#![cfg(unix)]
#![allow(
    dead_code,
    reason = "a shared helper: each test binary that includes it uses a different part of it"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A directory that removes itself, so a failing test leaves no databases behind.
pub struct TempDir(pub PathBuf);

impl TempDir {
    #[must_use]
    pub fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("afrolink-{label}-{unique}"));
        std::fs::create_dir_all(&path).expect("a temp directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// The binary as an operator would run it, not a library call that resembles it.
#[must_use]
pub fn afrolinkd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_afrolinkd"))
}

/// A node with keys, a genesis and a config, on ports nothing else is using.
pub fn prepared(dir: &Path, chain: &str, label: &str, p2p: u16, rpc: u16) {
    let status = afrolinkd()
        .args(["init", "--dir"])
        .arg(dir)
        .args(["--chain-id", chain, "--moniker", label])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("afrolinkd init runs");
    assert!(status.success(), "init failed");

    let path = dir.join("config");
    let text = std::fs::read_to_string(&path).expect("the config init just wrote");
    let rewritten: String = text
        .lines()
        .map(|line| {
            if line.starts_with("p2p_listen") {
                format!("p2p_listen = 127.0.0.1:{p2p}")
            } else if line.starts_with("rpc_listen") {
                format!("rpc_listen = 127.0.0.1:{rpc}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, rewritten).expect("the config is writable");
}

/// Start the node, with its log going to a file we can read back.
pub fn start(dir: &Path) -> (Child, PathBuf) {
    let log = dir.join("node.log");
    let handle = std::fs::File::create(&log).expect("a log file");
    let child = afrolinkd()
        .args(["start", "--dir"])
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(handle))
        .spawn()
        .expect("afrolinkd start runs");
    (child, log)
}

#[must_use]
pub fn log_of(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Wait for something to appear in the log, so the test never races the node.
pub fn wait_for_log(path: &Path, needle: &str, patience: Duration) -> bool {
    let deadline = Instant::now().checked_add(patience);
    while deadline.is_some_and(|at| Instant::now() < at) {
        if log_of(path).contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Send a signal by name, e.g. `TERM`.
///
/// # Why `kill(1)` and not a crate
///
/// The workspace forbids `unsafe`, and every Rust way to send a signal to
/// another process goes through `libc`. Shelling out costs a process and buys
/// the rule staying absolute.
pub fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(child.id().to_string())
        .status()
        .expect("kill runs");
    assert!(status.success(), "could not send SIG{name}");
}

/// Wait for the process to exit, returning whether it did in time.
pub fn wait_for_exit(child: &mut Child, patience: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now().checked_add(patience);
    while deadline.is_some_and(|at| Instant::now() < at) {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    None
}

/// A child that is killed when the test ends, however the test ends.
///
/// A panicking assertion must not leave a node holding a port: the next test to
/// claim it would fail for a reason that has nothing to do with what it tests.
pub struct Running(pub Child);

impl Drop for Running {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}
