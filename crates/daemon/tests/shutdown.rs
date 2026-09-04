//! The real binary, stopped the way real things stop it.
//!
//! # The defect this exists for
//!
//! `afrolinkd` installs a signal handler so that it can close its peers, flush
//! its store and write its anchors. It handled **SIGINT only** — what a terminal
//! sends on Ctrl-C, and what nothing in production sends. `systemd`, `docker
//! stop` and Kubernetes all send **SIGTERM**, then `SIGKILL` after a grace
//! period. So the clean-stop path was written, was correct, was covered by the
//! cluster harness, and *was never taken in the one situation it existed for*: a
//! node stopped by its own service manager simply died, leaving its anchors
//! unwritten and its peers holding connections nobody would close.
//!
//! That is the seventh time in this workspace that correct, tested code turned
//! out to be reachable from no caller. Every previous one was found by running
//! the artefact rather than by adding a test of the kind that already existed.
//! This file is the generalisation: **the entry point is under test, not only
//! the library behind it.** It is the cheap version of what CometBFT's `test/e2e`
//! does with Docker Compose and a testnet manifest — real binaries, real signals,
//! assertions on what an operator would see.
//!
//! # What it asserts, and why each one is here
//!
//! * **SIGTERM stops the node cleanly.** The regression itself.
//! * **SIGINT does too.** So that fixing one does not silently break the other.
//! * **The clean-stop *work* actually happened** — the log says so and the exit
//!   status is success. Asserting only that the process died would pass against
//!   a node that was killed, which is the bug.
//! * **It stops inside a bounded time.** `docker stop` waits ten seconds and
//!   Kubernetes waits thirty; a shutdown slower than that is an ungraceful one
//!   with extra steps.
//! * **A second signal is obeyed at once.** An operator who asks twice wants out
//!   now, and a daemon that refuses is a daemon that teaches people `kill -9`.
//!
//! # Why signals are sent by `kill(1)`
//!
//! The workspace forbids `unsafe`, and every Rust way to send a signal to
//! another process goes through `libc`. Shelling out to `kill` costs a process
//! and buys the rule staying absolute.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long to wait for the node to produce blocks before signalling it.
const RUNNING: Duration = Duration::from_secs(20);
/// How long a clean stop may take. Comfortably inside `docker stop`'s ten
/// seconds, which is the tightest contract any of the three service managers
/// holds us to.
const STOP_WITHIN: Duration = Duration::from_secs(8);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("afrolink-shutdown-{label}-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// The binary as an operator would run it, not a library call that resembles it.
fn afrolinkd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_afrolinkd"))
}

/// A node with keys, a genesis and a config, on ports nothing else is using.
fn prepared(dir: &Path, label: &str, p2p: u16, rpc: u16) {
    let status = afrolinkd()
        .args(["init", "--dir"])
        .arg(dir)
        .args(["--chain-id", "afrolink-shutdown", "--moniker", label])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("afrolinkd init runs");
    assert!(status.success(), "init failed");

    let path = dir.join("config");
    let text = std::fs::read_to_string(&path).unwrap();
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
    std::fs::write(&path, rewritten).unwrap();
}

/// Start the node, with its log going to a file we can read back.
fn start(dir: &Path) -> (Child, PathBuf) {
    let log = dir.join("node.log");
    let handle = std::fs::File::create(&log).unwrap();
    let child = afrolinkd()
        .args(["start", "--dir"])
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(handle))
        .spawn()
        .expect("afrolinkd start runs");
    (child, log)
}

fn log_of(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Wait for something to appear in the log, so the test never races the node.
fn wait_for_log(path: &Path, needle: &str, patience: Duration) -> bool {
    let deadline = Instant::now().checked_add(patience);
    while deadline.is_some_and(|at| Instant::now() < at) {
        if log_of(path).contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(child.id().to_string())
        .status()
        .expect("kill runs");
    assert!(status.success(), "could not send SIG{name}");
}

/// Wait for the process to exit, returning whether it did in time.
fn wait_for_exit(child: &mut Child, patience: Duration) -> Option<std::process::ExitStatus> {
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

/// Start a node, let it commit, signal it, and say what happened.
fn stopped_by(label: &str, name: &str, p2p: u16, rpc: u16) -> (std::process::ExitStatus, String) {
    let dir = TempDir::new(label);
    prepared(&dir.0, label, p2p, rpc);
    let (mut child, log) = start(&dir.0);

    // Signal a node that is *doing something*. A node killed before it began has
    // nothing to shut down cleanly, so it would pass this test while broken.
    let running = wait_for_log(&log, "height 2", RUNNING);
    if !running {
        drop(child.kill());
        panic!("the node never committed a block:\n{}", log_of(&log));
    }

    signal(&child, name);
    let Some(status) = wait_for_exit(&mut child, STOP_WITHIN) else {
        drop(child.kill());
        panic!(
            "SIG{name} did not stop the node within {}s:\n{}",
            STOP_WITHIN.as_secs(),
            log_of(&log)
        );
    };
    (status, log_of(&log))
}

#[test]
fn sigterm_stops_the_node_cleanly() {
    // **The regression.** SIGTERM is what systemd, Docker and Kubernetes send.
    // Before this, the handler took SIGINT only and the process died on SIGTERM
    // with none of the work below done.
    let (status, log) = stopped_by("sigterm", "TERM", 29656, 29657);
    assert!(
        status.success(),
        "a node stopped by its service manager must exit successfully, got {status:?}\n{log}"
    );
    assert!(
        log.contains("received interrupt"),
        "the signal handler must run, not be bypassed:\n{log}"
    );
    assert!(
        log.contains("stopping"),
        "the clean-stop path must be taken — a process that merely dies also 'stops':\n{log}"
    );
}

#[test]
fn sigint_stops_the_node_cleanly_too() {
    // Kept so that widening the handler to SIGTERM cannot silently narrow it away
    // from the terminal case an operator uses every day.
    let (status, log) = stopped_by("sigint", "INT", 29666, 29667);
    assert!(status.success(), "got {status:?}\n{log}");
    assert!(log.contains("stopping"), "{log}");
}

#[test]
fn a_second_signal_stops_the_node_at_once() {
    // An operator who asks twice wants out now. A daemon that refuses is a daemon
    // that teaches people to reach for `kill -9`, which is how the clean-stop
    // path stops being taken at all.
    let dir = TempDir::new("twice");
    prepared(&dir.0, "twice", 29676, 29677);
    let (mut child, log) = start(&dir.0);
    assert!(
        wait_for_log(&log, "height 2", RUNNING),
        "the node never committed a block:\n{}",
        log_of(&log)
    );

    signal(&child, "TERM");
    signal(&child, "TERM");
    let status = wait_for_exit(&mut child, STOP_WITHIN);
    if status.is_none() {
        drop(child.kill());
        panic!("asking twice did not stop the node:\n{}", log_of(&log));
    }
}

#[test]
fn a_stopped_node_leaves_a_store_it_can_resume_from() {
    // What the clean stop is *for*. Asserting the log alone would pass against a
    // shutdown that printed the right words and flushed nothing, so this restarts
    // the node and makes it say where it came back from.
    let dir = TempDir::new("resume");
    prepared(&dir.0, "resume", 29686, 29687);
    let (mut child, log) = start(&dir.0);
    assert!(
        wait_for_log(&log, "height 3", RUNNING),
        "the node never committed:\n{}",
        log_of(&log)
    );
    signal(&child, "TERM");
    assert!(
        wait_for_exit(&mut child, STOP_WITHIN).is_some_and(|s| s.success()),
        "{}",
        log_of(&log)
    );

    let (mut again, second) = start(&dir.0);
    let resumed = wait_for_log(&second, "resuming at height", RUNNING);
    signal(&again, "TERM");
    let _ = wait_for_exit(&mut again, STOP_WITHIN);
    let text = log_of(&second);
    assert!(resumed, "the node did not report where it resumed:\n{text}");
    assert!(
        !text.contains("resuming at height 0"),
        "a cleanly stopped node must come back to the chain it had, not to genesis:\n{text}"
    );
    assert!(
        text.contains("loaded from the state tree"),
        "it should not have had to replay from genesis:\n{text}"
    );
}
