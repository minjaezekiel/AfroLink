//! The loop that turns a clock into consensus, in one place.
//!
//! # Why this is a module rather than the body of `run::drive`
//!
//! It used to be the body of `run::drive`, and the cluster harness had a
//! hand-written copy of it — the timers, the round-begun bookkeeping,
//! `begin_round`, `schedule` and `wants_new_round`, all written twice. Two
//! copies of a loop are two loops, and they drifted: the harness never re-dialled
//! where the daemon does every five seconds, so a peer lost under load was gone
//! for the rest of the run, and the symptom surfaced far away as an intermittent
//! sync stall that looked like a defect in block sync.
//!
//! That is the inverse of the hazard `sim.rs` was written to avoid. A simulator
//! *more* capable than production hides bugs; a harness *less* capable than
//! production invents them. Both are the same mistake — the thing under test is
//! not the thing that ships — and the fix for both is to delete the divergence
//! rather than to keep the two in step by hand.
//!
//! FoundationDB's answer, and TigerBeetle's after it, is to make every
//! nondeterministic input **pluggable**, so the simulator drives the real code
//! rather than a model of it. This workspace already does that twice: `Node` has
//! no clock and takes time as `Event::Timeout`, and `Manager` has no clock and
//! takes it as `on_tick(elapsed)`. What was missing was the layer above them —
//! the loop that reads the actual clock. So it gets the same treatment: the clock
//! arrives as [`Driver::step`]'s `now`, and the daemon and the harness run the
//! same code with different clocks and different timings.
//!
//! # A halt is in the return type
//!
//! `Persist` reports a failed write by setting a flag, and `run::drive` treats it
//! as fatal: a node that cannot write its own chain stops rather than voting on a
//! history only it can see. The harness held the same flag and **dropped it**, so
//! a failed write there was silent — the node carried on with a store one block
//! behind its consensus state.
//!
//! A convention that both callers must remember to check is a convention one of
//! them will forget. So the flag is owned here and the check is in the signature:
//! [`Driver::step`] returns `Result<_, Halted>`, and `Result` is `#[must_use]`.
//! A caller cannot drive a node without confronting the one condition that means
//! it must stop.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afrolink_consensus::Step;
use afrolink_node::{Action, SharedNode};
use afrolink_p2p::transport::Transport;
use afrolink_primitives::{Height, Timestamp};

use crate::config::Config;

/// How many rounds may be begun back to back before the loop takes a breath.
///
/// A round that ends immediately asks for the next one, and a proposer nobody can
/// reach makes that happen every time. Bounded so the loop cannot spin: eight
/// rounds is far more than a healthy chain needs and far less than forever.
const MAX_ROUND_RESTARTS: usize = 8;

/// Every period the loop needs, in one place.
///
/// The harness runs the same code an order of magnitude faster than the daemon.
/// Holding the periods as data rather than as constants is what lets it, and is
/// what stops "make the test quicker" turning into "write the loop again".
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    /// How often the loop wakes. Short, so a consensus timeout fires close to
    /// when it was due rather than up to a whole peer tick late.
    pub poll: Duration,
    /// How often peer housekeeping runs.
    ///
    /// This no longer affects what any rate limit *means* — those are per second,
    /// measured against elapsed time, precisely because tying them to this number
    /// once turned a limit of 512 messages into ten thousand a second when the
    /// poll period changed for unrelated reasons. What it governs is how promptly
    /// a node announces its height and asks for addresses.
    pub peer_tick: Duration,
    /// How often the node dials to fill its outbound slots.
    ///
    /// Not every tick: a dial is a TCP connection and a handshake, and retrying a
    /// dead seed twenty times a second is a way to look like an attacker to it.
    pub dial: Duration,
    /// Shortest time between one commit and the next proposal.
    pub block_interval: Duration,
    /// How long to wait for a proposal before prevoting nil.
    pub timeout_propose: Duration,
    /// How long to wait for prevotes before precommitting nil.
    pub timeout_prevote: Duration,
    /// How long to wait for precommits before moving to the next round.
    pub timeout_precommit: Duration,
}

impl Timings {
    /// What an operator configured.
    #[must_use]
    pub const fn from_config(config: &Config) -> Self {
        Self {
            poll: Duration::from_millis(20),
            peer_tick: Duration::from_millis(500),
            dial: Duration::from_secs(5),
            block_interval: Duration::from_millis(config.block_interval_ms),
            timeout_propose: Duration::from_millis(config.timeout_propose_ms),
            timeout_prevote: Duration::from_millis(config.timeout_prevote_ms),
            timeout_precommit: Duration::from_millis(config.timeout_precommit_ms),
        }
    }
}

/// A node that cannot write its own chain.
///
/// Returned rather than logged, so that no caller can drive a node past it.
///
/// Carrying on would mean serving queries about blocks that will not survive a
/// restart, and voting on a history only this process can see.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct Halted(pub String);

/// A timer the consensus driver asked for.
#[derive(Debug, Clone, Copy)]
struct Deadline {
    step: Step,
    at: Instant,
}

/// What one pass of the loop did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beat {
    /// Nothing worth telling anyone about.
    Idle,
    /// A height became final — decided here or learned from a peer.
    ///
    /// Reported rather than logged from inside, because what a daemon does with
    /// this (write a line) and what a test does with it (nothing) are different,
    /// and a loop that logged would make the harness noisy in proportion to how
    /// well it was working.
    Committed(Height),
}

/// One node's share of the daemon loop.
pub struct Driver {
    timings: Timings,
    halted: Arc<Mutex<Option<String>>>,
    deadline: Option<Deadline>,
    height: Height,
    started: bool,
    next_round_at: Instant,
    dial_at: Instant,
    peer_tick_at: Instant,
}

impl Driver {
    /// A driver for a node that is at `height` now.
    ///
    /// `halted` is the flag `Persist` sets when a write fails. It is required
    /// rather than optional: a driver that could be built without one is a driver
    /// that can run a node whose store is silently broken.
    #[must_use]
    pub fn new(timings: Timings, halted: Arc<Mutex<Option<String>>>, now: Instant) -> Self {
        Self {
            timings,
            halted,
            deadline: None,
            height: Height(0),
            started: false,
            next_round_at: now,
            dial_at: now,
            peer_tick_at: now,
        }
    }

    /// How long to sleep between passes.
    #[must_use]
    pub const fn poll(&self) -> Duration {
        self.timings.poll
    }

    /// Why this node must stop, if it must.
    ///
    /// For callers that are doing something other than stepping — settling a
    /// test cluster, say — and still need to notice. [`Self::step`] checks it
    /// too, and returns it where it cannot be ignored.
    #[must_use]
    pub fn halted(&self) -> Option<String> {
        self.halted.lock().ok().and_then(|held| held.clone())
    }

    /// Run one pass of the loop.
    ///
    /// `dial` is false only while a caller is deliberately holding a node off the
    /// network. A real partition stops a node reconnecting as well as stopping
    /// its traffic, so a partition every peer can dial straight through is not a
    /// partition.
    ///
    /// # Errors
    /// [`Halted`] if a write to this node's store failed. The node must stop.
    pub fn step(
        &mut self,
        now: Instant,
        transport: &Transport,
        shared: &Arc<SharedNode>,
        dial: bool,
    ) -> Result<Beat, Halted> {
        if let Ok(reason) = self.halted.lock()
            && let Some(why) = reason.clone()
        {
            return Err(Halted(why));
        }

        // Peer housekeeping: budgets, address exchange, status, and the block
        // requests that catch this node up.
        if now >= self.peer_tick_at {
            transport.tick();
            self.peer_tick_at = now.checked_add(self.timings.peer_tick).unwrap_or(now);
        }
        if dial && now >= self.dial_at {
            transport.dial_out();
            self.dial_at = now.checked_add(self.timings.dial).unwrap_or(now);
        }

        let mut beat = Beat::Idle;
        let at = current_height(shared);
        if at != self.height || !self.started {
            // A height was decided — here or by catching up — so the round state
            // has been reset and the next round has to be opened.
            let first = !self.started;
            self.height = at;
            self.started = true;
            self.deadline = None;
            self.next_round_at = now.checked_add(self.timings.block_interval).unwrap_or(now);
            if !first {
                beat = Beat::Committed(Height(at.0.saturating_sub(1)));
            }
        }

        if now >= self.next_round_at && self.deadline.is_none() {
            if transport.is_behind() {
                // Catching up rather than proposing. A block built on stale state
                // is one everybody who is not behind votes down, which costs a
                // round and, on a small validator set, stalls the chain while it
                // happens.
                self.next_round_at = now.checked_add(self.timings.block_interval).unwrap_or(now);
            } else {
                // Through the transport, not straight at the node. A round that
                // commits has to reach the store, and the transport is the one
                // place that knows how — a driver holding the node itself would
                // produce blocks that exist only in memory.
                self.deadline = self.begin_round(now, transport);
            }
        }

        if let Some(due) = self.deadline
            && now >= due.at
        {
            self.deadline = None;
            let actions = transport.timeout(due.step);
            self.deadline = self.schedule(now, &actions);
            // A step that ended the round asks for the next one to be *begun*.
            // Waiting instead is how a chain advances rounds forever without
            // committing, once a single proposer is unreachable.
            if wants_new_round(&actions) {
                self.deadline = self.begin_round(now, transport);
            }
        }

        Ok(beat)
    }

    /// Open a round, and keep opening them while each one ends at once.
    fn begin_round(&self, now: Instant, transport: &Transport) -> Option<Deadline> {
        let mut deadline = None;
        for _ in 0..MAX_ROUND_RESTARTS {
            let actions = transport.start_round(wall_clock());
            deadline = self.schedule(now, &actions);
            if !wants_new_round(&actions) {
                return deadline;
            }
        }
        deadline
    }

    /// Turn a `ScheduleTimeout` action into a real deadline.
    ///
    /// Only the first is kept: the state machine asks for one timer at a time,
    /// and a second would fire a step the round has already left.
    ///
    /// The wait **grows with the round**, as Tendermint's does. A network failing
    /// to agree because it is slow gets more time on each attempt; one that keeps
    /// the same deadline every round never recovers from being merely slow.
    fn schedule(&self, now: Instant, actions: &[Action]) -> Option<Deadline> {
        actions.iter().find_map(|action| match action {
            Action::ScheduleTimeout(step, round) => {
                let base = match step {
                    Step::Propose => self.timings.timeout_propose,
                    Step::Prevote => self.timings.timeout_prevote,
                    Step::Precommit => self.timings.timeout_precommit,
                };
                let wait = base.saturating_mul(round.0.saturating_add(1));
                Some(Deadline {
                    step: *step,
                    at: now.checked_add(wait).unwrap_or(now),
                })
            }
            _ => None,
        })
    }
}

/// Whether a batch of actions asked for the next round to be begun.
fn wants_new_round(actions: &[Action]) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, Action::StartRound(_)))
}

/// The height this node is working on.
fn current_height(shared: &Arc<SharedNode>) -> Height {
    shared.lock().map_or(Height(0), |node| node.height())
}

/// Wall-clock time, as the chain measures it.
///
/// The one place in the workspace that reads it. Everything below takes time as
/// data, which is what makes the deterministic simulator possible at all.
fn wall_clock() -> Timestamp {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    Timestamp::from_millis(millis)
}

/// How long the stop sequence may take before the process exits regardless.
///
/// Under `docker stop`'s ten seconds, which is the tightest of the three
/// contracts below, with room left for the log line to be written.
pub const STOP_BUDGET: Duration = Duration::from_secs(8);

/// A watchdog that bounds how long stopping may take.
///
/// # The contract every service manager holds us to
///
/// `systemd` waits `TimeoutStopSec` (90 seconds by default), `docker stop` waits
/// **10 seconds**, and Kubernetes waits `terminationGracePeriodSeconds` (30 by
/// default). Each then sends `SIGKILL`. A shutdown slower than the shortest of
/// those is not a graceful shutdown — it is an ungraceful one with extra steps,
/// and the work it was trying to finish is lost anyway.
///
/// So the stop sequence runs while one of these is alive. If it has not been
/// dropped within [`STOP_BUDGET`], the process exits rather than waiting to be
/// killed. The difference is worth having because an exit we chose can say *why*
/// in the log, and a `SIGKILL` cannot.
///
/// # What is and is not tested
///
/// The firing path ends in `process::exit`, so it cannot be exercised in-process
/// without ending the test run; it is not directly covered. The *other*
/// direction is, and it is the dangerous one: a watchdog that fired on a healthy
/// shutdown would kill good nodes, and
/// `a_watchdog_that_finishes_in_time_never_fires` holds that shut.
pub struct StopWatchdog {
    done: Arc<std::sync::atomic::AtomicBool>,
}

impl StopWatchdog {
    /// Begin bounding a shutdown by [`STOP_BUDGET`].
    #[must_use]
    pub fn start() -> Self {
        Self::with_budget(STOP_BUDGET)
    }

    /// Begin bounding a shutdown by `budget`.
    #[must_use]
    pub fn with_budget(budget: Duration) -> Self {
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watching = Arc::clone(&done);
        let started = Instant::now();
        std::thread::spawn(move || {
            while !watching.load(Ordering::SeqCst) {
                if started.elapsed() >= budget {
                    crate::run::log(&format!(
                        "shutdown did not finish within {}s; exiting rather than waiting to be killed",
                        budget.as_secs()
                    ));
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Self { done }
    }
}

impl Drop for StopWatchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
    }
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

    #[test]
    fn a_watchdog_that_finishes_in_time_never_fires() {
        // The direction that matters. A watchdog firing on a *healthy* shutdown
        // would kill good nodes for no reason, and it would do it by calling
        // `process::exit` — so if this were wrong, this test would not fail, it
        // would end the whole run. That it completes at all is the assertion.
        {
            let _watchdog = StopWatchdog::with_budget(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    #[test]
    fn several_watchdogs_do_not_interfere_with_each_other() {
        // Each owns its own flag: one shutdown finishing must not disarm another,
        // and one being dropped must not leave a thread watching a flag nobody
        // will ever set.
        for _ in 0..8 {
            let watchdog = StopWatchdog::with_budget(Duration::from_millis(80));
            std::thread::sleep(Duration::from_millis(10));
            drop(watchdog);
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    #[test]
    fn timings_come_from_the_config_rather_than_from_constants() {
        // The harness runs these an order of magnitude faster than the daemon.
        // If they were constants again, it would have to write its own loop
        // again, which is the whole defect this module exists to remove.
        let config = Config {
            block_interval_ms: 4_321,
            timeout_propose_ms: 1_234,
            ..Config::default()
        };
        let timings = Timings::from_config(&config);
        assert_eq!(timings.block_interval, Duration::from_millis(4_321));
        assert_eq!(timings.timeout_propose, Duration::from_millis(1_234));
    }
}
