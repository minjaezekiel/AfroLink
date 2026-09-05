//! What one commit costs as the state grows.
//!
//! A measurement, not an assertion — but the numbers it prints are the reason
//! `SparseMerkleTree` keeps its structure instead of recomputing it. Run with
//! `cargo test --release -p afrolink-state --test scale -- --ignored --nocapture`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a benchmark, not consensus code"
)]

use afrolink_state::nodes::{MemoryNodes, commit_tree};
use afrolink_state::store::Namespace;
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use std::time::Instant;

fn key(i: usize) -> StoreKey {
    StoreKey::new(Namespace::Balance, &[format!("acct{i:08}").as_bytes()])
}

fn filled(n: usize) -> MemoryStore {
    let mut s = MemoryStore::new();
    for i in 0..n {
        s.set(&key(i), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
    s
}

fn micros(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1_000_000.0
}

#[test]
#[ignore = "measurement, run explicitly"]
fn what_a_commit_costs_as_state_grows() {
    println!(
        "\n  accounts |  root()  | 1 write+root | clone()  |  prove() | commit: visited/written"
    );
    println!(
        "-----------|----------|--------------|----------|----------|------------------------"
    );
    for n in [1_000usize, 10_000, 100_000, 1_000_000] {
        let mut store = filled(n);

        let t = Instant::now();
        let _ = store.root();
        let root_us = micros(t);

        let t = Instant::now();
        store.set(&key(n + 1), vec![9; 8]);
        let _ = store.root();
        let write_us = micros(t);

        let t = Instant::now();
        let copy = store.clone();
        let clone_us = micros(t);
        drop(copy);

        let t = Instant::now();
        let _ = store.tree().prove(key(n / 2).as_bytes());
        let prove_us = micros(t);

        // The commit the daemon actually runs: a full first write, then one
        // changed key. The second is the number that decides whether a chain
        // can keep 1s blocks as it grows.
        let mut nodes = MemoryNodes::new();
        let _ = commit_tree(store.tree(), &mut nodes);
        store.set(&key(7), vec![42; 8]);
        let (_, again) = commit_tree(store.tree(), &mut nodes);

        println!(
            "{n:>10} | {root_us:>6.1}us | {write_us:>10.1}us | {clone_us:>6.1}us | {prove_us:>6.1}us | {:>7}/{:<7}",
            again.visited, again.written
        );
    }
    println!();
}
