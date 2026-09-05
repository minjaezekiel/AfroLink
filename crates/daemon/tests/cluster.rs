//! Do real nodes, on real sockets, with real databases, agree?
//!
//! The harness these run on lives in [`harness`], shared with `load.rs` rather
//! than copied into it — a second hand-written copy of a node loop is what
//! `crates/daemon/src/driver.rs` exists to prevent, and the same reasoning
//! applies to the thing that assembles the nodes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

mod harness;

// **One binary, so one lock.** These suites each start four real nodes on real
// sockets, and `harness::exclusive()` is a `static` — which serialises tests
// within a binary and does nothing at all between binaries. Left as separate
// integration targets, `cargo test` ran two four-node clusters at once and both
// missed their deadlines; the failures looked like defects in block sync and
// were contention between the tests themselves.
#[path = "suites/load.rs"]
mod load;

use afrolink_primitives::Height;
use harness::{CEILING, Cluster, ClusterNode, TEARDOWN, TempDir, chain, exclusive, validators};

// -- the tests ---------------------------------------------------------------

#[test]
fn four_real_nodes_on_four_sockets_commit_the_same_chain() {
    let _serial = exclusive();
    // The question a testnet asks and neither existing suite could. Four
    // validators, four databases, four loopback sockets, one genesis, real
    // handshakes and real gossip between them.
    let mut cluster = Cluster::start(4, "agreement");

    assert!(
        cluster.wait_until(CEILING, |c| c.lowest_tip() >= Height(5)),
        "the cluster did not reach height 5; tips are {:?}",
        cluster.nodes.iter().map(|n| n.tip().0).collect::<Vec<_>>()
    );

    cluster.quiesce();
    cluster.assert_agreement();
    cluster.assert_converged();
}

#[test]
fn a_payment_submitted_to_one_node_is_committed_by_all_of_them() {
    let _serial = exclusive();
    // End to end over the real network: a client hands a transaction to one node,
    // it is gossiped, included in a block, and every node's *database* can prove
    // where it landed.
    let mut cluster = Cluster::start(4, "payment");
    let payment = cluster.payment(0);
    let id = payment.id();
    cluster.nodes[0]
        .shared
        .lock()
        .unwrap()
        .submit(payment)
        .expect("a valid payment");

    assert!(
        cluster.wait_until(CEILING, |c| c.nodes.iter().all(|n| n
            .store
            .locate(&id)
            .unwrap()
            .is_some())),
        "the payment never reached every node's store"
    );
    cluster.quiesce();
    cluster.assert_agreement();

    // And every node agrees on *where* it landed, which is what a receipt proves.
    let first = cluster.nodes[0].store.locate(&id).unwrap().unwrap();
    for node in &cluster.nodes {
        assert_eq!(
            node.store.locate(&id).unwrap().unwrap(),
            first,
            "node {} put the payment in a different block",
            node.seed
        );
    }
}

#[test]
fn a_partitioned_node_falls_behind_and_catches_up_when_healed() {
    let _serial = exclusive();
    // The property block sync exists for, asserted across the whole stack rather
    // than at the manager. One node is cut off, the others carry on without it,
    // and when it is reconnected it must reach the same state root — not merely
    // the same height.
    let mut cluster = Cluster::start(4, "partition");
    assert!(
        cluster.wait_until(CEILING, |c| c.lowest_tip() >= Height(3)),
        "the cluster never got going"
    );

    // Cut node 3 off. The remaining three are still more than two thirds of four,
    // so the chain must keep committing without it.
    let isolated = 3;
    cluster.partition(isolated);
    let left_at = cluster.nodes[isolated].tip();

    let others_advanced = cluster.wait_until(CEILING, |c| {
        c.nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != isolated)
            .all(|(_, n)| n.tip().0 >= left_at.0 + 4)
    });
    assert!(
        others_advanced,
        "a three-of-four majority stalled when one node was partitioned away"
    );
    assert!(
        cluster.nodes[isolated].tip().0 <= left_at.0 + 1,
        "the partitioned node kept committing without a quorum it could reach"
    );

    // Heal. It has to catch up through block sync, verifying every certificate.
    cluster.heal();
    assert!(
        cluster.wait_until(CEILING, |c| {
            let tip = c.nodes[0].tip();
            c.nodes[isolated].tip() >= tip && tip.0 > 0
        }),
        "the healed node never caught up: it is at {:?}, the others are at {:?}",
        cluster.nodes[isolated].tip(),
        cluster.nodes[0].tip()
    );

    cluster.quiesce();
    cluster.assert_agreement();
    cluster.assert_converged();
}

#[test]
fn a_node_that_joins_late_reaches_the_tip_from_genesis() {
    let _serial = exclusive();
    // A new validator joining a chain that is already running: it holds only
    // genesis, and must arrive at the same state as everybody else by asking for
    // blocks and verifying each one.
    let mut cluster = Cluster::start(4, "latecomer");
    assert!(
        cluster.wait_until(CEILING, |c| c.lowest_tip() >= Height(5)),
        "the cluster never got going"
    );

    // A fifth node on the same genesis. It is not in the validator set — it is a
    // full node, which is the common case and the one nobody tests.
    let late = ClusterNode::start(9, 4, TempDir::new("latecomer-9"));
    let target = cluster.nodes[0].tip();
    for node in &cluster.nodes {
        drop(late.transport.dial(node.addr()));
    }
    cluster.nodes.push(late);

    assert!(
        cluster.wait_until(CEILING, |c| {
            c.nodes.last().is_some_and(|n| n.tip() >= target)
        }),
        "the late node never caught up to {:?}",
        target
    );

    cluster.quiesce();
    let late = cluster.nodes.last().unwrap();
    let reference = &cluster.nodes[0];
    assert_eq!(
        late.store.block(target).unwrap().map(|b| b.header.id()),
        reference
            .store
            .block(target)
            .unwrap()
            .map(|b| b.header.id()),
        "the late node holds a different block at the height it caught up to"
    );
    cluster.assert_agreement();
}

#[test]
fn a_restarted_node_resumes_from_its_database_and_rejoins() {
    let _serial = exclusive();
    // What a real operator does: stop a node, start it again, and expect it back.
    // The store is reopened rather than rebuilt, so this also asserts that what
    // was persisted is enough to continue from — the property that was silently
    // false when eighteen blocks left the database empty.
    let mut cluster = Cluster::start(4, "restart");
    assert!(
        cluster.wait_until(CEILING, |c| c.lowest_tip() >= Height(4)),
        "the cluster never got going"
    );

    let restarted = 2;
    let seed = cluster.nodes[restarted].seed;
    let before = cluster.nodes[restarted].tip();
    assert!(before.0 >= 1, "there must be something to resume from");

    // Stop it: drop the node, which stops its transport and closes its database.
    let dir = {
        let node = cluster.nodes.remove(restarted);
        node.transport.handle().stop();
        node.dir
    };
    // Let its threads go before asking the rest to carry on without it, so what
    // is measured is the protocol rather than the machine.
    std::thread::sleep(TEARDOWN);

    // The remaining three are still a quorum, so the chain must not stall.
    assert!(
        cluster.wait_until(CEILING, |c| c.lowest_tip().0 > before.0 + 2),
        "a three-of-four majority stalled: it was at {:?} when the fourth went \
         down and is at {:?} now",
        before,
        cluster.lowest_tip()
    );

    // Start it again on the same directory.
    let back = ClusterNode::start(seed, 4, dir);
    assert!(
        back.tip() >= before,
        "a restarted node came back at {:?} having committed {:?} — \
         its database did not hold what it had decided",
        back.tip(),
        before
    );
    for node in &cluster.nodes {
        drop(back.transport.dial(node.addr()));
    }
    cluster.nodes.push(back);

    let target = cluster.nodes[0].tip();
    assert!(
        cluster.wait_until(CEILING, |c| c
            .nodes
            .last()
            .is_some_and(|n| n.tip() >= target)),
        "the restarted node never rejoined"
    );
    cluster.quiesce();
    cluster.assert_agreement();
}

#[test]
fn every_node_serves_the_same_answer_from_its_own_database() {
    let _serial = exclusive();
    // A wallet may talk to any node and must get the same chain. This is the
    // property that makes the query layer worth having, and it is checked against
    // the durable store rather than a node's memory, because that is what a
    // served query reads.
    let mut cluster = Cluster::start(4, "queries");
    assert!(
        cluster.wait_until(CEILING, |c| c.lowest_tip() >= Height(4)),
        "the cluster never got going"
    );

    cluster.quiesce();
    let common = cluster.lowest_stored_tip();
    for h in 1..=common.0 {
        let height = Height(h);
        let mut roots = Vec::new();
        for node in &cluster.nodes {
            let block = node.store.block(height).unwrap().expect("a stored block");
            let commit = node.store.commit(height).unwrap().expect("a certificate");
            // Every node's copy of a height must carry a certificate that
            // finalises the block it is stored beside.
            assert_eq!(
                commit.block_id,
                block.header.id(),
                "node {} stored a certificate for a different block at {h}",
                node.seed
            );
            assert_eq!(commit.verify(&chain(), &validators(4)), Ok(()));
            roots.push(block.header.app_hash);
        }
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "nodes disagree about the state root at height {h}"
        );
    }
}
