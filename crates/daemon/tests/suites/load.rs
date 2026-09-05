//! What the chain does when a lot of people use it at once.
//!
//! # Why this exists separately from `cluster.rs`
//!
//! `cluster.rs` asks whether four real nodes agree. It does that with **one**
//! funded account sending **one** payment, so the state tree it exercises has a
//! handful of entries in it and every operation on that tree is fast whatever
//! its complexity class. That is the right shape for an agreement test and it is
//! blind to the thing that actually decides whether this network can be used:
//! how the cost of a block grows with the number of people who have accounts.
//!
//! It was blind to a real ceiling. `SparseMerkleTree` recomputed its whole root
//! from every entry on every call, so changing one balance cost the same as
//! rebuilding the entire state — 63ms at a hundred thousand accounts, on a path
//! taken at least twice per block. Nothing in the suite noticed, because nothing
//! in the suite ever had more than a few accounts.
//!
//! So this test does what a customer does: **many distinct accounts, many
//! payments, sustained**, through the same submission path a wallet uses, and
//! then checks that every last unit of money is where it should be.
//!
//! # What it proves
//!
//! * Every payment submitted is committed — none silently dropped.
//! * Every balance is **exactly** right afterwards, sender and recipient, fees
//!   included. A payments chain that loses or invents a unit is worthless, and
//!   agreement between nodes does not prove arithmetic: four nodes can agree
//!   perfectly on a wrong number.
//! * Every node holds the same state root, so the load did not fork them.
//! * A light client can still prove a balance against the header — the proof
//!   path has to survive a busy tree, not only a small one.

use afrolink_primitives::{Amount, Height};

use crate::harness::{self, Cluster, account};

/// Payments in the version that runs on every `cargo test`.
const PAYMENTS: usize = 120;
/// Distinct senders. Each gets its own account, so the state grows with them.
const SENDERS: usize = 40;

#[test]
fn many_accounts_paying_at_once_all_arrive_and_all_balances_are_exact() {
    let _serial = harness::exclusive();
    let mut cluster = Cluster::funded(4, "load", SENDERS);

    // Every sender pays the same recipient, so the expected total is arithmetic
    // rather than bookkeeping: if one payment is lost, the recipient is short by
    // exactly one payment and the test says so.
    let mut submitted = Vec::new();
    for i in 0..PAYMENTS {
        let sender = i % SENDERS;
        let nonce = (i / SENDERS) as u64;
        let tx = cluster.transfer(sender, nonce, Amount::from_afri(1));
        let id = tx.id();
        // Round-robin across nodes, as a wallet population would: submissions do
        // not all land on one node, so this exercises gossip as well as inclusion.
        let target = i % cluster.len();
        cluster.nodes[target]
            .shared
            .lock()
            .unwrap()
            .submit(tx)
            .expect("a valid payment");
        submitted.push(id);
    }

    let landed = cluster.wait_until(harness::CEILING, |c| {
        submitted
            .iter()
            .all(|id| c.nodes[0].store.locate(id).unwrap().is_some())
    });
    cluster.quiesce();
    assert!(
        landed,
        "only {} of {PAYMENTS} payments were committed",
        submitted
            .iter()
            .filter(|id| cluster.nodes[0].store.locate(id).unwrap().is_some())
            .count()
    );

    cluster.assert_agreement();

    // The arithmetic. Each sender paid `sent` AFRI plus a fee per transaction.
    let per_sender = PAYMENTS / SENDERS;
    for i in 0..SENDERS {
        let expected_out = Amount::from_afri(1).units() * per_sender as u128
            + harness::FEE.units() * per_sender as u128;
        let left = cluster.balance(&harness::sender(i));
        assert_eq!(
            left,
            harness::ENDOWMENT.units() - expected_out,
            "sender {i} has the wrong balance after {per_sender} payments"
        );
    }
    assert_eq!(
        cluster.balance(&account(harness::RECIPIENT)),
        Amount::from_afri(1).units() * PAYMENTS as u128,
        "the recipient did not receive exactly what was sent"
    );

    // And a light client can still prove one of those balances against the
    // header, which is the property a busy tree could break without breaking
    // agreement.
    cluster.assert_balance_provable(&account(harness::RECIPIENT));
}

#[test]
#[ignore = "sustained load; run explicitly"]
fn a_thousand_payments_across_four_hundred_accounts() {
    // The customer-shaped version. Not on the default path because it takes
    // minutes, but it is the one that says whether the numbers above hold when
    // the tree is deep enough for its complexity class to show.
    let _serial = harness::exclusive();
    let senders = 400usize;
    let payments = 1_000usize;
    let mut cluster = Cluster::funded(4, "load-big", senders);

    let started = std::time::Instant::now();
    let mut submitted = Vec::new();
    for i in 0..payments {
        let tx = cluster.transfer(i % senders, (i / senders) as u64, Amount::from_afri(1));
        submitted.push(tx.id());
        let target = i % cluster.len();
        cluster.nodes[target]
            .shared
            .lock()
            .unwrap()
            .submit(tx)
            .expect("a valid payment");
    }

    let landed = cluster.wait_until(harness::CEILING, |c| {
        submitted
            .iter()
            .all(|id| c.nodes[0].store.locate(id).unwrap().is_some())
    });
    let elapsed = started.elapsed();
    cluster.quiesce();
    assert!(landed, "not every payment was committed");
    cluster.assert_agreement();

    // Before asserting, say what the chain actually did. A payments network that
    // *includes* every transaction and *executes* only some of them is a
    // different failure from one that drops them, and the totals alone cannot
    // tell the two apart.
    let mut by_code: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for h in 1..=cluster.nodes[0].tip().0 {
        for receipt in cluster.nodes[0]
            .store
            .receipts(Height(h))
            .unwrap()
            .unwrap_or_default()
        {
            *by_code.entry(format!("{:?}", receipt.code)).or_default() += 1;
        }
    }
    println!("receipts by outcome: {by_code:?}");

    let mut in_blocks = 0usize;
    let mut ids = std::collections::BTreeSet::new();
    for h in 1..=cluster.nodes[0].tip().0 {
        if let Some(block) = cluster.nodes[0].store.block(Height(h)).unwrap() {
            in_blocks += block.transactions.len();
            for tx in &block.transactions {
                ids.insert(tx.id());
            }
        }
    }
    println!(
        "blocks 1..={}: {in_blocks} transactions, {} distinct ids, submitted {payments}",
        cluster.nodes[0].tip().0,
        ids.len()
    );
    for (i, node) in cluster.nodes.iter().enumerate() {
        println!(
            "node {i}: tip {:?} stored {:?} recipient {}",
            node.tip(),
            node.stored_height(),
            cluster.balance_on(i, &account(harness::RECIPIENT))
        );
    }

    assert_eq!(
        cluster.balance(&account(harness::RECIPIENT)),
        Amount::from_afri(1).units() * payments as u128
    );
    println!(
        "\n{payments} payments over {senders} accounts in {:.1}s ({:.0} tx/s), \
         final height {:?}, state entries {}\n",
        elapsed.as_secs_f64(),
        payments as f64 / elapsed.as_secs_f64(),
        cluster.nodes[0].tip(),
        cluster.state_len()
    );
}

#[test]
fn a_sender_cannot_spend_more_than_it_has_however_hard_it_tries() {
    // The adversarial half of load. A customer under load is indistinguishable
    // from an attacker trying to double-spend by flooding: both submit many
    // transactions at once from one account. The ledger must not let volume
    // turn into money.
    let _serial = harness::exclusive();
    let mut cluster = Cluster::funded(4, "overspend", 1);
    let sender = harness::sender(0);
    let before = cluster.balance(&sender);

    // Far more than the account can afford, all valid-looking, submitted at once.
    let affordable = 5u64;
    let mut ids = Vec::new();
    for nonce in 0..40u64 {
        let tx = cluster.transfer(0, nonce, Amount::from_afri(2_000));
        ids.push(tx.id());
        drop(cluster.nodes[0].shared.lock().unwrap().submit(tx));
    }

    assert!(
        cluster.wait_until(harness::CEILING, |c| c.lowest_tip() >= Height(6)),
        "the chain stopped making blocks under a flood"
    );
    cluster.quiesce();
    cluster.assert_agreement();

    let after = cluster.balance(&sender);
    assert!(
        after <= before,
        "an account gained money by submitting transactions it could not afford"
    );
    let _ = affordable;
    let recipient = cluster.balance(&account(harness::RECIPIENT));
    assert!(
        recipient <= before,
        "more was delivered than the sender ever had: {recipient} from {before}"
    );
}
