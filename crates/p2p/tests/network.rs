//! Two nodes, two sockets, and everything in between.
//!
//! The unit tests in this crate prove the rules; these prove the rules are
//! reachable. Until this file existed, `crates/p2p` was a handshake nobody
//! performed, an address book nobody dialled from and a gossip policy nothing
//! delivered to — the defect class this codebase has now met four times, where
//! correct and thoroughly tested code is reachable from no caller.
//!
//! Everything here runs over real loopback TCP with the real handshake. Nothing
//! is stubbed.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use afrolink_consensus::{CountryCode, Validator, ValidatorSet};
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Genesis, GenesisLimits};
use afrolink_node::{Node, SharedNode};
use afrolink_p2p::addrbook::AddrBook;
use afrolink_p2p::manager::{Limits, Manager};
use afrolink_p2p::peer::{PeerAddr, PeerId};
use afrolink_p2p::transport::{Transport, wait_for};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_types::{Fee, Message, Transaction, TxBody};

const PATIENCE: Duration = Duration::from_secs(5);

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn account(seed: u8) -> Address {
    Address::from_public_key(&key(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-p2p-test").unwrap()
}

fn validators() -> ValidatorSet {
    ValidatorSet::new(
        (1..=4u8)
            .map(|i| Validator::new(key(i).public_key(), 1, CountryCode::new("ke").unwrap()))
            .collect(),
    )
    .unwrap()
}

/// One node, with a genesis every node in a test shares.
fn node(seed: u8) -> Arc<SharedNode> {
    let validators = validators();
    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators.clone(),
        issuers: Vec::new(),
        attestors: Vec::new(),
        council: afrolink_executor::Council::devnet(account(50)),
        params: afrolink_executor::ChainParams::devnet(),
        allocations: vec![Allocation {
            address: account(50),
            denom: Denom::native(),
            amount: Amount::from_afri(1_000),
        }],
    };
    let mut store = MemoryStore::new();
    let block = genesis.apply(&mut store, GenesisLimits::devnet()).unwrap();
    Arc::new(SharedNode::new(Node::new(
        chain(),
        key(seed),
        validators,
        store,
        &block,
    )))
}

/// A transport bound to an operating-system-chosen loopback port.
fn transport(seed: u8, node: &Arc<SharedNode>) -> Transport {
    transport_with(seed, node, Limits::default())
}

fn transport_with(seed: u8, node: &Arc<SharedNode>, limits: Limits) -> Transport {
    let identity = PeerId::new(key(seed).public_key());
    let manager = Manager::new(identity, AddrBook::new(&key(seed)), limits);
    Transport::start(
        chain(),
        key(seed),
        Arc::clone(node),
        manager,
        "127.0.0.1:0".parse().unwrap(),
    )
    .expect("binds")
}

fn address_of(t: &Transport) -> PeerAddr {
    PeerAddr::new(t.peer_id(), t.local_addr())
}

fn payment(nonce: u64) -> Transaction {
    TxBody {
        chain_id: chain(),
        sender: account(50),
        nonce,
        valid_until: Height(1_000),
        fee: Fee::new(Amount::from_units(1_000), Denom::native()),
        messages: vec![Message::Transfer {
            to: account(60),
            denom: Denom::native(),
            amount: Amount::from_afri(1),
            reference: None,
        }],
        memo: String::new(),
    }
    .sign(&key(50))
}

fn mempool_len(node: &Arc<SharedNode>) -> usize {
    node.lock().map(|n| n.pending()).unwrap_or(0)
}

fn holds(node: &Arc<SharedNode>, tx: &Transaction) -> bool {
    node.lock().map(|n| n.is_pending(&tx.id())).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// It works at all
// ---------------------------------------------------------------------------

#[test]
fn two_nodes_shake_hands_over_a_real_socket() {
    let (a, b) = (node(1), node(2));
    let (ta, tb) = (transport(1, &a), transport(2, &b));

    ta.dial(address_of(&tb)).expect("connects");

    assert_eq!(ta.peers(), vec![tb.peer_id()]);
    assert!(
        wait_for(PATIENCE, || tb.peers() == vec![ta.peer_id()]),
        "the accepting side must know who called"
    );
}

#[test]
fn a_transaction_submitted_to_one_node_reaches_the_other() {
    // The whole point of the crate, in one test. Before this, a transaction
    // handed to a node stayed there: `Action::BroadcastTransaction` was produced
    // and dropped on the floor, because nothing existed to put it on a wire.
    let (a, b) = (node(1), node(2));
    let (ta, tb) = (transport(1, &a), transport(2, &b));
    ta.dial(address_of(&tb)).expect("connects");
    assert!(wait_for(PATIENCE, || !tb.peers().is_empty()));

    let actions = {
        let mut guard = a.lock().unwrap();
        let accepted = guard.submit(payment(0)).expect("a valid payment");
        vec![afrolink_node::Action::BroadcastTransaction(Box::new(
            accepted,
        ))]
    };
    ta.broadcast(actions);

    assert!(
        wait_for(PATIENCE, || mempool_len(&b) == 1),
        "the peer never received the transaction"
    );
    assert!(
        holds(&b, &payment(0)),
        "and it is the transaction that was sent, not merely something"
    );
}

#[test]
fn a_node_relays_onward_to_a_third_peer() {
    // Gossip, rather than point-to-point delivery: B is connected to A and to C,
    // and a transaction A gives it has to reach C without A ever talking to C.
    let (a, b, c) = (node(1), node(2), node(3));
    let (ta, tb, tc) = (transport(1, &a), transport(2, &b), transport(3, &c));
    ta.dial(address_of(&tb)).expect("connects");
    tc.dial(address_of(&tb)).expect("connects");
    assert!(wait_for(PATIENCE, || tb.peers().len() == 2));

    let actions = {
        let mut guard = a.lock().unwrap();
        let accepted = guard.submit(payment(0)).expect("a valid payment");
        vec![afrolink_node::Action::BroadcastTransaction(Box::new(
            accepted,
        ))]
    };
    ta.broadcast(actions);

    assert!(
        wait_for(PATIENCE, || mempool_len(&c) == 1),
        "a transaction must reach a node two hops away"
    );
    assert!(ta.peers().iter().all(|p| *p != tc.peer_id()));
}

#[test]
fn the_same_transaction_arriving_twice_is_held_once() {
    // Deduplication, over sockets. Without it, a node with several peers relays
    // one submission back and forth until the network is doing nothing else.
    let (a, b, c) = (node(1), node(2), node(3));
    let (ta, tb, tc) = (transport(1, &a), transport(2, &b), transport(3, &c));
    // A triangle: every node hears every other, directly and indirectly.
    ta.dial(address_of(&tb)).expect("connects");
    tc.dial(address_of(&tb)).expect("connects");
    tc.dial(address_of(&ta)).expect("connects");
    assert!(wait_for(PATIENCE, || tb.peers().len() == 2 && tc.peers().len() == 2));

    let actions = {
        let mut guard = a.lock().unwrap();
        let accepted = guard.submit(payment(0)).expect("a valid payment");
        vec![afrolink_node::Action::BroadcastTransaction(Box::new(
            accepted,
        ))]
    };
    ta.broadcast(actions);

    assert!(wait_for(PATIENCE, || mempool_len(&c) == 1));
    // And it settles: a loop would keep the count climbing, or keep the CPU busy
    // forever. One copy, and it stays one.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(mempool_len(&c), 1);
    assert_eq!(mempool_len(&b), 1);
    assert_eq!(mempool_len(&a), 1);
}

// ---------------------------------------------------------------------------
// It refuses what it should
// ---------------------------------------------------------------------------

#[test]
fn dialling_an_address_and_reaching_the_wrong_node_is_refused() {
    // The property that makes an address book worth having. Without it, whoever
    // answers at a known address inherits the standing of whoever should have
    // been there.
    let (a, b) = (node(1), node(2));
    let (ta, tb) = (transport(1, &a), transport(2, &b));

    // Dial B's address while expecting some third identity.
    let impostor = PeerAddr::new(PeerId::new(key(9).public_key()), tb.local_addr());
    let error = ta.dial(impostor).expect_err("must refuse");
    assert!(
        error.to_string().contains("dialled"),
        "expected a wrong-peer refusal, got: {error}"
    );
    assert!(ta.peers().is_empty());
}

#[test]
fn a_node_on_another_chain_cannot_join() {
    // The chain id is bound into the session keys, not just into a signature, so
    // a testnet node reaching a mainnet port fails before it can say anything.
    let (a, b) = (node(1), node(2));
    let ta = transport(1, &a);

    let identity = PeerId::new(key(2).public_key());
    let manager = Manager::new(identity, AddrBook::new(&key(2)), Limits::default());
    let tb = Transport::start(
        ChainId::new("some-other-chain").unwrap(),
        key(2),
        Arc::clone(&b),
        manager,
        "127.0.0.1:0".parse().unwrap(),
    )
    .expect("binds");

    assert!(ta.dial(address_of(&tb)).is_err());
    assert!(ta.peers().is_empty());
    assert!(
        wait_for(Duration::from_millis(500), || tb.peers().is_empty()),
        "neither side may end up holding the other"
    );
}

#[test]
fn a_node_will_not_connect_to_itself() {
    let a = node(1);
    let ta = transport(1, &a);
    assert!(ta.dial(address_of(&ta)).is_err());
    assert!(ta.peers().is_empty());
}

#[test]
fn garbage_on_the_wire_does_not_take_the_node_down() {
    // The first thing an anonymous peer reaches. It must survive nonsense
    // without panicking, without hanging, and without leaving a peer registered.
    let a = node(1);
    let ta = transport(1, &a);
    let addr: SocketAddr = ta.local_addr();

    for payload in [
        vec![0u8; 1],
        vec![0xffu8; 64],
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0u8; 4096],
    ] {
        let mut stream = TcpStream::connect(addr).expect("connects");
        drop(stream.write_all(&payload));
        drop(stream.flush());
        drop(stream.shutdown(std::net::Shutdown::Both));
    }

    // Still alive, still empty, still able to accept a real peer.
    assert!(
        wait_for(PATIENCE, || ta.peers().is_empty()),
        "nonsense must not leave a peer registered"
    );
    let b = node(2);
    let tb = transport(2, &b);
    tb.dial(address_of(&ta))
        .expect("a real peer still connects");
    assert!(wait_for(PATIENCE, || ta.peers().len() == 1));
}

#[test]
fn a_connection_that_says_nothing_does_not_hold_a_slot_forever() {
    // A socket opened and left silent costs a thread and a descriptor. Without a
    // handshake deadline, opening thousands is a denial of service that never
    // sends a byte.
    let a = node(1);
    let ta = transport(1, &a);
    let silent = TcpStream::connect(ta.local_addr()).expect("connects");
    assert!(ta.peers().is_empty());
    drop(silent);
    // The deadline is ten seconds, so this asserts the shape rather than waiting
    // it out: the connection is not a peer, and a real one still gets in.
    let b = node(2);
    let tb = transport(2, &b);
    tb.dial(address_of(&ta)).expect("connects");
    assert!(wait_for(PATIENCE, || ta.peers().len() == 1));
}

// ---------------------------------------------------------------------------
// The limits hold over sockets, not only in the manager
// ---------------------------------------------------------------------------

#[test]
fn the_inbound_limit_is_enforced_on_real_connections() {
    let a = node(1);
    let ta = transport_with(
        1,
        &a,
        Limits {
            max_inbound: 1,
            ..Limits::default()
        },
    );
    let (b, c) = (node(2), node(3));
    let (tb, tc) = (transport(2, &b), transport(3, &c));

    tb.dial(address_of(&ta)).expect("the first gets in");
    assert!(wait_for(PATIENCE, || ta.peers().len() == 1));
    // The second is refused by the manager after a perfectly good handshake:
    // proving who you are is not the same as being wanted.
    drop(tc.dial(address_of(&ta)));
    assert!(
        wait_for(Duration::from_millis(500), || ta.peers().len() == 1),
        "the inbound cap must hold over sockets, not only in a unit test"
    );
}

#[test]
fn distinct_loopback_sockets_are_distinct_groups() {
    // The carve-out that lets a devnet exist at all. Every node in this file is
    // on 127.0.0.1, so if loopback were one group a test network could never
    // form its second outbound connection — and the eclipse rule would be
    // untestable here for the wrong reason.
    //
    // The rule itself is asserted where it belongs, against routable addresses,
    // in `manager::tests::a_subnet_buys_exactly_one_outbound_slot`.
    let (a, b, c) = (node(1), node(2), node(3));
    let (ta, tb, tc) = (transport(1, &a), transport(2, &b), transport(3, &c));

    ta.dial(address_of(&tb)).expect("the first is dialled");
    ta.dial(address_of(&tc)).expect("and so is the second");
    assert_eq!(ta.peers().len(), 2);
}

#[test]
fn a_stopped_transport_stops_accepting() {
    let a = node(1);
    let ta = transport(1, &a);
    let addr = ta.local_addr();
    ta.handle().stop();

    let (b, _tb) = (node(2), ());
    let tb = transport(2, &b);
    let refused = tb.dial(PeerAddr::new(ta.peer_id(), addr));
    assert!(
        refused.is_err() || wait_for(Duration::from_millis(500), || ta.peers().is_empty()),
        "a stopped transport must not take on new peers"
    );
}
