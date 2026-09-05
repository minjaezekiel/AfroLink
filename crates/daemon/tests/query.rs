//! What a wallet gets when it asks a running `afrolinkd` for a balance.
//!
//! # The defect this exists for
//!
//! [10 §18](../../../docs/10-network-hardening.md). A node writes block N to
//! its store and publishes the state a moment later; the two are separate acts
//! and nothing makes them one. `answer()` took the height it stamped on a proof
//! from the **block store** and built the proof from the **published state**.
//! Inside that window a wallet was handed a proof of the state at N-1, labelled
//! N, and pointed at the header for N — which it cannot possibly satisfy.
//!
//! The user does not see a stale balance. They see a node whose answers do not
//! verify, which is indistinguishable from a node serving forgeries. On a
//! payments network that is the most damaging thing a correct node can do.
//!
//! # Why the test is here and not in the harness
//!
//! Because the seam is the point. The cluster harness proves the property
//! across `LiveChain` → `answer` → `LightClient` in one process; this proves it
//! across a **socket**, from a **binary an operator started**, against **its own
//! genesis file** — the four defects found by running the artefact were all
//! found on exactly that side of the seam.
//!
//! Everything the wallet needs comes from the node or from the genesis document
//! an operator can check independently. Nothing reaches into the process.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use afrolink_crypto::{Address, SecretKey};
use afrolink_daemon::identity;
use afrolink_executor::Genesis;
use afrolink_light::LightClient;
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{Amount, Denom, Height};
use afrolink_rpc::Response;
use afrolink_state::StoreKey;
use afrolink_types::{Fee, Message, TxBody};

#[path = "binary/mod.rs"]
mod binary;

/// How long to wait for the node to start producing blocks.
const RUNNING: Duration = Duration::from_secs(20);
/// How long to keep asking.
///
/// **A duration, not a count.** The window this test exists for opens once per
/// block and closes in the time it takes to swap a mutex, so what matters is
/// how many block boundaries the sampling covers, not how many questions are
/// asked between them. At roughly a block a second this crosses several, with
/// no pause between requests so that the gaps are as small as the loop allows.
const SAMPLING: Duration = Duration::from_secs(8);
/// Below this, the run was too slow to have proved anything.
const MIN_SAMPLES: usize = 200;

/// One HTTP GET, spoken by hand.
///
/// No client library: the node's contract is HTTP over a socket, and a test
/// that shares a client with the server proves only that they agree with each
/// other.
fn get(port: u16, path: &str) -> Vec<u8> {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("the node is listening");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout");
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("the request goes out");
    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).expect("the answer comes back");

    // Split the headers from the body on the blank line, and check the status
    // before trusting the body: a 500 with an empty body would otherwise decode
    // as a malformed response and read as a codec defect.
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header terminator in {} bytes", raw.len()));
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "GET {path} answered:\n{head}"
    );
    raw[split.saturating_add(4)..].to_vec()
}

fn response(port: u16, path: &str) -> Response {
    let body = get(port, path);
    decode_exact::<Response>(&body).unwrap_or_else(|e| panic!("GET {path} returned {e:?}"))
}

/// Submit a signed transaction the way a wallet does, and return what came back.
fn post(port: u16, path: &str, body: &[u8]) -> String {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("the node is listening");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout");
    write!(
        socket,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\
         Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("the headers go out");
    socket.write_all(body).expect("the body goes out");
    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).expect("the answer comes back");
    String::from_utf8_lossy(&raw).to_string()
}

/// A payment from the genesis-funded account to `to`.
fn payment(
    chain_id: &afrolink_primitives::ChainId,
    from: &SecretKey,
    nonce: u64,
    to: Address,
) -> Vec<u8> {
    TxBody {
        chain_id: chain_id.clone(),
        sender: Address::from_public_key(&from.public_key()),
        nonce,
        valid_until: Height(100_000),
        fee: Fee::new(Amount::from_units(1_000), Denom::native()),
        messages: vec![Message::Transfer {
            to,
            denom: Denom::native(),
            amount: Amount::from_afri(1),
            reference: None,
        }],
        memo: String::new(),
    }
    .sign(from)
    .to_bytes()
}

#[test]
fn a_balance_a_running_node_serves_verifies_against_the_header_it_names() {
    let dir = binary::TempDir::new("query-verify");
    let (p2p, rpc) = (29736, 29737);
    binary::prepared(&dir.0, "afrolink-query", "query", p2p, rpc);

    // The wallet's root of trust: the genesis document, which an operator
    // compares against every other operator's before starting. Read from disk
    // rather than fetched from the node under test, because a node that could
    // choose the validator set a client checks it against could say anything.
    let raw = std::fs::read(dir.0.join("genesis")).expect("init wrote a genesis");
    let document = decode_exact::<Genesis>(&raw).expect("it is a genesis document");
    let validators = document.validators.clone();
    let funded = document.allocations[0].address;
    let key = StoreKey::balance(&funded, &Denom::native());

    let (child, log) = binary::start(&dir.0);
    let _running = binary::Running(child);
    assert!(
        binary::wait_for_log(&log, "height 3", RUNNING),
        "the node never committed a block:\n{}",
        binary::log_of(&log)
    );

    // **Give the node something to do.** An idle chain commits identical empty
    // blocks, so its state tree never changes and the interval between writing
    // a block and publishing it is a few microseconds — too narrow for sampling
    // to find, which is why the first version of this test passed against the
    // defect it was written for. Real payments widen it the way real use does:
    // every one adds accounts to the tree that a commit then has to write.
    let signer = identity::load(&dir.0.join("consensus_key")).expect("init wrote a key");
    let mut nonce = 0u64;
    let mut offered = 0usize;

    let mut verified = 0usize;
    let mut heights = Vec::new();
    let until = std::time::Instant::now()
        .checked_add(SAMPLING)
        .expect("a deadline");
    while std::time::Instant::now() < until {
        // A fresh recipient each time, so the tree grows rather than repeating.
        //
        // Offered far slower than the sampling loop turns: the mempool caps one
        // sender at 64 queued transactions, which is a defence and not an
        // obstacle. A wallet that ignored it would be the flood the cap exists
        // for, so this backs off exactly as a well-behaved one does.
        if verified.is_multiple_of(25) {
            let mut seed = [0u8; 32];
            seed[0] = 0xB0;
            seed[1..9].copy_from_slice(&nonce.to_be_bytes());
            let to = Address::from_public_key(&SecretKey::from_bytes(&seed).public_key());
            let reply = post(
                rpc,
                "/v1/transactions",
                &payment(&document.chain_id, &signer, nonce, to),
            );
            if reply.starts_with("HTTP/1.1 202") {
                nonce = nonce.saturating_add(1);
                offered = offered.saturating_add(1);
            } else {
                // Back-pressure is the only refusal this test tolerates, and the
                // nonce is not consumed by one. Anything else is the node
                // rejecting a payment it should have taken.
                assert!(
                    reply.contains("transactions queued"),
                    "the node refused a valid payment:\n{reply}"
                );
            }
        }

        let Response::Value(proved) = response(
            rpc,
            &format!("/v1/accounts/{funded}/balance?denom={}", Denom::native()),
        ) else {
            panic!("a balance query was not answered with a proved value");
        };

        // The tip is read **after** the balance, not before.
        //
        // These are two HTTP requests against a chain that is committing a
        // block a second, so the node legitimately moves between them. Asking
        // first and asserting `proved <= tip` fails whenever a block lands in
        // the gap — which it did, three runs in four, and it was the *test*
        // that was wrong. Read afterwards, the comparison is sound in the
        // direction that matters: a node must never prove against a height it
        // had not reached by the time it was asked.
        let Response::Status(status) = response(rpc, "/v1/status") else {
            panic!("/v1/status did not answer with a status");
        };
        let tip = status.tip.header.height;
        assert!(
            proved.height() <= tip,
            "the node proved a balance at height {} and then reported its tip as {}",
            proved.height().0,
            tip.0
        );
        assert!(
            proved.height() > Height(0),
            "the node answered from genesis while committing blocks"
        );

        // **The wallet's actual work.** Fetch the header the node named, trust
        // it only because its validator set matches the genesis one, and check
        // the proof against it.
        let Response::Header(header) = response(rpc, &format!("/v1/blocks/{}", proved.height().0))
        else {
            panic!(
                "the node proved at height {} and will not serve that header",
                proved.height().0
            );
        };
        let client = LightClient::from_checkpoint(
            document.chain_id.clone(),
            header.header.clone(),
            validators.clone(),
            validators.clone(),
        )
        .expect("the genesis validator set matches the header it committed");

        let value = proved.verify(&client, &key).unwrap_or_else(|e| {
            panic!(
                "a wallet could not verify the balance this node served: {e:?}\n  \
                 answered at height {}, whose header claims state {}\n{}",
                proved.height().0,
                &header.header.app_hash.to_hex()[..12],
                binary::log_of(&log)
            )
        });
        assert!(
            value.is_some(),
            "the genesis allocation proved absent at height {}",
            proved.height().0
        );

        heights.push(proved.height().0);
        verified = verified.saturating_add(1);
    }

    assert!(
        verified >= MIN_SAMPLES,
        "only {verified} answers in {}s — too few to have crossed the window",
        SAMPLING.as_secs()
    );

    // The chain has to have *moved* underneath the sampling, or the window this
    // test exists for was never open and the run proves nothing.
    let first = heights.first().copied().unwrap_or(0);
    let last = heights.last().copied().unwrap_or(0);
    assert!(
        last > first,
        "the node did not commit anything while being queried ({verified} samples \
         all at height {first}), so this run never entered the window it is for"
    );

    assert!(
        offered > 0,
        "no payment was ever accepted, so the state tree never grew and the \
         window this test samples for stayed as narrow as an idle chain's"
    );

    // And an answer never goes backwards. A wallet that asks twice and is told
    // less the second time has watched money disappear on a healthy node.
    assert!(
        heights.windows(2).all(|w| w[1] >= w[0]),
        "the height a balance was proved at went backwards: {heights:?}"
    );
}
