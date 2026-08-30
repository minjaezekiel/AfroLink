//! The transport, end to end: a real chain on disk, a real socket, and a wallet
//! that verifies what came back.
//!
//! The claim under test is the one the whole design rests on:
//!
//! > A phone holding one header and a validator set can ask a node it does not
//! > trust for its balance, over plain HTTP, and either get the truth or catch
//! > the lie.
//!
//! Everything else here is the transport doing its second job — refusing. The
//! request-smuggling and limit tests in `wire` prove the parser refuses; these
//! prove the refusals survive contact with a socket, a thread pool and a
//! keep-alive connection, which is where a parser's guarantees usually leak.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use afrolink_bank::Issuer;
use afrolink_consensus::{Commit, CountryCode, Validator, ValidatorSet, Vote, VoteType};
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Block, Genesis, GenesisLimits};
use afrolink_http::{Config, Server};
use afrolink_light::LightClient;
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_rpc::{ProvedValue, Query, Response};
use afrolink_state::MemoryStore;
use afrolink_store::{ChainStore, ServedChain};

// ---------------------------------------------------------------------------
// A minimal HTTP client, so the test speaks the protocol rather than a library's
// idea of it. Sending raw bytes is the only way to test what a hostile client
// would actually send.
// ---------------------------------------------------------------------------

struct Reply {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A connection that can send several requests, so keep-alive is testable.
struct Conn {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Conn {
    fn open(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
        }
    }

    fn send(&mut self, raw: &str) {
        self.writer.write_all(raw.as_bytes()).unwrap();
        self.writer.flush().unwrap();
    }

    /// Read exactly one response, using its declared `Content-Length`.
    fn recv(&mut self) -> Reply {
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap();

        let mut headers = BTreeMap::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }

        let length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        self.reader.read_exact(&mut body).unwrap();

        Reply {
            status,
            headers,
            body,
        }
    }
}

/// One request on its own connection.
fn get(addr: SocketAddr, target: &str) -> Reply {
    raw(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: n\r\nConnection: close\r\n\r\n"),
    )
}

fn raw(addr: SocketAddr, request: &str) -> Reply {
    let mut conn = Conn::open(addr);
    conn.send(request);
    conn.recv()
}

// ---------------------------------------------------------------------------
// Chain fixture
// ---------------------------------------------------------------------------

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn account(seed: u8) -> Address {
    Address::from_public_key(&key(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-http-test").unwrap()
}

fn kes() -> Denom {
    Denom::sovereign("ke", "kes").unwrap()
}

fn validators() -> ValidatorSet {
    ValidatorSet::new(
        (1..=4u8)
            .map(|i| Validator::new(key(i).public_key(), 1, CountryCode::new("ke").unwrap()))
            .collect(),
    )
    .unwrap()
}

fn commit_for(block: &Block) -> Commit {
    let block_id = block.header.id();
    let signatures = (1..=4u8)
        .map(|s| {
            Vote {
                chain_id: chain(),
                height: block.header.height,
                round: Round::ZERO,
                vote_type: VoteType::Precommit,
                block_id: Some(block_id),
                validator: account(s),
            }
            .sign(&key(s))
        })
        .collect();
    Commit::new(block.header.height, Round::ZERO, block_id, signatures)
}

/// A funded genesis chain in a fresh database, plus the wallet's starting point.
fn chain_on_disk(name: &str) -> (std::path::PathBuf, ChainStore, MemoryStore, LightClient) {
    let mut path = std::env::temp_dir();
    path.push(format!("afrolink-http-{name}-{}.redb", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators(),
        issuers: vec![(kes(), Issuer::new(account(100)))],
        allocations: vec![Allocation {
            address: account(50),
            denom: kes(),
            amount: Amount::from_afri(2_500),
        }],
    };

    let store = ChainStore::open(&path).unwrap();
    store.put_genesis(&genesis).unwrap();

    let mut state = MemoryStore::new();
    let block = genesis.apply(&mut state, GenesisLimits::devnet()).unwrap();
    store.put_block(&block, &commit_for(&block)).unwrap();
    store.persist_state(&state).unwrap();

    let client = LightClient::new(chain(), validators(), block.header.clone());
    (path, store, state, client)
}

/// Run a server for the duration of `body`, then stop it.
///
/// `std::thread::scope` is what lets the server borrow the view rather than
/// demanding ownership of the node's state — the same reason `Server::run`
/// takes a reference.
fn with_server<F: FnOnce(SocketAddr) + Send>(name: &str, config: Config, body: F) {
    let (path, store, state, _client) = chain_on_disk(name);
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", config).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view).unwrap());
        body(addr);
        handle.stop();
    });

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

#[test]
fn a_wallet_verifies_a_balance_fetched_over_http() {
    let (path, store, state, client) = chain_on_disk("verify");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view).unwrap());

        let query = Query::Balance {
            address: account(50),
            denom: kes(),
        };
        let reply = get(
            addr,
            &format!(
                "/v1/accounts/{}/balance?denom={}",
                account(50).to_bech32().unwrap(),
                kes().as_str()
            ),
        );

        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.header("content-type"),
            Some("application/vnd.afrolink.v1+bin")
        );

        // The bytes off the socket decode to a response, and the proof inside
        // it checks against a header the wallet trusts. Nothing about the
        // transport is trusted at any point.
        let response = decode_exact::<Response>(&reply.body).unwrap();
        let balance = response
            .as_value()
            .unwrap()
            .verify_amount(&client, &query.store_key().unwrap())
            .unwrap();
        assert_eq!(balance, Amount::from_afri(2_500));

        handle.stop();
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_tampered_body_fails_verification_rather_than_being_believed() {
    // This is the reason the transport is allowed to be plain HTTP. A proxy
    // that rewrites the answer is in exactly the same position as a hostile
    // node, and the light client already assumes hostile nodes.
    let (path, store, state, client) = chain_on_disk("tamper");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view).unwrap());

        let query = Query::Balance {
            address: account(50),
            denom: kes(),
        };
        let reply = get(
            addr,
            &format!(
                "/v1/accounts/{}/balance?denom={}",
                account(50).to_bech32().unwrap(),
                kes().as_str()
            ),
        );
        let honest = decode_exact::<Response>(&reply.body).unwrap();
        let proof = honest.as_value().unwrap().proof().clone();

        // Rebuild the response on the wire with a larger balance and the real
        // proof — what a man in the middle would send.
        let mut wire = vec![2u8]; // Response::Value
        honest.as_value().unwrap().height().encode(&mut wire);
        Some(Amount::from_afri(9_999_999).to_bytes()).encode(&mut wire);
        proof.encode(&mut wire);
        let forged = decode_exact::<Response>(&wire).unwrap();

        assert!(
            forged
                .as_value()
                .unwrap()
                .verify(&client, &query.store_key().unwrap())
                .is_err(),
            "an inflated balance must not verify"
        );

        handle.stop();
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_json_view_carries_the_proof_and_names_the_unverified_field() {
    // The failure `crates/rpc` exists to prevent is a convenience endpoint that
    // returns a balance without a proof. A JSON renderer is how that would
    // arrive, so the shape is asserted rather than left to review.
    with_server("json", Config::default(), |addr| {
        let reply = get(
            addr,
            &format!(
                "/v1/accounts/{}/balance?denom={}&format=json",
                account(50).to_bech32().unwrap(),
                kes().as_str()
            ),
        );
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-type"), Some("application/json"));

        let body = reply.text();
        assert!(body.contains("\"value_unverified\""), "{body}");
        assert!(body.contains("\"proof\""), "{body}");
        // And the canonical bytes, so reading JSON never costs the ability to
        // verify.
        assert!(body.contains("\"response\""), "{body}");
        assert!(
            !body.contains("\"balance\""),
            "a proof-free balance: {body}"
        );
    });
}

#[test]
fn accept_json_is_honoured_and_binary_is_the_default() {
    with_server("negotiate", Config::default(), |addr| {
        let plain = get(addr, "/v1/status");
        assert_eq!(
            plain.header("content-type"),
            Some("application/vnd.afrolink.v1+bin"),
            "a client that did not ask should not pay for hex"
        );
        assert_eq!(plain.header("vary"), Some("Accept"));

        let asked = raw(
            addr,
            "GET /v1/status HTTP/1.1\r\nHost: n\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(asked.header("content-type"), Some("application/json"));
    });
}

#[test]
fn a_posted_canonical_query_answers_the_same_as_its_route() {
    // The two surfaces must not drift: a wallet using POST and a developer
    // using the path should get identical bytes.
    with_server("post", Config::default(), |addr| {
        let query = Query::Balance {
            address: account(50),
            denom: kes(),
        };
        let body = query.to_bytes();

        let mut request = format!(
            "POST /v1/query HTTP/1.1\r\nHost: n\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);

        let mut conn = Conn::open(addr);
        conn.writer.write_all(&request).unwrap();
        conn.writer.flush().unwrap();
        let posted = conn.recv();

        let routed = get(
            addr,
            &format!(
                "/v1/accounts/{}/balance?denom={}",
                account(50).to_bech32().unwrap(),
                kes().as_str()
            ),
        );

        assert_eq!(posted.status, 200);
        assert_eq!(posted.body, routed.body);
    });
}

#[test]
fn one_connection_serves_several_requests() {
    // Keep-alive is not an optimisation on a mobile radio: a new connection
    // means waking the radio and paying a round trip.
    with_server("keepalive", Config::default(), |addr| {
        let mut conn = Conn::open(addr);
        for _ in 0..3 {
            conn.send("GET /health HTTP/1.1\r\nHost: n\r\n\r\n");
            let reply = conn.recv();
            assert_eq!(reply.status, 200);
            assert_eq!(reply.header("connection"), Some("keep-alive"));
            assert!(reply.text().contains("\"height\":0"), "{}", reply.text());
        }
    });
}

#[test]
fn the_index_tells_a_developer_what_this_node_answers() {
    with_server("index", Config::default(), |addr| {
        let reply = get(addr, "/");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-type"), Some("application/json"));
        let body = reply.text();
        assert!(
            body.contains("/v1/accounts/{address}/balance?denom="),
            "{body}"
        );
    });
}

#[test]
fn a_proved_absence_is_served_as_an_answer_rather_than_a_404() {
    // "You have no balance" is a claim the node must prove like any other. A
    // 404 here would let a node lie by omission and blame the transport.
    let (path, store, state, client) = chain_on_disk("absent");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view).unwrap());

        let query = Query::Balance {
            address: account(77),
            denom: kes(),
        };
        let reply = get(
            addr,
            &format!(
                "/v1/accounts/{}/balance?denom={}",
                account(77).to_bech32().unwrap(),
                kes().as_str()
            ),
        );
        assert_eq!(reply.status, 200);

        let response = decode_exact::<Response>(&reply.body).unwrap();
        let proved: &ProvedValue = response.as_value().unwrap();
        assert!(proved.value_unverified().is_none());
        assert_eq!(
            proved
                .verify_amount(&client, &query.store_key().unwrap())
                .unwrap(),
            Amount::ZERO
        );

        handle.stop();
    });

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Refusals, over a real socket
// ---------------------------------------------------------------------------

#[test]
fn a_smuggling_attempt_is_refused_and_the_connection_is_not_reused() {
    // A desync only pays off if the attacker can keep sending on the same
    // connection. After a parse failure the stream position is unknown, so the
    // server must answer once and close.
    with_server("smuggle", Config::default(), |addr| {
        let mut conn = Conn::open(addr);
        conn.send(
            "POST /v1/query HTTP/1.1\r\nHost: n\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /v1/status HTTP/1.1\r\nHost: n\r\n\r\n",
        );
        let reply = conn.recv();
        assert_eq!(reply.status, 501, "{}", reply.text());
        assert_eq!(reply.header("connection"), Some("close"));

        // Nothing further comes back: the smuggled request was never a request.
        let mut rest = Vec::new();
        conn.reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "server kept talking: {rest:?}");
    });
}

#[test]
fn a_bare_lf_request_is_refused_over_a_socket_too() {
    with_server("barelf", Config::default(), |addr| {
        let reply = raw(addr, "GET /v1/status HTTP/1.1\nHost: n\n\n");
        assert_eq!(reply.status, 400);
        assert_eq!(reply.header("connection"), Some("close"));
    });
}

#[test]
fn an_oversized_body_is_refused_rather_than_buffered() {
    let config = Config {
        max_body_bytes: 32,
        ..Config::default()
    };
    with_server("toobig", config, |addr| {
        let reply = raw(
            addr,
            "POST /v1/query HTTP/1.1\r\nHost: n\r\nContent-Length: 1000000\r\n\r\n",
        );
        assert_eq!(reply.status, 413);
    });
}

#[test]
fn a_slow_client_is_dropped_rather_than_holding_a_thread() {
    // Slowloris: open a connection and never finish the request. Without a read
    // timeout this holds a thread until the process dies.
    let config = Config {
        read_timeout: Duration::from_millis(150),
        ..Config::default()
    };
    with_server("slowloris", config, |addr| {
        let mut conn = Conn::open(addr);
        conn.send("GET /v1/status HTTP/1.1\r\n");

        let mut rest = Vec::new();
        let started = std::time::Instant::now();
        let _ = conn.reader.read_to_end(&mut rest);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the server waited too long to give up"
        );
    });
}

#[test]
fn an_unknown_route_is_a_404_with_a_pointer_to_the_index() {
    with_server("notfound", Config::default(), |addr| {
        let reply = get(addr, "/v1/nonsense");
        assert_eq!(reply.status, 404);
        assert!(reply.text().contains("GET /"), "{}", reply.text());
    });
}

#[test]
fn a_wrong_method_says_which_one_to_use() {
    with_server("allow", Config::default(), |addr| {
        let reply = raw(
            addr,
            "POST /v1/status HTTP/1.1\r\nHost: n\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(reply.status, 405);
        assert_eq!(reply.header("allow"), Some("GET"));
    });
}

#[test]
fn a_missing_height_is_a_404_and_a_bad_one_is_a_400() {
    with_server("heights", Config::default(), |addr| {
        assert_eq!(get(addr, "/v1/blocks/999").status, 404);
        assert_eq!(get(addr, "/v1/blocks/latest").status, 400);
    });
}

#[test]
fn a_browser_can_read_this_node_without_a_proxy_in_front() {
    // Everything served is public, proof-carrying data with no cookies and no
    // ambient authority, so permissive CORS grants a page nothing `curl` did
    // not already have — and it is what makes an explorer possible.
    with_server("cors", Config::default(), |addr| {
        let reply = get(addr, "/v1/status");
        assert_eq!(reply.header("access-control-allow-origin"), Some("*"));

        let preflight = raw(
            addr,
            "OPTIONS /v1/query HTTP/1.1\r\nHost: n\r\nOrigin: https://explorer.example\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(preflight.status, 204);
        assert_eq!(
            preflight.header("access-control-allow-methods"),
            Some("GET, POST, OPTIONS")
        );
    });
}

#[test]
fn a_node_at_capacity_refuses_rather_than_queueing() {
    // An unbounded backlog is the same failure as an unbounded thread count,
    // with a longer fuse.
    let config = Config {
        max_connections: 1,
        read_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    with_server("capacity", config, |addr| {
        // Hold the one slot open with an unfinished request.
        let mut held = Conn::open(addr);
        held.send("GET /v1/status HTTP/1.1\r\n");

        // Give the server a moment to accept and occupy its single slot.
        let mut refused = None;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(20));
            let reply = get(addr, "/health");
            if reply.status == 503 {
                refused = Some(reply);
                break;
            }
        }

        let reply = refused.expect("a second connection should have been refused");
        assert!(reply.text().contains("capacity"), "{}", reply.text());
    });
}

#[test]
fn a_backend_failure_does_not_narrate_the_nodes_filesystem() {
    // The one thing an error must not do is tell a stranger where the database
    // lives. `QueryError::Backend` carries detail for logs, not for clients.
    struct Broken;
    impl afrolink_rpc::ChainView for Broken {
        fn chain_id(&self) -> &ChainId {
            static ID: std::sync::OnceLock<ChainId> = std::sync::OnceLock::new();
            ID.get_or_init(|| ChainId::new("broken").unwrap())
        }
        fn tip_height(&self) -> Result<Height, afrolink_rpc::QueryError> {
            Err(afrolink_rpc::QueryError::Backend(
                "/home/validator/secret/chain.redb is corrupt".into(),
            ))
        }
        fn signed_header(
            &self,
            _height: Height,
        ) -> Result<Option<afrolink_rpc::SignedHeader>, afrolink_rpc::QueryError> {
            Ok(None)
        }
        fn prove(
            &self,
            _key: &afrolink_state::StoreKey,
        ) -> Result<(Option<Vec<u8>>, afrolink_state::Proof), afrolink_rpc::QueryError> {
            Err(afrolink_rpc::QueryError::Backend("disk on fire".into()))
        }
    }

    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();
    let view = Broken;

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view).unwrap());

        let reply = get(addr, "/v1/status");
        assert_eq!(reply.status, 500);
        let text = reply.text();
        assert!(!text.contains("/home/validator"), "path leaked: {text}");
        assert!(!text.contains("corrupt"), "backend detail leaked: {text}");

        // And a store that cannot be read is reported as unhealthy rather than
        // as a healthy node with no data.
        assert_eq!(get(addr, "/health").status, 503);

        handle.stop();
    });
}

#[test]
fn stopping_the_server_actually_stops_it() {
    let (path, store, state, _client) = chain_on_disk("stop");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view).unwrap());
        assert_eq!(get(addr, "/health").status, 200);
        handle.stop();
        assert!(handle.is_stopped());
    });

    // The scope has joined the accept loop, so the port is released. If `stop`
    // did not wake `accept`, this test would hang rather than fail — which is
    // the honest signal for a shutdown that does not shut down.
    let _ = std::fs::remove_file(&path);
}
