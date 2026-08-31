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
use afrolink_rpc::{HistoryCursor, ProvedTransaction, ProvedValue, Query, ReadOnly, Response};
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
    store.put_block(&block, &commit_for(&block), &[]).unwrap();
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
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();
        body(addr);
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
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

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
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

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
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

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
        fn block(
            &self,
            _height: Height,
        ) -> Result<Option<afrolink_executor::Block>, afrolink_rpc::QueryError> {
            Err(afrolink_rpc::QueryError::Backend(
                "/home/validator/secret/chain.redb is corrupt".into(),
            ))
        }
        fn receipts(
            &self,
            _height: Height,
        ) -> Result<Option<Vec<afrolink_executor::TxReceipt>>, afrolink_rpc::QueryError> {
            Err(afrolink_rpc::QueryError::Backend("disk on fire".into()))
        }
        fn locate(
            &self,
            _id: &afrolink_crypto::hash::Hash32,
        ) -> Result<Option<(Height, u32)>, afrolink_rpc::QueryError> {
            Ok(None)
        }
        fn history(
            &self,
            _address: &Address,
            _from: Height,
            _limit: usize,
        ) -> Result<Option<(Vec<afrolink_rpc::HistoryEntry>, bool)>, afrolink_rpc::QueryError>
        {
            Ok(None)
        }
    }

    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();
    let view = Broken;

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        let reply = get(addr, "/v1/status");
        assert_eq!(reply.status, 500);
        let text = reply.text();
        assert!(!text.contains("/home/validator"), "path leaked: {text}");
        assert!(!text.contains("corrupt"), "backend detail leaked: {text}");

        // And a store that cannot be read is reported as unhealthy rather than
        // as a healthy node with no data.
        assert_eq!(get(addr, "/health").status, 503);
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
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();
        assert_eq!(get(addr, "/health").status, 200);
        handle.stop();
        assert!(handle.is_stopped());
    });

    // The scope has joined the accept loop, so the port is released. If `stop`
    // did not wake `accept`, this test would hang rather than fail — which is
    // the honest signal for a shutdown that does not shut down.
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Payment history: block bodies, inclusion proofs, and the index
// ---------------------------------------------------------------------------

/// A signed payment from account 50 to account 60.
fn payment(nonce: u64) -> afrolink_types::Transaction {
    use afrolink_types::{Fee, Message, TxBody};

    TxBody {
        chain_id: chain(),
        sender: account(50),
        nonce,
        valid_until: Height(10_000),
        fee: Fee::new(Amount::from_units(1_000), kes()),
        messages: vec![Message::Transfer {
            to: account(60),
            denom: kes(),
            amount: Amount::from_afri(7),
            reference: Some(afrolink_pay::PaymentReference(880_123)),
        }],
        memo: String::new(),
    }
    .sign(&key(50))
}

/// Genesis plus a block containing one payment, with a wallet advanced to it.
fn chain_with_payment(
    name: &str,
) -> (
    std::path::PathBuf,
    ChainStore,
    MemoryStore,
    LightClient,
    afrolink_executor::BlockHeader,
    afrolink_types::Transaction,
) {
    use afrolink_executor::{Executor, ValidatorSets};

    let (path, store, mut state, mut client) = chain_on_disk(name);
    let genesis_block = store.block(Height::GENESIS).unwrap().unwrap();

    let sent = payment(0);
    let executor = Executor::new(chain());
    let (block, outcome) = executor.build_block(
        &mut state,
        Height(1),
        Timestamp::from_millis(1_700_000_001_000),
        genesis_block.header.id(),
        vec![sent.clone()],
        ValidatorSets::unchanged(&validators()),
    );
    assert_eq!(outcome.succeeded(), 1, "the fixture payment must apply");

    let commit = commit_for(&block);
    let receipts: Vec<afrolink_executor::TxReceipt> =
        outcome.outcomes.iter().map(|o| o.receipt.clone()).collect();
    store.put_block(&block, &commit, &receipts).unwrap();
    store.persist_state(&state).unwrap();
    client
        .update(
            block.header.clone(),
            &commit,
            validators(),
            validators(),
            Timestamp::from_millis(1_700_000_100_000),
        )
        .unwrap();

    (path, store, state, client, block.header, sent)
}

#[test]
fn a_wallet_sees_a_payment_arrive_and_can_prove_it() {
    // The claim this whole layer exists for. A recipient who never saw the
    // transaction, does not know its id, and does not trust the node: finds it
    // through the index, then proves it against a header it verified itself.
    let (path, store, state, client, _header, sent) = chain_with_payment("history");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        // 1. The recipient asks what touched their account.
        let listing = get(
            addr,
            &format!("/v1/accounts/{}/history", account(60).to_bech32().unwrap()),
        );
        assert_eq!(listing.status, 200);
        let Response::History(history) = decode_exact::<Response>(&listing.body).unwrap() else {
            panic!("expected a history response");
        };
        assert!(!history.truncated());
        let entries = history.entries_unverified();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tx_id, sent.id());

        // 2. That id is only a hint. The proof is what makes it true.
        let fetched = get(addr, &format!("/v1/transactions/{}", sent.id().to_hex()));
        assert_eq!(fetched.status, 200);
        let Response::Transaction(proved) = decode_exact::<Response>(&fetched.body).unwrap() else {
            panic!("expected a transaction response");
        };

        // Verified against the header the *wallet* holds, not the fixture's —
        // the client walked to it from genesis by checking commit signatures,
        // which is the only header it has any reason to believe.
        let effects = proved
            .verify(client.trusted_header())
            .expect("inclusion must verify");
        assert_eq!(effects.transaction.id(), sent.id());
        assert_eq!(effects.transaction.body.sender, account(50));

        // 3. The receipt is proved too, so "it worked" is not a claim.
        assert!(
            effects.receipt.code.succeeded(),
            "the payment succeeded, and that is provable"
        );

        // 4. And the destination tag survived, which is what an exchange
        //    reconciles against.
        let afrolink_types::Message::Transfer { reference, .. } =
            &effects.transaction.body.messages[0]
        else {
            panic!("expected a transfer");
        };
        assert_eq!(*reference, Some(afrolink_pay::PaymentReference(880_123)));
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_substituted_transaction_fails_its_inclusion_proof() {
    let (path, store, state, _client, header, sent) = chain_with_payment("substitute");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        let fetched = get(addr, &format!("/v1/transactions/{}", sent.id().to_hex()));
        let Response::Transaction(honest) = decode_exact::<Response>(&fetched.body).unwrap() else {
            panic!("expected a transaction response");
        };

        // Rebuild the response with a different transaction and the real
        // receipt. The Merkle leaf is the transaction's own id, so this cannot
        // survive — and even if it could, the receipt names a different
        // transaction, which is checked separately.
        let mut wire = vec![4u8]; // Response::Transaction
        honest.height().encode(&mut wire);
        honest.index_unverified().encode(&mut wire);
        1u32.encode(&mut wire);
        payment(9).encode(&mut wire);
        Vec::<afrolink_crypto::hash::Hash32>::new().encode(&mut wire);
        honest.receipt_unverified().encode(&mut wire);
        Vec::<afrolink_crypto::hash::Hash32>::new().encode(&mut wire);

        let forged = decode_exact::<Response>(&wire).unwrap();
        let Response::Transaction(forged) = forged else {
            panic!("expected a transaction response");
        };
        assert!(
            forged.verify(&header).is_err(),
            "a substituted transaction must not verify"
        );
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_block_body_lets_a_client_check_it_received_all_of_it() {
    // The difference between `Query::Block` and `Query::Transaction`: here the
    // client recomputes the root itself, so a node cannot serve a subset.
    let (path, store, state, _client, header, sent) = chain_with_payment("block-body");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        let fetched = get(addr, "/v1/blocks/1/transactions");
        assert_eq!(fetched.status, 200);
        let Response::Block(block) = decode_exact::<Response>(&fetched.body).unwrap() else {
            panic!("expected a block response");
        };

        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].id(), sent.id());
        assert_eq!(
            afrolink_executor::Block::tx_root(&block.transactions),
            header.tx_root,
            "the body must reconstruct the root the header committed to"
        );
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_node_without_an_index_says_so_rather_than_reporting_no_payments() {
    // The distinction that matters: "I do not index history" and "you have
    // received nothing" are different answers, and a wallet that cannot tell
    // them apart will show a user an empty account.
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();
    let view = Unindexed;

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        let reply = get(
            addr,
            &format!("/v1/accounts/{}/history", account(60).to_bech32().unwrap()),
        );
        assert_eq!(reply.status, 501, "{}", reply.text());
        assert!(
            reply.text().contains("does not maintain"),
            "{}",
            reply.text()
        );
    });
}

/// A node that answers reads but keeps no history index.
struct Unindexed;

impl afrolink_rpc::ChainView for Unindexed {
    fn chain_id(&self) -> &ChainId {
        static ID: std::sync::OnceLock<ChainId> = std::sync::OnceLock::new();
        ID.get_or_init(chain)
    }
    fn tip_height(&self) -> Result<Height, afrolink_rpc::QueryError> {
        Ok(Height::GENESIS)
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
        Err(afrolink_rpc::QueryError::Backend("no state".into()))
    }
    fn block(
        &self,
        _height: Height,
    ) -> Result<Option<afrolink_executor::Block>, afrolink_rpc::QueryError> {
        Ok(None)
    }
    fn receipts(
        &self,
        _height: Height,
    ) -> Result<Option<Vec<afrolink_executor::TxReceipt>>, afrolink_rpc::QueryError> {
        Ok(None)
    }
    fn locate(
        &self,
        _id: &afrolink_crypto::hash::Hash32,
    ) -> Result<Option<(Height, u32)>, afrolink_rpc::QueryError> {
        Ok(None)
    }
    fn history(
        &self,
        _address: &Address,
        _from: Height,
        _limit: usize,
    ) -> Result<Option<(Vec<afrolink_rpc::HistoryEntry>, bool)>, afrolink_rpc::QueryError> {
        Ok(None)
    }
}

#[test]
fn an_unknown_transaction_id_is_a_404() {
    with_server("unknown-tx", Config::default(), |addr| {
        let reply = get(addr, &format!("/v1/transactions/{}", "ab".repeat(32)));
        assert_eq!(reply.status, 404);
    });
}

// ---------------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------------

/// A node that accepts transactions, wired the way a real one would be.
fn live_node() -> afrolink_node::SharedNode {
    use afrolink_executor::{Genesis, GenesisLimits};

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
    let mut state = MemoryStore::new();
    let block = genesis.apply(&mut state, GenesisLimits::devnet()).unwrap();
    afrolink_node::SharedNode::new(afrolink_node::Node::new(
        chain(),
        key(1),
        validators(),
        state,
        &block,
    ))
}

fn post(addr: SocketAddr, target: &str, body: &[u8]) -> Reply {
    let mut request = format!(
        "POST {target} HTTP/1.1\r\nHost: n\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);

    let mut conn = Conn::open(addr);
    conn.writer.write_all(&request).unwrap();
    conn.writer.flush().unwrap();
    conn.recv()
}

#[test]
fn a_wallet_can_send_money_and_the_node_holds_it() {
    let (path, store, state, _client) = chain_on_disk("submit");
    let view = ServedChain::new(chain(), &store, &state);
    let node = live_node();
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &node).unwrap());
        let _stop = handle.clone().stop_on_drop();

        let sent = payment(0);
        let reply = post(addr, "/v1/transactions", &sent.to_bytes());

        // 202, not 200: the node holds it, no block contains it. A wallet that
        // reads acceptance as settlement tells someone their money arrived.
        assert_eq!(reply.status, 202, "{}", reply.text());
        assert!(
            reply.text().contains(&sent.id().to_hex()),
            "{}",
            reply.text()
        );
        assert!(reply.text().contains("pending"), "{}", reply.text());

        assert!(node.lock().unwrap().is_pending(&sent.id()));
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_rejected_transaction_is_answered_with_a_reason_the_wallet_can_act_on() {
    let (path, store, state, _client) = chain_on_disk("reject");
    let view = ServedChain::new(chain(), &store, &state);
    let node = live_node();
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &node).unwrap());
        let _stop = handle.clone().stop_on_drop();

        // Signed for a different chain — the classic way a wallet pointed at
        // the wrong network loses money on other chains.
        let wrong = afrolink_types::TxBody {
            chain_id: ChainId::new("some-other-chain").unwrap(),
            sender: account(50),
            nonce: 0,
            valid_until: Height(10_000),
            fee: afrolink_types::Fee::new(Amount::from_units(1_000), kes()),
            messages: vec![afrolink_types::Message::WithdrawUnbonded],
            memo: String::new(),
        }
        .sign(&key(50));

        let reply = post(addr, "/v1/transactions", &wrong.to_bytes());
        assert_eq!(reply.status, 400, "{}", reply.text());
        assert!(reply.text().contains("chain"), "{}", reply.text());
        assert_eq!(node.lock().unwrap().pending(), 0);
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_transaction_with_trailing_bytes_is_refused() {
    // Two encodings of one payment is the malleability the codec exists to
    // prevent, and a submission endpoint is exactly where it would arrive.
    let (path, store, state, _client) = chain_on_disk("trailing");
    let view = ServedChain::new(chain(), &store, &state);
    let node = live_node();
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &node).unwrap());
        let _stop = handle.clone().stop_on_drop();

        let mut bytes = payment(0).to_bytes();
        bytes.push(0);
        let reply = post(addr, "/v1/transactions", &bytes);

        assert_eq!(reply.status, 400, "{}", reply.text());
        assert!(reply.text().contains("canonical"), "{}", reply.text());
        assert_eq!(node.lock().unwrap().pending(), 0);
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_read_only_node_refuses_submissions_rather_than_dropping_them() {
    // A serving node with no consensus role is a legitimate deployment. What it
    // must not do is accept a payment and silently discard it.
    with_server("readonly", Config::default(), |addr| {
        let reply = post(addr, "/v1/transactions", &payment(0).to_bytes());
        assert_eq!(reply.status, 501, "{}", reply.text());
        assert!(reply.text().contains("validator"), "{}", reply.text());
    });
}

#[test]
fn an_empty_submission_is_refused_before_it_reaches_the_node() {
    with_server("empty-submit", Config::default(), |addr| {
        let reply = post(addr, "/v1/transactions", b"");
        assert_eq!(reply.status, 400, "{}", reply.text());
    });
}

// ---------------------------------------------------------------------------
// The provable history chain
// ---------------------------------------------------------------------------

/// Genesis plus `count` blocks, each carrying one payment from 50 to 60.
///
/// Separate blocks on purpose: the walk crosses headers, which is where a
/// wallet's work actually is.
fn chain_with_payments(
    name: &str,
    count: u64,
) -> (
    std::path::PathBuf,
    ChainStore,
    MemoryStore,
    Vec<afrolink_types::Transaction>,
) {
    use afrolink_executor::{Executor, ValidatorSets};

    let (path, store, mut state, _client) = chain_on_disk(name);
    let mut parent = store.block(Height::GENESIS).unwrap().unwrap();
    let executor = Executor::new(chain());
    let mut sent = Vec::new();

    for nonce in 0..count {
        let payment = payment(nonce);
        let (block, outcome) = executor.build_block(
            &mut state,
            parent.header.height.next(),
            Timestamp::from_millis(1_700_000_000_000 + (nonce + 1) * 1_000),
            parent.header.id(),
            vec![payment.clone()],
            ValidatorSets::unchanged(&validators()),
        );
        assert_eq!(outcome.succeeded(), 1, "fixture payment {nonce} must apply");

        let commit = commit_for(&block);
        let receipts: Vec<afrolink_executor::TxReceipt> =
            outcome.outcomes.iter().map(|o| o.receipt.clone()).collect();
        store.put_block(&block, &commit, &receipts).unwrap();
        sent.push(payment);
        parent = block;
    }
    store.persist_state(&state).unwrap();

    (path, store, state, sent)
}

/// Fetch a header and check its commit, the way a wallet would.
fn verified_header(addr: SocketAddr, height: Height) -> afrolink_executor::BlockHeader {
    let reply = get(addr, &format!("/v1/blocks/{}", height.0));
    assert_eq!(reply.status, 200, "{}", reply.text());
    let Response::Header(signed) = decode_exact::<Response>(&reply.body).unwrap() else {
        panic!("expected a header response");
    };
    signed
        .verify(&chain(), &validators())
        .expect("the commit must carry a quorum");
    signed.header
}

fn fetch_transaction(addr: SocketAddr, id: &afrolink_crypto::hash::Hash32) -> ProvedTransaction {
    let reply = get(addr, &format!("/v1/transactions/{}", id.to_hex()));
    assert_eq!(reply.status, 200, "{}", reply.text());
    let Response::Transaction(proved) = decode_exact::<Response>(&reply.body).unwrap() else {
        panic!("expected a transaction response");
    };
    *proved
}

// ---------------------------------------------------------------------------
// Key rotation and signer lists, end to end (ADR-0017)
// ---------------------------------------------------------------------------

#[test]
fn a_wallet_can_prove_who_may_sign_for_an_account() {
    // Authorisation left stateless verification and became a fact about the
    // account record. That record is served with a proof, so a wallet — or an
    // exchange deciding whether a withdrawal request is genuine — can establish
    // which keys are entitled to act, against a header it verified itself.
    use afrolink_types::{AccountFlag, Message, Signer, SignerList};

    let (path, store, mut state, _client) = chain_on_disk("authority");
    let executor = afrolink_executor::Executor::new(chain());
    let parent = store.block(Height::GENESIS).unwrap().unwrap();

    let list = SignerList::new(
        (11..=13u8)
            .map(|s| Signer {
                key: key(s).public_key(),
                weight: 1,
            })
            .collect(),
        2,
    )
    .unwrap();

    let rotate = afrolink_types::TxBody {
        chain_id: chain(),
        sender: account(50),
        nonce: 0,
        valid_until: Height(10_000),
        fee: afrolink_types::Fee::new(Amount::from_units(1_000), kes()),
        messages: vec![
            Message::SetRegularKey {
                key: Some(key(9).public_key()),
            },
            Message::SetSignerList {
                list: Some(list.clone()),
            },
            Message::SetAccountFlag {
                flag: AccountFlag::MasterKeyDisabled,
                enabled: true,
            },
        ],
        memo: String::new(),
    }
    .sign(&key(50));

    let (block, outcome) = executor.build_block(
        &mut state,
        Height(1),
        Timestamp::from_millis(1_700_000_001_000),
        parent.header.id(),
        vec![rotate],
        afrolink_executor::ValidatorSets::unchanged(&validators()),
    );
    assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
    let receipts: Vec<afrolink_executor::TxReceipt> =
        outcome.outcomes.iter().map(|o| o.receipt.clone()).collect();
    store
        .put_block(&block, &commit_for(&block), &receipts)
        .unwrap();
    store.persist_state(&state).unwrap();

    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        let _stop = handle.clone().stop_on_drop();

        let tip = verified_header(addr, Height(1));
        let client = afrolink_light::LightClient::new(chain(), validators(), tip);
        let record = read_account(addr, &client, account(50)).expect("the account exists");

        // The master key is retired, and a wallet can see that rather than
        // being told it by a node.
        assert!(
            !record.authorises(&[key(50).public_key()]),
            "the disabled master key must not authorise"
        );
        assert!(record.authorises(&[key(9).public_key()]));
        assert!(record.authorises(&[key(11).public_key(), key(12).public_key()]));
        assert!(
            !record.authorises(&[key(11).public_key()]),
            "one signer is not the quorum"
        );
        assert_eq!(record.signers.as_ref(), Some(&list));
    });

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// RequireDestinationTag, end to end (ADR-0016)
// ---------------------------------------------------------------------------

/// Genesis, a payment that funds the exchange, the exchange flagging itself, and
/// an untagged deposit that the ledger refuses.
///
/// Returns the id of the refused deposit, because the interesting artefact is
/// its **receipt**: the reason for the failure is committed, not asserted by
/// whichever node the wallet happened to ask.
fn chain_with_a_tag_requiring_exchange(
    name: &str,
) -> (
    std::path::PathBuf,
    ChainStore,
    MemoryStore,
    afrolink_crypto::hash::Hash32,
) {
    use afrolink_executor::{Executor, ValidatorSets};
    use afrolink_types::{AccountFlag, Fee, Message, TxBody};

    let (path, store, mut state, _client) = chain_on_disk(name);
    let mut parent = store.block(Height::GENESIS).unwrap().unwrap();
    let executor = Executor::new(chain());

    let flag = TxBody {
        chain_id: chain(),
        sender: account(60),
        nonce: 0,
        valid_until: Height(10_000),
        fee: Fee::new(Amount::from_units(1_000), kes()),
        messages: vec![Message::SetAccountFlag {
            flag: AccountFlag::RequireReference,
            enabled: true,
        }],
        memo: String::new(),
    }
    .sign(&key(60));

    let untagged = TxBody {
        chain_id: chain(),
        sender: account(50),
        nonce: 1,
        valid_until: Height(10_000),
        fee: Fee::new(Amount::from_units(1_000), kes()),
        messages: vec![Message::Transfer {
            to: account(60),
            denom: kes(),
            amount: Amount::from_afri(7),
            reference: None,
        }],
        memo: String::new(),
    }
    .sign(&key(50));
    let refused = untagged.id();

    // Block 1 funds the exchange, block 2 flags it, block 3 is the mistake.
    let blocks = [
        (vec![payment(0)], 1u64),
        (vec![flag], 1),
        (vec![untagged], 0),
    ];
    for (transactions, expect_succeeded) in blocks {
        let (block, outcome) = executor.build_block(
            &mut state,
            parent.header.height.next(),
            Timestamp::from_millis(1_700_000_000_000 + parent.header.height.next().0 * 1_000),
            parent.header.id(),
            transactions,
            ValidatorSets::unchanged(&validators()),
        );
        assert_eq!(
            outcome.succeeded() as u64,
            expect_succeeded,
            "fixture block {} did not behave as intended: {:?}",
            block.header.height.0,
            outcome.outcomes[0].result
        );
        let receipts: Vec<afrolink_executor::TxReceipt> =
            outcome.outcomes.iter().map(|o| o.receipt.clone()).collect();
        store
            .put_block(&block, &commit_for(&block), &receipts)
            .unwrap();
        parent = block;
    }
    store.persist_state(&state).unwrap();

    (path, store, state, refused)
}

#[test]
fn a_wallet_can_prove_an_address_requires_a_reference_before_it_pays() {
    // The half of the flag that makes it usable rather than merely correct. A
    // warning a wallet shows *before* sending is the only warning that helps,
    // and it has to be provable — a node that lied in either direction would
    // otherwise be able to make a payment fail, or make a wallet skip the
    // prompt on an address that genuinely needs one.
    let (path, store, state, _refused) = chain_with_a_tag_requiring_exchange("requires-flag");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        let _stop = handle.clone().stop_on_drop();

        let tip = verified_header(addr, Height(3));
        let client = afrolink_light::LightClient::new(chain(), validators(), tip);

        let flagged = read_account(addr, &client, account(60)).expect("the exchange has a record");
        assert_eq!(
            flagged.requires_reference(),
            afrolink_pay::RequiresReference::Yes,
            "the wallet must be able to see the requirement, with a proof"
        );

        let ordinary = read_account(addr, &client, account(50)).expect("the payer has a record");
        assert_eq!(
            ordinary.requires_reference(),
            afrolink_pay::RequiresReference::No,
            "and must not see one where there is none"
        );
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_reason_an_untagged_deposit_failed_is_itself_proved() {
    // "You forgot the reference" arrives as a committed receipt rather than as
    // a node's opinion. That matters because it is the one failure the sender
    // can act on, and acting on it means resending money.
    let (path, store, state, refused) = chain_with_a_tag_requiring_exchange("requires-receipt");
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        let _stop = handle.clone().stop_on_drop();

        let header = verified_header(addr, Height(3));
        let proved = fetch_transaction(addr, &refused);
        let effects = proved
            .verify(&header)
            .expect("the receipt must prove against outcome_root");

        assert_eq!(
            effects.receipt.code,
            afrolink_executor::ResultCode::Reference,
            "the ledger committed to *why* it refused"
        );
        assert!(
            effects.receipt.previous_for(&account(60)).is_err(),
            "a refused deposit must not appear in the exchange's history"
        );
    });

    let _ = std::fs::remove_file(&path);
}

/// Fetch an account record and verify it against a header the wallet trusts.
fn read_account(
    addr: SocketAddr,
    client: &afrolink_light::LightClient,
    address: Address,
) -> Option<afrolink_types::Account> {
    let query = Query::Account { address };
    let reply = get(
        addr,
        &format!("/v1/accounts/{}", address.to_bech32().unwrap()),
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
    let Response::Value(proved) = decode_exact::<Response>(&reply.body).unwrap() else {
        panic!("expected a value response");
    };
    proved
        .verify(client, &query.store_key().unwrap())
        .unwrap()
        .map(|bytes| decode_exact::<afrolink_types::Account>(bytes).unwrap())
}

#[test]
fn a_wallet_walks_its_whole_history_and_knows_when_it_has_all_of_it() {
    // The claim ADR-0014 could not make. Every link is committed: the account's
    // pointer is in state, and each receipt is in `outcome_root`. Reaching the
    // end means the history is complete, not merely that the server stopped.
    let (path, store, state, sent) = chain_with_payments("walk", 3);
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        // The recipient's account record, proved against the tip.
        let tip = verified_header(addr, Height(3));
        let query = Query::Account {
            address: account(60),
        };
        let reply = get(
            addr,
            &format!("/v1/accounts/{}", account(60).to_bech32().unwrap()),
        );
        let Response::Value(proved) = decode_exact::<Response>(&reply.body).unwrap() else {
            panic!("expected a value response");
        };
        let client = afrolink_light::LightClient::new(chain(), validators(), tip.clone());
        let bytes = proved
            .verify(&client, &query.store_key().unwrap())
            .unwrap()
            .expect("the recipient has an account record");
        let record = decode_exact::<afrolink_types::Account>(bytes).unwrap();

        // Walk it.
        let mut cursor = HistoryCursor::new(account(60), &record);
        let mut walked = Vec::new();
        while let Some(pointer) = cursor.next_pointer() {
            let header = verified_header(addr, pointer.height);
            let proved = fetch_transaction(addr, &pointer.tx_id);
            let transaction = cursor.step(&proved, &header).expect("the chain must hold");
            walked.push(transaction.id());
        }

        assert!(cursor.complete(), "the walk reached the end of the chain");
        assert_eq!(cursor.seen(), 3);

        // Newest first, and every payment accounted for.
        let expected: Vec<_> = sent
            .iter()
            .rev()
            .map(afrolink_types::Transaction::id)
            .collect();
        assert_eq!(walked, expected);
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_node_that_skips_a_payment_is_caught_rather_than_believed() {
    // The attack ADR-0014 admitted it could not detect: hide one payment. With
    // the chain committed, skipping a link means answering with a transaction
    // the committed pointer did not name.
    let (path, store, state, sent) = chain_with_payments("skip", 3);
    let view = ServedChain::new(chain(), &store, &state);
    let server = Server::bind("127.0.0.1:0", Config::default()).unwrap();
    let handle = server.handle();
    let addr = server.local_addr();

    std::thread::scope(|scope| {
        scope.spawn(|| server.run(&view, &ReadOnly).unwrap());
        // Stops the server even if an assertion below panics. Without it a
        // failed test hangs in the scope's join rather than reporting.
        let _stop = handle.clone().stop_on_drop();

        let tip = verified_header(addr, Height(3));
        let client = afrolink_light::LightClient::new(chain(), validators(), tip);
        let query = Query::Account {
            address: account(60),
        };
        let reply = get(
            addr,
            &format!("/v1/accounts/{}", account(60).to_bech32().unwrap()),
        );
        let Response::Value(proved) = decode_exact::<Response>(&reply.body).unwrap() else {
            panic!("expected a value response");
        };
        let record = decode_exact::<afrolink_types::Account>(
            proved
                .verify(&client, &query.store_key().unwrap())
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let mut cursor = HistoryCursor::new(account(60), &record);

        // First step honestly, to reach the middle of the chain.
        let pointer = cursor.next_pointer().unwrap();
        let header = verified_header(addr, pointer.height);
        cursor
            .step(&fetch_transaction(addr, &pointer.tx_id), &header)
            .unwrap();

        // Now a hostile server skips the second payment and offers the first.
        // Every proof it supplies is genuine — the transaction really is in its
        // block. It is the *link* that fails.
        let skipped_to = sent[0].id();
        let pointer = cursor.next_pointer().unwrap();
        assert_ne!(
            pointer.tx_id, skipped_to,
            "the fixture must actually skip one"
        );

        let substitute = fetch_transaction(addr, &skipped_to);
        let substitute_header = verified_header(addr, Height(1));
        let error = cursor.step(&substitute, &substitute_header).unwrap_err();

        assert!(
            matches!(error, afrolink_rpc::HistoryError::WrongHeight { .. }),
            "a skipped link must not verify, got {error:?}"
        );

        // And the wallet knows it did not finish, which is the whole point: it
        // shows an error rather than a short history.
        assert!(!cursor.complete());
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_account_that_never_transacted_has_a_complete_empty_history() {
    // A proved absence is a complete history of length zero. Distinguishing it
    // from "the server declined" is the reason `complete()` exists.
    let cursor = HistoryCursor::empty(account(77));
    assert!(cursor.complete());
    assert_eq!(cursor.seen(), 0);
    assert_eq!(cursor.next_pointer(), None);
}

#[test]
fn a_receipt_proves_a_failed_transaction_failed() {
    // Without a committed outcome a node can claim your payment failed when it
    // succeeded, or the reverse. The code is coarse on purpose — it names the
    // subsystem that refused, not the detail — but it is committed.
    use afrolink_executor::{Executor, ResultCode, ValidatorSets};

    let (path, store, mut state, _client) = chain_on_disk("failed");
    let genesis_block = store.block(Height::GENESIS).unwrap().unwrap();

    // Account 60 has nothing, so its transfer cannot be funded.
    let broke = afrolink_types::TxBody {
        chain_id: chain(),
        sender: account(60),
        nonce: 0,
        valid_until: Height(10_000),
        fee: afrolink_types::Fee::new(Amount::ZERO, kes()),
        messages: vec![afrolink_types::Message::Transfer {
            to: account(50),
            denom: kes(),
            amount: Amount::from_afri(1_000_000),
            reference: None,
        }],
        memo: String::new(),
    }
    .sign(&key(60));

    let executor = Executor::new(chain());
    let (block, outcome) = executor.build_block(
        &mut state,
        Height(1),
        Timestamp::from_millis(1_700_000_001_000),
        genesis_block.header.id(),
        vec![broke.clone()],
        ValidatorSets::unchanged(&validators()),
    );
    assert_eq!(outcome.succeeded(), 0, "the fixture payment must fail");

    let receipt = &outcome.outcomes[0].receipt;
    assert_eq!(receipt.code, ResultCode::Bank, "the bank refused it");
    assert_eq!(
        block.header.outcome_root,
        outcome.outcome_root(),
        "the header must commit to what happened, not only to what ran"
    );

    // A failed transfer moves the sender's history but not the recipient's:
    // otherwise anyone could write into a stranger's history by failing to pay
    // them.
    let touched: Vec<_> = receipt.touched.iter().map(|t| t.address).collect();
    assert!(touched.contains(&account(60)), "the sender paid a nonce");
    assert!(
        !touched.contains(&account(50)),
        "a failed payment must not appear in the intended recipient's history"
    );

    let _ = std::fs::remove_file(&path);
}
