//! Hostile bytes against the HTTP parser.
//!
//! With [ADR-0013](../../../docs/adr/0013-http-transport.md) the request parser
//! became the largest untrusted-input surface in the workspace: it is the first
//! thing an anonymous peer reaches, and it runs before any signature, proof or
//! quorum check.
//!
//! Three properties. The first two are the codec suite's, in HTTP's clothing;
//! the third is the one that is specific to a streaming protocol.
//!
//! **Totality.** Arbitrary bytes must produce a `Request` or a `WireError`,
//! never a panic. A panic in this parser is a remote denial of service on a
//! validator, reachable without a key.
//!
//! **Unique reading.** If bytes parse, re-rendering the parsed request in
//! canonical form and parsing *that* must produce the same request — see
//! [`decodes_are_canonical`](afrolink_fuzz::decodes_are_canonical).
//!
//! **The boundary ignores what follows.** If bytes parse and leave `rest`
//! unread, then those bytes with anything appended must parse to the same
//! request and leave `rest` plus the appended bytes unread. *This* is the
//! property request smuggling violates. It is asserted separately because a
//! canonicalising renderer can hide a first-wins or last-wins mistake from the
//! round trip, and cannot hide a moved request boundary.
//!
//! Note what is *not* asserted: that the parser accepts everything a browser
//! might send. It should not. The refusals are unit-tested in `crates/http`;
//! here the concern is only that acceptance is unambiguous.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use std::io::{BufReader, Read};

use afrolink_fuzz::{Rng, mutate};
use afrolink_http::Config;
use afrolink_http::wire::{Method, Request, read_request};

/// Requests a real client would send, used as mutation seeds. Structure-aware
/// mutation reaches decoder paths that uniform noise never does, because noise
/// almost never gets past the request line.
const SEEDS: &[&str] = &[
    "GET / HTTP/1.1\r\nHost: node\r\n\r\n",
    "GET /health HTTP/1.1\r\nHost: node\r\nConnection: close\r\n\r\n",
    "GET /v1/status HTTP/1.1\r\nHost: node\r\nAccept: application/json\r\n\r\n",
    "GET /v1/supply?denom=sov/ke/kes HTTP/1.1\r\nHost: node\r\n\r\n",
    "GET /v1/accounts/afri1qqqq/balance?denom=afri&format=json HTTP/1.1\r\nHost: n\r\n\r\n",
    "GET /v1/names/amina HTTP/1.1\r\nHost: node\r\nUser-Agent: curl/8.0\r\n\r\n",
    "GET /v1/contacts/00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff HTTP/1.1\r\nHost: n\r\n\r\n",
    "POST /v1/query HTTP/1.1\r\nHost: node\r\nContent-Length: 1\r\n\r\n\x00",
    "POST /v1/query HTTP/1.1\r\nHost: node\r\nContent-Length: 0\r\n\r\n",
    "OPTIONS /v1/query HTTP/1.1\r\nHost: n\r\nOrigin: https://x.example\r\n\r\n",
    "GET /v1/blocks/12345 HTTP/1.0\r\nHost: node\r\n\r\n",
    "GET /a%2Fb?k=%20v HTTP/1.1\r\nHost: node\r\n\r\n",
];

fn parse(bytes: &[u8]) -> Option<Request> {
    let mut reader = BufReader::new(bytes);
    read_request(&mut reader, &Config::default()).ok()
}

/// Parse, and report what was left unread.
fn parse_leaving(bytes: &[u8]) -> Option<(Request, Vec<u8>)> {
    let mut reader = BufReader::new(bytes);
    let request = read_request(&mut reader, &Config::default()).ok()?;
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).ok()?;
    Some((request, rest))
}

/// Percent-encode everything outside RFC 3986 `unreserved`.
///
/// Deliberately aggressive: a delimiter that survives into a rendered target is
/// exactly how a round trip would appear to succeed while meaning something
/// else.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02x}"));
        }
    }
    out
}

/// Render a parsed request back into canonical wire bytes.
fn render(request: &Request) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(match request.method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Options => "OPTIONS",
    });
    out.push(' ');
    out.push('/');
    let path: Vec<String> = request.segments.iter().map(|s| encode(s)).collect();
    out.push_str(&path.join("/"));

    if !request.params.is_empty() {
        out.push('?');
        let pairs: Vec<String> = request
            .params
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
            .collect();
        out.push_str(&pairs.join("&"));
    }

    out.push_str(" HTTP/1.1\r\n");
    for (name, value) in &request.headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&request.body);
    bytes
}

/// Everything a parsed request means, except the one field derived from the
/// version — which `render` always writes as 1.1 and which has its own tests.
#[derive(Debug, PartialEq, Eq)]
struct Meaning {
    method: Method,
    segments: Vec<String>,
    params: Vec<(String, String)>,
    body: Vec<u8>,
}

fn meaning(request: &Request) -> Meaning {
    Meaning {
        method: request.method,
        segments: request.segments.clone(),
        params: request
            .params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        body: request.body.clone(),
    }
}

/// The property: acceptance is unambiguous.
fn one_reading(label: &str, bytes: &[u8]) {
    let Some(first) = parse(bytes) else {
        // A refusal is always an acceptable outcome. The parser is allowed to
        // be as strict as it likes; it is not allowed to be ambiguous.
        return;
    };

    let rendered = render(&first);
    let Some(second) = parse(&rendered) else {
        panic!(
            "{label}: a parsed request did not survive being written back out\n\
             original: {:?}\nrendered: {:?}",
            String::from_utf8_lossy(bytes),
            String::from_utf8_lossy(&rendered)
        );
    };

    assert_eq!(
        meaning(&first),
        meaning(&second),
        "{label}: two readings of one request\n  original: {:?}\n  rendered: {:?}",
        String::from_utf8_lossy(bytes),
        String::from_utf8_lossy(&rendered)
    );

    // Headers survive a round trip too, which is what keeps `Content-Length`
    // and `Connection` from being reinterpreted on the way back.
    assert_eq!(
        first.headers, second.headers,
        "{label}: headers changed meaning on re-parse"
    );

    // Structural invariants that must hold for *anything* the parser accepted.
    assert!(
        !first.headers.contains_key("transfer-encoding"),
        "{label}: a request with Transfer-Encoding was accepted"
    );
    assert!(
        first.segments.iter().all(|s| !s.is_empty()),
        "{label}: an empty path segment survived"
    );
    assert!(
        first
            .headers
            .keys()
            .all(|k| k.chars().all(|c| !c.is_ascii_uppercase())),
        "{label}: a header name was not folded to lower case"
    );
    if let Some(declared) = first.headers.get("content-length") {
        let declared: usize = declared.parse().expect("accepted a non-numeric length");
        assert_eq!(
            first.body.len(),
            declared,
            "{label}: body length disagrees with Content-Length"
        );
    } else {
        assert!(
            first.body.is_empty(),
            "{label}: a body arrived without a Content-Length"
        );
    }
}

/// **The smuggling property**, stated directly.
///
/// A request's boundary must be determined by the request itself and by nothing
/// that follows it. So: if `bytes` parses and leaves `rest` unread, then
/// `bytes || suffix` must parse to the *same* request and leave exactly
/// `rest || suffix` unread.
///
/// Every desync is a violation of this. A front end and a back end that agree
/// on this property cannot disagree about where one request ends and the next
/// begins, whatever they disagree about otherwise — which is why it is worth
/// asserting separately from the round trip, where a canonicalising renderer
/// can hide a last-wins or first-wins mistake.
fn boundary_ignores_what_follows(label: &str, bytes: &[u8], suffix: &[u8]) {
    let Some((first, rest)) = parse_leaving(bytes) else {
        return;
    };

    let mut extended = bytes.to_vec();
    extended.extend_from_slice(suffix);

    let Some((second, tail)) = parse_leaving(&extended) else {
        panic!(
            "{label}: appending bytes turned a valid request invalid\n  request: {:?}",
            String::from_utf8_lossy(bytes)
        );
    };

    assert_eq!(
        meaning(&first),
        meaning(&second),
        "{label}: appending bytes changed what the request said\n  request: {:?}",
        String::from_utf8_lossy(bytes)
    );

    let mut expected = rest;
    expected.extend_from_slice(suffix);
    assert_eq!(
        tail,
        expected,
        "{label}: the request boundary moved when bytes were appended\n  request: {:?}",
        String::from_utf8_lossy(bytes)
    );
}

#[test]
fn the_seeds_themselves_have_one_reading() {
    for seed in SEEDS {
        one_reading("seed", seed.as_bytes());
    }
}

#[test]
fn mutated_requests_are_never_ambiguous_and_never_panic() {
    // ~36 000 inputs: each seed, mutated, then mutated again so two independent
    // corruptions can interact — which is where framing bugs actually live.
    let mut rng = Rng::new(0x48_54_54_50_00_00_00_01);
    for round in 0..3_000u64 {
        for seed in SEEDS {
            let once = mutate(&mut rng, seed.as_bytes());
            one_reading(&format!("mutate/{round}"), &once);

            let twice = mutate(&mut rng, &once);
            one_reading(&format!("mutate2/{round}"), &twice);
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic_the_parser() {
    // Uniform noise finds little, but "little" is not "nothing", and a panic
    // here is a remote denial of service reachable without any key at all.
    let mut rng = Rng::new(0x48_54_54_50_00_00_00_02);
    for _ in 0..20_000u32 {
        let blob = rng.blob(256);
        let _ = parse(&blob);
    }
}

#[test]
fn a_request_spliced_from_two_others_is_still_read_only_one_way() {
    // The shape of a smuggling attempt: bytes that one parser splits into two
    // requests. Splicing seeds together generates that shape directly rather
    // than waiting for random mutation to stumble into it.
    let mut rng = Rng::new(0x48_54_54_50_00_00_00_03);
    for round in 0..4_000u64 {
        let left = SEEDS[rng.below(SEEDS.len())];
        let right = SEEDS[rng.below(SEEDS.len())];
        let cut = rng.below(left.len().saturating_add(1));

        let mut spliced = left.as_bytes()[..cut].to_vec();
        spliced.extend_from_slice(right.as_bytes());
        one_reading(&format!("splice/{round}"), &spliced);

        // And the same with a mutation on top, so the join is not always at a
        // byte boundary a real client would produce.
        let mutated = mutate(&mut rng, &spliced);
        one_reading(&format!("splice-mutate/{round}"), &mutated);
    }
}

#[test]
fn a_requests_boundary_never_depends_on_what_comes_after_it() {
    // The property in its natural habitat: a second, complete request appended
    // to the first. If the parser can be talked into consuming part of it — or
    // into stopping short and leaving a fragment that reads as a request — the
    // two ends of a proxy chain disagree, and that is a desync.
    let mut rng = Rng::new(0x48_54_54_50_00_00_00_04);

    for round in 0..3_000u64 {
        let seed = SEEDS[rng.below(SEEDS.len())];
        let follower = SEEDS[rng.below(SEEDS.len())];

        // A whole request as the suffix — the shape of the attack.
        boundary_ignores_what_follows(
            &format!("append-request/{round}"),
            seed.as_bytes(),
            follower.as_bytes(),
        );

        // Random noise, which catches a parser that reads past its own end for
        // reasons unrelated to framing.
        let noise = rng.blob(32);
        boundary_ignores_what_follows(&format!("append-noise/{round}"), seed.as_bytes(), &noise);

        // And a mutated request as the head, so the property is tested on the
        // odd corners the parser still accepts rather than only on clean input.
        let mutated = mutate(&mut rng, seed.as_bytes());
        boundary_ignores_what_follows(
            &format!("append-to-mutant/{round}"),
            &mutated,
            follower.as_bytes(),
        );
    }
}

#[test]
fn a_header_block_of_pure_noise_is_bounded_rather_than_buffered() {
    // The limits are what stop a peer from turning one connection into
    // unbounded memory. Asserted against the parser directly, because the
    // socket-level version of this test cannot distinguish "refused" from
    // "still reading".
    let config = Config {
        max_headers: 8,
        max_header_bytes: 256,
        ..Config::default()
    };
    let mut raw = String::from("GET / HTTP/1.1\r\n");
    for i in 0..1_000 {
        raw.push_str(&format!("x-pad-{i}: {}\r\n", "a".repeat(64)));
    }
    raw.push_str("\r\n");

    let mut reader = BufReader::new(raw.as_bytes());
    assert!(
        read_request(&mut reader, &config).is_err(),
        "a thousand headers were accepted under a limit of eight"
    );
}
