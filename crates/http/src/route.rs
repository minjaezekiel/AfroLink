//! Mapping a path to a [`Query`]. Pure, and therefore testable without a socket.
//!
//! # Shape
//!
//! The route table follows the Cosmos SDK's REST layout closely enough to be
//! guessable — `/v1/accounts/{address}/balance?denom=` rather than an invented
//! scheme — because familiarity is the entire argument of
//! [ADR-0009](../../../docs/adr/0009-developer-payment-surface.md).
//!
//! The subject of a query goes in the path; everything else goes in the query
//! string. That is not only aesthetic: a sovereign denomination is spelled
//! `sov/ke/kes`, and a value containing a slash in a path segment is a
//! percent-encoded `%2F` that intermediaries are famous for mangling. In a
//! query string it needs no encoding at all.
//!
//! # Parsing is the trust boundary
//!
//! Every path segment and parameter goes through the same constructors the
//! chain uses — [`Address::from_bech32`], [`Denom::new`], [`Username::new`] —
//! so an address that reaches [`Query`] has a valid checksum and a name that
//! reaches it has already been refused if it is confusable. There is no
//! second, laxer parser here, which is the mistake that makes two components
//! disagree about what a request said.

use std::collections::BTreeMap;

use afrolink_alias::{ContactCommitment, Username};
use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_primitives::codec::decode_exact;
use afrolink_primitives::{Denom, Height};
use afrolink_rpc::{MAX_HISTORY, Query};

use crate::wire::{Method, Request, Status};

/// How the answer should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The canonical codec — the default, and what a wallet should use.
    Binary,
    /// The developer view. Opt-in, and still proof-carrying.
    Json,
}

/// What a request resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `POST /v1/transactions` — a canonically-encoded transaction to submit.
    ///
    /// The only route that *changes* anything, and it is deliberately the only
    /// one: everything else on this server is a read. It is handled through a
    /// separate trait from [`ChainView`](afrolink_rpc::ChainView), so the
    /// guarantee that a query cannot reach a node's mempool stays structural.
    Submit(Vec<u8>),
    /// `/` — the route table.
    Index,
    /// `/health` — liveness, answered from the store rather than from a
    /// constant, so a node with an unreadable database reports unhealthy.
    Health,
    /// Anything that becomes a chain query.
    Chain(Box<Query>),
    /// A CORS preflight.
    Preflight,
}

/// Why a request did not resolve to a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// No route matches this path.
    NotFound,
    /// The path exists, but not for this method.
    MethodNotAllowed {
        /// What the `Allow` header should say.
        allow: &'static str,
    },
    /// A parameter was missing or did not parse.
    BadRequest(String),
}

impl RouteError {
    /// The status to answer with.
    #[must_use]
    pub fn status(&self) -> Status {
        match self {
            Self::NotFound => Status::NotFound,
            Self::MethodNotAllowed { .. } => Status::MethodNotAllowed,
            Self::BadRequest(_) => Status::BadRequest,
        }
    }

    /// The message to show the client.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NotFound => "no such route; GET / lists them".to_owned(),
            Self::MethodNotAllowed { allow } => format!("method not allowed; try {allow}"),
            Self::BadRequest(why) => why.clone(),
        }
    }
}

fn bad(why: impl Into<String>) -> RouteError {
    RouteError::BadRequest(why.into())
}

/// Resolve a request to a route.
///
/// # Errors
/// [`RouteError`] when no route matches, the method is wrong, or a parameter
/// does not parse.
pub fn route(request: &Request) -> Result<Route, RouteError> {
    // A preflight is answered before routing. A browser sends it for
    // `POST /v1/query` because the content type is not one of the three that
    // avoid it, and refusing it would make the endpoint unusable from a page.
    if request.method == Method::Options {
        return Ok(Route::Preflight);
    }

    let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();

    match segments.as_slice() {
        [] => get_only(request, Route::Index),
        ["health"] => get_only(request, Route::Health),
        ["v1", "status"] => chain(request, Query::Status),
        ["v1", "blocks", height] => {
            let height = height
                .parse::<u64>()
                .map_err(|_| bad("height must be a whole number"))?;
            chain(
                request,
                Query::Header {
                    height: Height(height),
                },
            )
        }
        ["v1", "accounts", address] => {
            let address = parse_address(address)?;
            chain(request, Query::Account { address })
        }
        ["v1", "accounts", address, "balance"] => {
            let address = parse_address(address)?;
            let denom = required_denom(&request.params)?;
            chain(request, Query::Balance { address, denom })
        }
        ["v1", "accounts", address, "alias"] => {
            let address = parse_address(address)?;
            chain(request, Query::PrimaryAlias { address })
        }
        ["v1", "accounts", address, "frozen"] => {
            let address = parse_address(address)?;
            let denom = required_denom(&request.params)?;
            chain(request, Query::Frozen { denom, address })
        }
        ["v1", "supply"] => {
            let denom = required_denom(&request.params)?;
            chain(request, Query::Supply { denom })
        }
        ["v1", "issuer"] => {
            let denom = required_denom(&request.params)?;
            chain(request, Query::Issuer { denom })
        }
        ["v1", "names", raw] => {
            let name = parse_name(raw)?;
            chain(request, Query::ResolveName { name })
        }
        ["v1", "contacts", commitment] => {
            let commitment = parse_commitment(commitment)?;
            chain(request, Query::ResolveContact { commitment })
        }
        ["v1", "blocks", height, "transactions"] => {
            let height = height
                .parse::<u64>()
                .map_err(|_| bad("height must be a whole number"))?;
            chain(
                request,
                Query::Block {
                    height: Height(height),
                },
            )
        }
        ["v1", "transactions", id] => {
            let id = parse_hash(id, "transaction id")?;
            chain(request, Query::Transaction { id })
        }
        ["v1", "accounts", address, "history"] => {
            let address = parse_address(address)?;
            let from = match request.param("from") {
                None => Height::GENESIS,
                Some(raw) => Height(
                    raw.parse::<u64>()
                        .map_err(|_| bad("from must be a whole number"))?,
                ),
            };
            let limit = match request.param("limit") {
                None => MAX_HISTORY,
                Some(raw) => raw
                    .parse::<u32>()
                    .map_err(|_| bad("limit must be a whole number"))?,
            };
            chain(
                request,
                Query::History {
                    address,
                    from,
                    limit,
                },
            )
        }
        ["v1", "transactions"] => {
            if request.method != Method::Post {
                return Err(RouteError::MethodNotAllowed { allow: "POST" });
            }
            if request.body.is_empty() {
                return Err(bad("a transaction body is required"));
            }
            Ok(Route::Submit(request.body.clone()))
        }
        ["v1", "query"] => {
            if request.method != Method::Post {
                return Err(RouteError::MethodNotAllowed { allow: "POST" });
            }
            let query = decode_exact::<Query>(&request.body)
                .map_err(|e| bad(format!("body is not a canonical Query: {e}")))?;
            Ok(Route::Chain(Box::new(query)))
        }
        _ => Err(RouteError::NotFound),
    }
}

fn get_only(request: &Request, route: Route) -> Result<Route, RouteError> {
    if request.method == Method::Get {
        Ok(route)
    } else {
        Err(RouteError::MethodNotAllowed { allow: "GET" })
    }
}

fn chain(request: &Request, query: Query) -> Result<Route, RouteError> {
    get_only(request, Route::Chain(Box::new(query)))
}

fn parse_address(text: &str) -> Result<Address, RouteError> {
    Address::from_bech32(text).map_err(|e| bad(format!("invalid address: {e}")))
}

fn required_denom(params: &BTreeMap<String, String>) -> Result<Denom, RouteError> {
    let raw = params
        .get("denom")
        .ok_or_else(|| bad("this route needs a ?denom= parameter"))?;
    Denom::new(raw.clone()).map_err(|e| bad(format!("invalid denom: {e}")))
}

/// Parse a username, refusing any spelling the constructor would have to change.
///
/// [`Username::new`] lower-cases, because it is written for a caller assembling
/// a value. A URL is not that caller — it is a decode boundary, and the codec's
/// rule holds here too: **if it would have to be normalised, it is refused.**
///
/// This is the same defect the fuzzer found in `Username::decode`, in its other
/// natural habitat. Accepting `/v1/names/AMINA` would give one registration two
/// URLs — two cache entries, two log lines — and would let a wallet display
/// `@AMINA` for a record that says `amina`, on the screen whose whole job is
/// letting a user recognise who they are paying.
fn parse_name(raw: &str) -> Result<Username, RouteError> {
    let name = Username::new(raw).map_err(|e| bad(format!("invalid name: {e}")))?;
    if name.as_str() != raw {
        return Err(bad(format!(
            "name is not canonical; use {:?}",
            name.as_str()
        )));
    }
    Ok(name)
}

/// A 32-byte hash, spelled as 64 lower-case hex characters.
///
/// Same strictness as a commitment, and for the same reason: two spellings of
/// one transaction id are two cache keys and two log lines for one payment.
fn parse_hash(text: &str, what: &str) -> Result<Hash32, RouteError> {
    let bytes = parse_hash_bytes(text, what)?;
    Ok(Hash32::from_bytes(bytes))
}

fn parse_hash_bytes(text: &str, what: &str) -> Result<[u8; 32], RouteError> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(format!("{what} must be 64 hex characters")));
    }
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(bad(format!("{what} must be lower-case hex")));
    }
    let decoded = hex::decode(text).map_err(|_| bad(format!("{what} is not hex")))?;
    <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| bad(format!("{what} is not 32 bytes")))
}

/// A contact commitment is 32 bytes, spelled as 64 lower-case hex characters.
///
/// Upper case is refused rather than folded. Two spellings of one commitment
/// would be two cache keys and two log lines for one lookup, and the codec's
/// rule — one encoding per value — is worth keeping at the edge too.
fn parse_commitment(text: &str) -> Result<ContactCommitment, RouteError> {
    let bytes = parse_hash_bytes(text, "commitment")?;
    decode_exact::<ContactCommitment>(&bytes).map_err(|_| bad("commitment is not 32 bytes"))
}

/// Decide how to render the answer.
///
/// `?format=` wins over `Accept`, because a developer typing it into a browser
/// address bar cannot change what the browser sends.
///
/// # Errors
/// [`RouteError::BadRequest`] for a `format` this server does not produce.
/// Silently falling back would let a client believe it asked for something.
pub fn format(request: &Request) -> Result<Format, RouteError> {
    if let Some(requested) = request.param("format") {
        return match requested {
            "json" => Ok(Format::Json),
            "bin" | "binary" => Ok(Format::Binary),
            other => Err(bad(format!("unknown format {other:?}; try json or binary"))),
        };
    }
    let accept = request.header("accept").unwrap_or("");
    if accept.contains("application/json") {
        Ok(Format::Json)
    } else {
        // The default is the cheap one. See `crates/rpc`: metered data is the
        // constraint, and a wallet that forgets to ask should not pay for hex.
        Ok(Format::Binary)
    }
}

/// A `Query` decoded from a body must still be one this server routes.
///
/// Present so the `POST` path cannot become a wider surface than the `GET`
/// paths by accident — every variant is reachable both ways, and this is the
/// assertion that keeps it true.
#[must_use]
pub fn is_routable(query: &Query) -> bool {
    matches!(
        query,
        Query::Status
            | Query::Header { .. }
            | Query::Balance { .. }
            | Query::Account { .. }
            | Query::Supply { .. }
            | Query::Issuer { .. }
            | Query::Frozen { .. }
            | Query::ResolveName { .. }
            | Query::ResolveContact { .. }
            | Query::PrimaryAlias { .. }
            | Query::Block { .. }
            | Query::Transaction { .. }
            | Query::History { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::codec::Encode;
    use std::io::BufReader;

    fn request(raw: &str) -> Request {
        let mut reader = BufReader::new(raw.as_bytes());
        crate::wire::read_request(&mut reader, &crate::Config::default()).unwrap()
    }

    fn get(target: &str) -> Result<Route, RouteError> {
        route(&request(&format!(
            "GET {target} HTTP/1.1\r\nHost: n\r\n\r\n"
        )))
    }

    fn address() -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[7; 32]).public_key())
    }

    fn bech32() -> String {
        address().to_bech32().unwrap()
    }

    #[test]
    fn the_root_serves_the_route_table() {
        assert_eq!(get("/").unwrap(), Route::Index);
    }

    #[test]
    fn a_balance_route_carries_the_address_and_the_denom() {
        let route = get(&format!(
            "/v1/accounts/{}/balance?denom=sov/ke/kes",
            bech32()
        ))
        .unwrap();
        assert_eq!(
            route,
            Route::Chain(Box::new(Query::Balance {
                address: address(),
                denom: Denom::sovereign("ke", "kes").unwrap(),
            }))
        );
    }

    #[test]
    fn a_sovereign_denom_needs_no_encoding_in_a_query_string() {
        // The reason denoms live in the query string rather than the path.
        let route = get("/v1/supply?denom=sov/ke/kes").unwrap();
        assert_eq!(
            route,
            Route::Chain(Box::new(Query::Supply {
                denom: Denom::sovereign("ke", "kes").unwrap()
            }))
        );
    }

    #[test]
    fn a_balance_route_without_a_denom_says_so() {
        let err = get(&format!("/v1/accounts/{}/balance", bech32())).unwrap_err();
        assert_eq!(err.status(), Status::BadRequest);
        assert!(err.message().contains("denom"), "{}", err.message());
    }

    #[test]
    fn an_address_with_a_broken_checksum_never_reaches_a_query() {
        // bech32m's checksum is the reason a mistyped address is a 400 rather
        // than a proved absence for an account nobody owns.
        let mut text = bech32();
        text.pop();
        text.push('q');
        let err = get(&format!("/v1/accounts/{text}")).unwrap_err();
        assert_eq!(err.status(), Status::BadRequest);
    }

    #[test]
    fn a_name_the_constructor_would_normalise_is_refused_instead() {
        // `Username::new` lower-cases for callers assembling a value. A URL is
        // a decode boundary, so two spellings of one name must not both work.
        let err = get("/v1/names/AMINA").unwrap_err();
        assert_eq!(err.status(), Status::BadRequest);
        assert!(err.message().contains("canonical"), "{}", err.message());

        // The canonical spelling still resolves.
        assert_eq!(
            get("/v1/names/amina").unwrap(),
            Route::Chain(Box::new(Query::ResolveName {
                name: Username::new("amina").unwrap()
            }))
        );
    }

    #[test]
    fn a_name_the_chain_would_refuse_never_becomes_a_query() {
        // The edge uses the chain's own constructor rather than a laxer one, so
        // a non-ASCII or out-of-range name fails here for the same reason it
        // would fail at registration.
        for name in ["ab", "amin\u{0430}", "-amina", "a".repeat(64).as_str()] {
            assert!(
                get(&format!("/v1/names/{name}")).is_err(),
                "accepted {name:?}"
            );
        }
    }

    #[test]
    fn a_commitment_must_be_thirty_two_bytes_of_lower_case_hex() {
        let long = "a".repeat(64);
        assert!(get(&format!("/v1/contacts/{long}")).is_ok());

        for bad in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "z".repeat(64),
        ] {
            assert!(
                get(&format!("/v1/contacts/{bad}")).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn a_height_that_is_not_a_number_is_a_bad_request_not_a_missing_block() {
        assert_eq!(
            get("/v1/blocks/latest").unwrap_err().status(),
            Status::BadRequest
        );
        assert_eq!(
            get("/v1/blocks/-1").unwrap_err().status(),
            Status::BadRequest
        );
    }

    #[test]
    fn an_unknown_path_is_not_silently_answered() {
        assert_eq!(get("/v1/nonsense").unwrap_err(), RouteError::NotFound);
        assert_eq!(get("/v2/status").unwrap_err(), RouteError::NotFound);
    }

    #[test]
    fn a_read_route_refuses_a_post_rather_than_treating_it_as_a_get() {
        let err = route(&request(
            "POST /v1/status HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ))
        .unwrap_err();
        assert_eq!(err, RouteError::MethodNotAllowed { allow: "GET" });
    }

    #[test]
    fn the_query_endpoint_refuses_a_get() {
        let err = get("/v1/query").unwrap_err();
        assert_eq!(err, RouteError::MethodNotAllowed { allow: "POST" });
    }

    #[test]
    fn a_posted_query_must_be_canonical() {
        let body = Query::Status.to_bytes();
        let raw = format!(
            "POST /v1/query HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(&body)
        );
        let mut reader = BufReader::new(raw.as_bytes());
        let request = crate::wire::read_request(&mut reader, &crate::Config::default()).unwrap();
        assert_eq!(
            route(&request).unwrap(),
            Route::Chain(Box::new(Query::Status))
        );

        // Trailing bytes are two encodings of one query, and the codec refuses
        // them at every boundary. This is one of those boundaries.
        let raw = "POST /v1/query HTTP/1.1\r\nContent-Length: 2\r\n\r\n\x00\x00";
        let mut reader = BufReader::new(raw.as_bytes());
        let request = crate::wire::read_request(&mut reader, &crate::Config::default()).unwrap();
        assert_eq!(route(&request).unwrap_err().status(), Status::BadRequest);
    }

    #[test]
    fn a_preflight_is_answered_before_routing() {
        let request = request("OPTIONS /v1/query HTTP/1.1\r\nHost: n\r\n\r\n");
        assert_eq!(route(&request).unwrap(), Route::Preflight);
    }

    #[test]
    fn binary_is_the_default_and_json_is_asked_for() {
        assert_eq!(
            format(&request("GET / HTTP/1.1\r\n\r\n")).unwrap(),
            Format::Binary
        );
        assert_eq!(
            format(&request("GET /?format=json HTTP/1.1\r\n\r\n")).unwrap(),
            Format::Json
        );
        assert_eq!(
            format(&request(
                "GET / HTTP/1.1\r\nAccept: application/json\r\n\r\n"
            ))
            .unwrap(),
            Format::Json
        );
        // A browser asking for HTML gets the cheap format, not a guess.
        assert_eq!(
            format(&request("GET / HTTP/1.1\r\nAccept: text/html\r\n\r\n")).unwrap(),
            Format::Binary
        );
    }

    #[test]
    fn an_unknown_format_is_refused_rather_than_ignored() {
        let err = format(&request("GET /?format=xml HTTP/1.1\r\n\r\n")).unwrap_err();
        assert_eq!(err.status(), Status::BadRequest);
    }

    #[test]
    fn every_query_variant_is_reachable_over_http() {
        // `is_routable` must stay exhaustive: a new `Query` variant that no
        // route reaches is a protocol split between the POST and GET surfaces.
        let address = address();
        let denom = Denom::native();
        for query in [
            Query::Status,
            Query::Header { height: Height(1) },
            Query::Balance {
                address,
                denom: denom.clone(),
            },
            Query::Account { address },
            Query::Supply {
                denom: denom.clone(),
            },
            Query::Issuer {
                denom: denom.clone(),
            },
            Query::Frozen { denom, address },
            Query::ResolveName {
                name: Username::new("amina").unwrap(),
            },
            Query::PrimaryAlias { address },
        ] {
            assert!(is_routable(&query), "unroutable: {query:?}");
        }
    }
}
