//! The developer-facing view: opt-in, and never proof-free.
//!
//! # Why this exists at all
//!
//! The wire format is the canonical codec. `crates/rpc` says why: data is the
//! one resource that is genuinely affordable in this market and it is still
//! metered, so a wallet should not pay for base-16 and field names. JSON is
//! offered because a developer with `curl` is the audience
//! [ADR-0009](../../../docs/adr/0009-developer-payment-surface.md) is written for, and
//! because an explorer in a browser is worth more than the bytes it costs.
//!
//! # The line this must not cross
//!
//! `crates/rpc` exists to make one failure impossible: *"one convenience
//! endpoint that returns a balance without a proof, added under deadline, and
//! every wallet author will use it because it is smaller and faster."*
//!
//! A JSON renderer is exactly how that failure would arrive. So:
//!
//! * every state answer carries its **proof**, hex-encoded;
//! * every state answer carries `response`, the full canonical encoding, so a
//!   client that reads JSON can still verify without asking twice;
//! * the decoded value is named **`value_unverified`**, matching
//!   [`ProvedValue::value_unverified`](afrolink_rpc::ProvedValue::value_unverified)
//!   — the escape hatch in the Rust API is deliberately verbose so its use is
//!   obvious in review, and the same name in JSON makes it just as obvious in a
//!   wallet's source.
//!
//! There is no shape here that says `{"balance": 2500}` and nothing else, and
//! there should never be one.
//!
//! # Hand-written, like the codec
//!
//! No `serde`. Writing JSON is escaping a string and concatenating; reading it
//! is where the difficulty and the dependency would be, and nothing here reads
//! it.

use afrolink_consensus::Commit;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::BlockHeader;
use afrolink_primitives::codec::Encode;
use afrolink_rpc::{ProvedValue, Response, SignedHeader, Status};

/// Escape and quote a string into `out`.
///
/// Control characters are escaped rather than passed through, so a chain-carried
/// string — a chain id, a username — cannot terminate the literal early.
pub fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `"name":"value",`
fn field_str(name: &str, value: &str, out: &mut String) {
    write_string(name, out);
    out.push(':');
    write_string(value, out);
    out.push(',');
}

/// `"name":123,`
fn field_num(name: &str, value: u64, out: &mut String) {
    write_string(name, out);
    out.push(':');
    out.push_str(&value.to_string());
    out.push(',');
}

/// `"name":"<hex>",`
fn field_hash(name: &str, value: &Hash32, out: &mut String) {
    field_str(name, &value.to_hex(), out);
}

/// Remove the trailing comma an object accumulated, and close it.
fn close(out: &mut String) {
    if out.ends_with(',') {
        out.pop();
    }
    out.push('}');
}

/// Render a header, without its commit.
fn write_header(header: &BlockHeader, out: &mut String) {
    out.push('{');
    field_str("chain_id", header.chain_id.as_str(), out);
    field_num("height", header.height.0, out);
    field_num("time_ms", header.time.0, out);
    field_hash("block_id", &header.id(), out);
    field_hash("parent", &header.parent, out);
    field_hash("tx_root", &header.tx_root, out);
    field_hash("app_hash", &header.app_hash, out);
    field_hash("validators_hash", &header.validators_hash, out);
    field_hash("next_validators_hash", &header.next_validators_hash, out);
    close(out);
}

/// Render a commit as a summary plus its canonical bytes.
///
/// The individual signatures are not expanded. A client that wants to check
/// them needs the exact bytes anyway, and a client that does not is better off
/// not being handed a list it might mistake for a verification.
fn write_commit(commit: &Commit, out: &mut String) {
    out.push('{');
    field_num("height", commit.height.0, out);
    field_num("round", u64::from(commit.round.0), out);
    field_hash("block_id", &commit.block_id, out);
    field_num("signatures", commit.signatures.len() as u64, out);
    field_str("bytes", &hex::encode(commit.to_bytes()), out);
    close(out);
}

fn write_signed_header(signed: &SignedHeader, out: &mut String) {
    out.push('{');
    write_string("header", out);
    out.push(':');
    write_header(&signed.header, out);
    out.push(',');
    write_string("commit", out);
    out.push(':');
    write_commit(&signed.commit, out);
    out.push('}');
}

fn write_status(status: &Status, out: &mut String) {
    out.push('{');
    field_str("chain_id", status.chain_id.as_str(), out);
    write_string("tip", out);
    out.push(':');
    write_signed_header(&status.tip, out);
    out.push('}');
}

fn write_proved_value(value: &ProvedValue, out: &mut String) {
    out.push('{');
    field_num("height", value.height().0, out);

    // Named for what it is. See the module docs: this is the one field a
    // careless wallet would read, and the name is the warning.
    write_string("value_unverified", out);
    out.push(':');
    match value.value_unverified() {
        Some(bytes) => write_string(&hex::encode(bytes), out),
        // A proved absence, not a missing answer.
        None => out.push_str("null"),
    }
    out.push(',');

    field_str("proof", &hex::encode(value.proof().to_bytes()), out);
    close(out);
}

/// Render a [`Response`] as JSON.
///
/// State answers additionally carry `response`: the canonical encoding of the
/// whole response, so reading the JSON view never means giving up the ability
/// to verify.
#[must_use]
pub fn response(response: &Response) -> String {
    let mut out = String::with_capacity(1024);
    match response {
        Response::Status(status) => write_status(status, &mut out),
        Response::Header(signed) => write_signed_header(signed, &mut out),
        Response::Value(value) => {
            out.push('{');
            write_string("value", &mut out);
            out.push(':');
            write_proved_value(value, &mut out);
            out.push(',');
            field_str("response", &hex::encode(response.to_bytes()), &mut out);
            close(&mut out);
        }
    }
    out
}

/// The index served at `/`: what this node answers, and how.
///
/// A route table a developer can read is the cheapest documentation there is,
/// and it costs one constant.
#[must_use]
pub fn index() -> String {
    let routes = [
        ("GET", "/health", "liveness, and the current height"),
        (
            "GET",
            "/v1/status",
            "tip header and the commit finalising it",
        ),
        ("GET", "/v1/blocks/{height}", "one header and its commit"),
        (
            "GET",
            "/v1/accounts/{address}",
            "nonce and revealed public key",
        ),
        (
            "GET",
            "/v1/accounts/{address}/balance?denom=",
            "balance in one denomination",
        ),
        (
            "GET",
            "/v1/accounts/{address}/alias",
            "the name a wallet should display",
        ),
        (
            "GET",
            "/v1/accounts/{address}/frozen?denom=",
            "whether an issuer froze this account",
        ),
        ("GET", "/v1/supply?denom=", "total supply of a denomination"),
        (
            "GET",
            "/v1/issuer?denom=",
            "registered issuer of a sovereign denomination",
        ),
        (
            "GET",
            "/v1/names/{name}",
            "which account a username points at",
        ),
        (
            "GET",
            "/v1/contacts/{commitment}",
            "which account a phone or email commitment points at",
        ),
        (
            "POST",
            "/v1/query",
            "a canonically-encoded Query; answers with a canonically-encoded Response",
        ),
    ];

    let mut out = String::from("{\"service\":\"afrolink\",\"api\":\"v1\",");
    out.push_str("\"formats\":{\"default\":\"canonical bytes\",\"json\":\"?format=json, or Accept: application/json\"},");
    out.push_str(
        "\"note\":\"every state answer carries a proof; verify it against a header you trust\",",
    );
    out.push_str("\"routes\":[");
    for (method, path, description) in routes {
        out.push('{');
        field_str("method", method, &mut out);
        field_str("path", path, &mut out);
        field_str("description", description, &mut out);
        close(&mut out);
        out.push(',');
    }
    if out.ends_with(',') {
        out.pop();
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_cannot_escape_its_own_quotes() {
        let mut out = String::new();
        write_string("a\"b\\c\nd", &mut out);
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn a_control_character_is_escaped_rather_than_emitted() {
        let mut out = String::new();
        write_string("a\u{0007}b", &mut out);
        assert_eq!(out, "\"a\\u0007b\"");
    }

    #[test]
    fn the_index_lists_every_route_it_claims_to() {
        let index = index();
        assert!(index.contains("/v1/status"));
        assert!(index.contains("/v1/accounts/{address}/balance?denom="));
        assert!(index.contains("/v1/query"));
        assert!(index.ends_with("]}"), "unterminated JSON: {index}");
    }
}
