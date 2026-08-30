//! Strict HTTP/1.1 parsing and response writing.
//!
//! # The rule
//!
//! **If a byte stream has more than one reading, it is refused.**
//!
//! Request smuggling is not a cryptographic failure; it is two parsers reading
//! one stream differently, and every published technique starts from a
//! construction that some parser tolerates. A server that tolerates nothing
//! ambiguous cannot be the disagreeing half.
//!
//! This is the same rule [`crates/primitives`](afrolink_primitives::codec)
//! applies to the consensus codec — one encoding per value, trailing bytes
//! rejected, no normalising at the boundary — applied to a much older and much
//! messier format.
//!
//! What is refused, and why each one matters:
//!
//! | Construction | Why it is refused |
//! |---|---|
//! | Bare `LF` as a line ending | The classic desync: a front end sees one request, a back end sees two |
//! | Leading whitespace on a header line (obs-fold) | Lets a header value continue into what another parser reads as a new header |
//! | Space before a header's colon | `Content-Length : 5` is a header to some parsers and not to others |
//! | Any `Transfer-Encoding` | The largest smuggling class. Nothing here needs chunked bodies |
//! | Repeated or comma-bearing `Content-Length` | Two lengths means two readings of the body boundary |
//! | A non-digit in `Content-Length` | `+5`, ` 5` and `0x5` must not be five |
//! | A stray space in the request line | The target is whatever the parser decides it is |
//! | Absolute-form targets (`GET http://…`) | Proxy syntax. This is not a proxy, and accepting it invites confusion about who the request was for |
//! | Control bytes or invalid UTF-8 after percent-decoding | A newline in a path is never a legitimate query |
//!
//! Percent-decoding happens **after** the path is split on `/`, so `%2F` can
//! never introduce a path separator. Decoding first is how directory traversal
//! gets past a route table.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};

use thiserror::Error;

/// Content type for canonical protocol bytes.
pub const CONTENT_TYPE_BINARY: &str = "application/vnd.afrolink.v1+bin";
/// Content type for the developer-facing view.
pub const CONTENT_TYPE_JSON: &str = "application/json";

/// Why a request could not be read.
///
/// Each variant carries the status the client should be told, because the
/// mapping is part of the protocol rather than a presentation detail.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The peer closed cleanly before sending anything.
    #[error("connection closed")]
    Closed,
    /// The underlying socket failed.
    #[error("io: {0}")]
    Io(String),
    /// The request line or a header was not well formed.
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    /// The request line exceeded its limit.
    #[error("request line too long")]
    RequestLineTooLong,
    /// The headers exceeded their limit.
    #[error("headers too large")]
    HeadersTooLarge,
    /// The body exceeded its limit.
    #[error("body too large")]
    BodyTooLarge,
    /// A method this server does not implement.
    #[error("method not allowed")]
    MethodNotAllowed,
    /// A version this server does not speak.
    #[error("unsupported HTTP version")]
    UnsupportedVersion,
    /// `Transfer-Encoding` was present.
    #[error("transfer-encoding is not supported")]
    TransferEncoding,
}

impl WireError {
    /// The status to answer with.
    #[must_use]
    pub fn status(&self) -> Status {
        match self {
            Self::Closed | Self::Io(_) => Status::BadRequest,
            Self::Malformed(_) => Status::BadRequest,
            Self::RequestLineTooLong => Status::UriTooLong,
            Self::HeadersTooLarge => Status::HeadersTooLarge,
            Self::BodyTooLarge => Status::PayloadTooLarge,
            Self::MethodNotAllowed => Status::MethodNotAllowed,
            Self::UnsupportedVersion => Status::VersionNotSupported,
            Self::TransferEncoding => Status::NotImplemented,
        }
    }
}

/// The methods this server implements.
///
/// Deliberately three. `HEAD`, `PUT` and the rest are answered with 405 and an
/// `Allow` header rather than silently treated as `GET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Read a query.
    Get,
    /// Submit a canonically-encoded query.
    Post,
    /// A CORS preflight.
    Options,
}

impl Method {
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        match bytes {
            b"GET" => Ok(Self::Get),
            b"POST" => Ok(Self::Post),
            b"OPTIONS" => Ok(Self::Options),
            _ => Err(WireError::MethodNotAllowed),
        }
    }

    /// The method name as it appears on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Options => "OPTIONS",
        }
    }
}

/// HTTP status codes this server can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The answer is in the body.
    Ok,
    /// There is deliberately no body — a CORS preflight.
    NoContent,
    /// The request was not well formed, or a parameter did not parse.
    BadRequest,
    /// No route matches.
    NotFound,
    /// The route exists but not for this method.
    MethodNotAllowed,
    /// The body exceeded the configured limit.
    PayloadTooLarge,
    /// The request target exceeded the configured limit.
    UriTooLong,
    /// The header block exceeded the configured limit.
    HeadersTooLarge,
    /// The node could not answer, and the reason is the node's own.
    InternalError,
    /// A construction this server refuses to implement.
    NotImplemented,
    /// The node is at capacity, or temporarily cannot answer.
    Unavailable,
    /// The client asked for a version this server does not speak.
    VersionNotSupported,
}

impl Status {
    /// The numeric code.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::NoContent => 204,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::UriTooLong => 414,
            Self::HeadersTooLarge => 431,
            Self::InternalError => 500,
            Self::NotImplemented => 501,
            Self::Unavailable => 503,
            Self::VersionNotSupported => 505,
        }
    }

    /// The reason phrase.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::NoContent => "No Content",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UriTooLong => "URI Too Long",
            Self::HeadersTooLarge => "Request Header Fields Too Large",
            Self::InternalError => "Internal Server Error",
            Self::NotImplemented => "Not Implemented",
            Self::Unavailable => "Service Unavailable",
            Self::VersionNotSupported => "HTTP Version Not Supported",
        }
    }

    /// Whether a connection may be reused after this status.
    ///
    /// A parse failure means the position in the byte stream is no longer
    /// known, so the connection must close — continuing to read from it is
    /// precisely the desync this module exists to avoid.
    #[must_use]
    pub fn allows_keep_alive(self) -> bool {
        matches!(
            self,
            Self::Ok
                | Self::NoContent
                | Self::NotFound
                | Self::MethodNotAllowed
                | Self::InternalError
                | Self::Unavailable
        )
    }
}

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Path segments, percent-decoded, with empty segments removed.
    ///
    /// Held split rather than as a string so a route can never be matched
    /// against a path that still needs normalising.
    pub segments: Vec<String>,
    /// Query parameters, percent-decoded.
    pub params: BTreeMap<String, String>,
    /// Lower-cased header names to values.
    pub headers: BTreeMap<String, String>,
    /// Request body. Empty unless a `Content-Length` was sent.
    pub body: Vec<u8>,
    /// Whether the client and this server agree to reuse the connection.
    pub keep_alive: bool,
}

impl Request {
    /// A query parameter, if present.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// A header, if present. `name` must already be lower case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// The path, rebuilt for display and error messages.
    #[must_use]
    pub fn path(&self) -> String {
        let mut out = String::from("/");
        out.push_str(&self.segments.join("/"));
        out
    }
}

/// A response, before it reaches a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status line.
    pub status: Status,
    /// `Content-Type` for the body.
    pub content_type: &'static str,
    /// Body bytes.
    pub body: Vec<u8>,
    /// Extra headers, in the order they should be sent.
    pub extra: Vec<(String, String)>,
}

impl HttpResponse {
    /// A response carrying canonical protocol bytes.
    #[must_use]
    pub fn binary(status: Status, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: CONTENT_TYPE_BINARY,
            body,
            extra: Vec::new(),
        }
    }

    /// A response carrying JSON.
    #[must_use]
    pub fn json(status: Status, body: String) -> Self {
        Self {
            status,
            content_type: CONTENT_TYPE_JSON,
            body: body.into_bytes(),
            extra: Vec::new(),
        }
    }

    /// An error, always as JSON.
    ///
    /// `message` must be safe to show a stranger. Backend detail — file paths,
    /// database errors — is deliberately not routed here: a public read
    /// endpoint should not narrate a node's filesystem to whoever asks.
    #[must_use]
    pub fn error(status: Status, message: &str) -> Self {
        let mut body = String::from("{\"error\":");
        crate::json::write_string(message, &mut body);
        body.push_str(",\"status\":");
        body.push_str(&status.code().to_string());
        body.push('}');
        Self::json(status, body)
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.extra.push((name.to_owned(), value.to_owned()));
        self
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Read one request.
///
/// Returns [`WireError::Closed`] when the peer shut down between requests,
/// which is the normal end of a keep-alive connection rather than a failure.
///
/// # Errors
/// Any construction listed in the module documentation, plus socket failures
/// and limit violations.
pub fn read_request<R: BufRead>(
    reader: &mut R,
    config: &crate::Config,
) -> Result<Request, WireError> {
    let line = read_line(reader, config.max_request_line).map_err(|e| match e {
        WireError::HeadersTooLarge => WireError::RequestLineTooLong,
        other => other,
    })?;
    if line.is_empty() {
        // A leading empty line is tolerated by some servers as a stray CRLF
        // from a previous request. Tolerating it means tolerating an extra
        // framing, so it is refused.
        return Err(WireError::Malformed("empty request line"));
    }

    let (method, target, version) = parse_request_line(&line)?;
    let (segments, params) = parse_target(target)?;
    let headers = read_headers(reader, config)?;

    let http_11 = match version {
        b"HTTP/1.1" => true,
        b"HTTP/1.0" => false,
        _ => return Err(WireError::UnsupportedVersion),
    };

    if headers.contains_key("transfer-encoding") {
        return Err(WireError::TransferEncoding);
    }

    let length = content_length(&headers)?;
    if length > config.max_body_bytes {
        return Err(WireError::BodyTooLarge);
    }

    let mut body = Vec::new();
    if length > 0 {
        let read = reader
            .take(length as u64)
            .read_to_end(&mut body)
            .map_err(|e| WireError::Io(e.to_string()))?;
        if read != length {
            return Err(WireError::Malformed("body shorter than Content-Length"));
        }
    }

    // HTTP/1.1 keeps the connection open unless told otherwise; 1.0 closes it
    // unless told otherwise. Getting this backwards for either version is a
    // hang, not a security bug, but it is the kind of hang that looks like a
    // network fault.
    let connection = headers.get("connection").map(String::as_str).unwrap_or("");
    let keep_alive = if http_11 {
        !connection.eq_ignore_ascii_case("close")
    } else {
        connection.eq_ignore_ascii_case("keep-alive")
    };

    Ok(Request {
        method,
        segments,
        params,
        headers,
        body,
        keep_alive,
    })
}

/// `METHOD SP TARGET SP VERSION`, with no latitude at all.
fn parse_request_line(line: &[u8]) -> Result<(Method, &[u8], &[u8]), WireError> {
    let mut parts = line.split(|b| *b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        // Splitting on *every* space means a stray one produces a fourth part
        // and lands here, rather than being absorbed into a field.
        return Err(WireError::Malformed("request line is not three fields"));
    };

    if !target.starts_with(b"/") {
        // Absolute-form and authority-form are proxy syntax. This server is an
        // origin server; accepting them would mean deciding whose request it is.
        return Err(WireError::Malformed("request target must be origin-form"));
    }

    Ok((Method::parse(method)?, target, version))
}

/// Split a target into decoded path segments and decoded parameters.
fn parse_target(target: &[u8]) -> Result<(Vec<String>, BTreeMap<String, String>), WireError> {
    let text = core::str::from_utf8(target)
        .map_err(|_| WireError::Malformed("request target is not UTF-8"))?;

    let (path, query) = match text.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (text, None),
    };

    // Decode per segment, after splitting. `%2F` therefore decodes to a literal
    // slash *inside* one segment and cannot create another.
    let mut segments = Vec::new();
    for raw in path.split('/') {
        if raw.is_empty() {
            continue;
        }
        let decoded = percent_decode(raw)?;
        if decoded == "." || decoded == ".." {
            // Nothing here is a filesystem, but a route table that can be
            // walked upwards is a bug waiting for a future route that is.
            return Err(WireError::Malformed("relative path segment"));
        }
        segments.push(decoded);
    }

    let mut params = BTreeMap::new();
    if let Some(query) = query {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (name, value) = match pair.split_once('=') {
                Some((n, v)) => (percent_decode(n)?, percent_decode(v)?),
                None => (percent_decode(pair)?, String::new()),
            };
            if params.insert(name, value).is_some() {
                // Two values for one parameter is two readings of the request.
                return Err(WireError::Malformed("repeated query parameter"));
            }
        }
    }

    Ok((segments, params))
}

/// Read header lines until the blank line that ends them.
fn read_headers<R: BufRead>(
    reader: &mut R,
    config: &crate::Config,
) -> Result<BTreeMap<String, String>, WireError> {
    let mut headers = BTreeMap::new();
    let mut total: usize = 0;

    loop {
        let line = read_line(reader, config.max_header_line)?;
        if line.is_empty() {
            return Ok(headers);
        }

        total = total
            .checked_add(line.len())
            .filter(|t| *t <= config.max_header_bytes)
            .ok_or(WireError::HeadersTooLarge)?;
        if headers.len() >= config.max_headers {
            return Err(WireError::HeadersTooLarge);
        }

        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            // Obsolete line folding. RFC 7230 already deprecated it; accepting
            // it lets a value swallow what the next parser calls a header.
            return Err(WireError::Malformed("folded header line"));
        }

        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return Err(WireError::Malformed("header without a colon"));
        };
        let (name, rest) = line
            .split_at_checked(colon)
            .ok_or(WireError::Malformed("header without a colon"))?;

        if name.is_empty() || !name.iter().all(|b| is_token_byte(*b)) {
            // A trailing space here is `Content-Length : 5`, which some parsers
            // read as a header and others do not.
            return Err(WireError::Malformed("header name is not a token"));
        }

        let value = rest
            .get(1..)
            .ok_or(WireError::Malformed("header without a value"))?;
        let value = trim_ows(value);
        if !value.iter().all(|b| is_field_byte(*b)) {
            return Err(WireError::Malformed("header value has control bytes"));
        }
        let value = core::str::from_utf8(value)
            .map_err(|_| WireError::Malformed("header value is not UTF-8"))?
            .to_owned();

        let name = name.to_ascii_lowercase();
        let name = core::str::from_utf8(&name)
            .map_err(|_| WireError::Malformed("header name is not UTF-8"))?
            .to_owned();

        // Repeats are refused wholesale rather than only for the headers that
        // matter today, so a future header cannot be smuggled by duplication.
        if headers.insert(name, value).is_some() {
            return Err(WireError::Malformed("repeated header"));
        }
    }
}

/// Body length: absent means zero, and anything ambiguous is refused.
fn content_length(headers: &BTreeMap<String, String>) -> Result<usize, WireError> {
    let Some(raw) = headers.get("content-length") else {
        return Ok(0);
    };
    // A comma is the list form, `Content-Length: 5, 5`, which is a repeat by
    // another spelling.
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WireError::Malformed("Content-Length is not a plain number"));
    }
    raw.parse::<usize>()
        .map_err(|_| WireError::Malformed("Content-Length does not fit"))
}

/// One CRLF-terminated line, bounded, with the terminator removed.
fn read_line<R: BufRead>(reader: &mut R, max: usize) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::new();
    let read = reader
        .by_ref()
        .take(max.saturating_add(1) as u64)
        .read_until(b'\n', &mut buf)
        .map_err(|e| WireError::Io(e.to_string()))?;

    if read == 0 {
        return Err(WireError::Closed);
    }
    if buf.last() != Some(&b'\n') {
        return Err(WireError::HeadersTooLarge);
    }
    buf.pop();
    if buf.last() != Some(&b'\r') {
        // Bare LF is the desync primitive. Nothing legitimate sends it.
        return Err(WireError::Malformed("line not terminated by CRLF"));
    }
    buf.pop();
    Ok(buf)
}

/// Percent-decode one path segment or parameter.
///
/// `+` is **not** treated as a space. That convention belongs to HTML form
/// bodies, and honouring it here would give `a+b` two readings.
fn percent_decode(input: &str) -> Result<String, WireError> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();

    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        let (Some(hi), Some(lo)) = (bytes.next(), bytes.next()) else {
            return Err(WireError::Malformed("truncated percent-escape"));
        };
        if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
            // Rejected explicitly: `from_str_radix` would accept a leading `+`.
            return Err(WireError::Malformed("percent-escape is not hex"));
        }
        let pair = [hi, lo];
        let text = core::str::from_utf8(&pair)
            .map_err(|_| WireError::Malformed("percent-escape is not hex"))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|_| WireError::Malformed("percent-escape is not hex"))?;
        out.push(byte);
    }

    let decoded =
        String::from_utf8(out).map_err(|_| WireError::Malformed("path is not valid UTF-8"))?;
    if decoded.chars().any(char::is_control) {
        return Err(WireError::Malformed("path contains control characters"));
    }
    Ok(decoded)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if *first == b' ' || *first == b'\t' {
            value = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = value.split_last() {
        if *last == b' ' || *last == b'\t' {
            value = rest;
        } else {
            break;
        }
    }
    value
}

/// RFC 7230 `tchar`.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Visible ASCII, plus space and tab. Excludes CR, LF and NUL by construction.
fn is_field_byte(b: u8) -> bool {
    b == b'\t' || (0x20..0x7f).contains(&b)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Write a response.
///
/// `Content-Length` is always sent and always correct, so a client never has to
/// guess where a body ends — the same reason chunked encoding is refused on the
/// way in.
///
/// # Errors
/// Socket failures.
pub fn write_response<W: Write>(
    writer: &mut W,
    response: &HttpResponse,
    keep_alive: bool,
    config: &crate::Config,
) -> std::io::Result<()> {
    let mut head = String::with_capacity(256);
    head.push_str("HTTP/1.1 ");
    head.push_str(&response.status.code().to_string());
    head.push(' ');
    head.push_str(response.status.reason());
    head.push_str("\r\n");

    header(&mut head, "Content-Type", response.content_type);
    header(
        &mut head,
        "Content-Length",
        &response.body.len().to_string(),
    );
    header(
        &mut head,
        "Connection",
        if keep_alive { "keep-alive" } else { "close" },
    );
    // Balances change every second; a cached one is a wrong one.
    header(&mut head, "Cache-Control", "no-store");
    // Without this a browser may sniff the binary body as something executable.
    header(&mut head, "X-Content-Type-Options", "nosniff");
    if let Some(origin) = &config.allow_origin {
        header(&mut head, "Access-Control-Allow-Origin", origin);
    }
    for (name, value) in &response.extra {
        header(&mut head, name, value);
    }
    // No `Server` header: a version string is free reconnaissance.
    head.push_str("\r\n");

    writer.write_all(head.as_bytes())?;
    writer.write_all(&response.body)?;
    writer.flush()
}

/// Append one header, dropping any value that could inject another.
///
/// Header injection needs a CR or LF in a value. Every value written here is
/// either a constant or derived from chain data, but "derived from chain data"
/// is exactly the kind of thing that changes, so the check is unconditional.
fn header(out: &mut String, name: &str, value: &str) {
    if value.contains(['\r', '\n']) {
        return;
    }
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn parse(raw: &str) -> Result<Request, WireError> {
        let config = crate::Config::default();
        let mut reader = BufReader::new(raw.as_bytes());
        read_request(&mut reader, &config)
    }

    #[test]
    fn an_ordinary_get_parses() {
        let request = parse("GET /v1/status HTTP/1.1\r\nHost: node\r\n\r\n").unwrap();
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.segments, vec!["v1", "status"]);
        assert_eq!(request.header("host"), Some("node"));
        assert!(request.keep_alive);
    }

    #[test]
    fn query_parameters_are_decoded() {
        let request =
            parse("GET /v1/supply?denom=sov%2Fke%2Fkes HTTP/1.1\r\nHost: n\r\n\r\n").unwrap();
        assert_eq!(request.param("denom"), Some("sov/ke/kes"));
    }

    #[test]
    fn a_percent_encoded_slash_cannot_create_a_path_segment() {
        // Decoding before splitting is how a route table gets walked. Here the
        // slash lands inside one segment and stays there.
        let request = parse("GET /v1/names/a%2Fb HTTP/1.1\r\nHost: n\r\n\r\n").unwrap();
        assert_eq!(request.segments, vec!["v1", "names", "a/b"]);
    }

    #[test]
    fn a_bare_lf_line_ending_is_refused() {
        // The classic desync: a front end sees one request here, a back end two.
        let err = parse("GET /v1/status HTTP/1.1\nHost: n\r\n\r\n").unwrap_err();
        assert_eq!(err.status(), Status::BadRequest);
    }

    #[test]
    fn a_folded_header_is_refused() {
        let err = parse("GET / HTTP/1.1\r\nHost: n\r\n  continued\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_space_before_a_header_colon_is_refused() {
        let err = parse("GET / HTTP/1.1\r\nContent-Length : 0\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn transfer_encoding_is_refused_outright() {
        // The largest smuggling class, and nothing here needs it.
        let err =
            parse("POST /v1/query HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err();
        assert_eq!(err, WireError::TransferEncoding);
        assert_eq!(err.status(), Status::NotImplemented);
    }

    #[test]
    fn a_repeated_content_length_is_refused() {
        let err =
            parse("POST /v1/query HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n")
                .unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_content_length_that_is_not_a_plain_number_is_refused() {
        // Note what is *not* in this list: whitespace around the value. RFC 7230
        // makes surrounding OWS part of the framing rather than the value, so
        // stripping it is required rather than lenient — `Content-Length: 5`
        // has a space in it and means five.
        for value in ["+5", "0x5", "5, 5", "five", "-1", "5.0", ""] {
            let raw = format!("POST /v1/query HTTP/1.1\r\nContent-Length: {value}\r\n\r\nhello");
            assert!(parse(&raw).is_err(), "accepted Content-Length: {value:?}");
        }
    }

    #[test]
    fn surrounding_whitespace_is_stripped_from_a_header_value() {
        let request = parse("GET / HTTP/1.1\r\nAccept: \t application/json \t\r\n\r\n").unwrap();
        assert_eq!(request.header("accept"), Some("application/json"));
    }

    #[test]
    fn a_stray_space_in_the_request_line_is_refused() {
        let err = parse("GET /a b HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_absolute_form_target_is_refused() {
        // Proxy syntax. Accepting it means deciding whose request this was.
        let err = parse("GET http://elsewhere/v1/status HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_repeated_query_parameter_is_refused() {
        let err = parse("GET /v1/supply?denom=a&denom=b HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_control_character_cannot_be_smuggled_through_a_percent_escape() {
        let err = parse("GET /v1/names/a%00b HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
        let err = parse("GET /v1/names/a%0Ab HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_malformed_percent_escape_is_refused() {
        for target in ["/a%", "/a%2", "/a%zz", "/a%+5"] {
            let raw = format!("GET {target} HTTP/1.1\r\n\r\n");
            assert!(parse(&raw).is_err(), "accepted {target}");
        }
    }

    #[test]
    fn a_relative_segment_is_refused() {
        let err = parse("GET /v1/../secret HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
        // And the encoded spelling, which is the one that gets past naive checks.
        let err = parse("GET /v1/%2E%2E/secret HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_oversized_request_line_is_refused_rather_than_buffered() {
        let raw = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(16 * 1024));
        assert_eq!(parse(&raw).unwrap_err().status(), Status::UriTooLong);
    }

    #[test]
    fn an_oversized_body_is_refused_before_it_is_read() {
        let config = crate::Config {
            max_body_bytes: 8,
            ..crate::Config::default()
        };
        let raw = "POST /v1/query HTTP/1.1\r\nContent-Length: 9\r\n\r\n123456789";
        let mut reader = BufReader::new(raw.as_bytes());
        assert_eq!(
            read_request(&mut reader, &config).unwrap_err(),
            WireError::BodyTooLarge
        );
    }

    #[test]
    fn a_body_shorter_than_its_declared_length_is_refused() {
        let err = parse("POST /v1/query HTTP/1.1\r\nContent-Length: 20\r\n\r\nshort").unwrap_err();
        assert!(matches!(err, WireError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_unknown_method_is_not_treated_as_a_get() {
        let err = parse("DELETE /v1/status HTTP/1.1\r\n\r\n").unwrap_err();
        assert_eq!(err.status(), Status::MethodNotAllowed);
    }

    #[test]
    fn http_1_0_closes_by_default_and_1_1_does_not() {
        let ten = parse("GET /v1/status HTTP/1.0\r\n\r\n").unwrap();
        assert!(!ten.keep_alive);
        let eleven = parse("GET /v1/status HTTP/1.1\r\n\r\n").unwrap();
        assert!(eleven.keep_alive);
        let closing = parse("GET /v1/status HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        assert!(!closing.keep_alive);
    }

    #[test]
    fn a_version_this_server_does_not_speak_is_refused() {
        let err = parse("GET /v1/status HTTP/2.0\r\n\r\n").unwrap_err();
        assert_eq!(err.status(), Status::VersionNotSupported);
    }

    #[test]
    fn a_closed_connection_is_not_an_error_worth_answering() {
        assert_eq!(parse("").unwrap_err(), WireError::Closed);
    }

    #[test]
    fn a_header_value_cannot_inject_another_header() {
        // Nothing today puts attacker-controlled text in a header, which is
        // exactly when a guard like this is cheap to add and easy to forget.
        let response = HttpResponse::binary(Status::Ok, Vec::new())
            .with_header("X-Test", "ok\r\nX-Injected: yes");
        let mut out = Vec::new();
        write_response(&mut out, &response, false, &crate::Config::default()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("X-Injected"), "injected header survived");
    }

    #[test]
    fn a_response_always_declares_its_own_length() {
        let response = HttpResponse::binary(Status::Ok, vec![1, 2, 3]);
        let mut out = Vec::new();
        write_response(&mut out, &response, true, &crate::Config::default()).unwrap();
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("Content-Length: 3\r\n"), "{text}");
        assert!(text.contains("Connection: keep-alive\r\n"), "{text}");
        assert!(
            text.contains("X-Content-Type-Options: nosniff\r\n"),
            "{text}"
        );
        assert!(!text.contains("Server:"), "version disclosed");
    }

    #[test]
    fn a_parse_failure_never_allows_the_connection_to_continue() {
        // After a desync the position in the stream is unknown, so reuse is the
        // vulnerability rather than an optimisation.
        assert!(!Status::BadRequest.allows_keep_alive());
        assert!(!Status::PayloadTooLarge.allows_keep_alive());
        assert!(!Status::NotImplemented.allows_keep_alive());
        assert!(Status::Ok.allows_keep_alive());
    }
}
