//! Sockets, threads and the limits that bound them.
//!
//! # The model
//!
//! One blocking thread per connection, capped. No async runtime, no executor,
//! no dependency beyond `std`.
//!
//! This is a deliberate choice rather than a shortcut. The workload is
//! read-only queries answered from an in-memory tree; the interesting cost is
//! hashing a Merkle path, which is CPU, not waiting. Thread-per-connection is
//! the wrong model for a hundred thousand idle websockets and an entirely
//! reasonable one for a few hundred concurrent proof requests. What it buys is
//! that `crates/node` stays synchronous — which is what makes the deterministic
//! Byzantine simulator possible — and that the dependency tree does not grow by
//! two orders of magnitude to serve a read endpoint.
//!
//! # [`respond`] is the seam
//!
//! Everything that decides *what* to answer is a pure function from a
//! [`Request`] to an [`HttpResponse`]. Everything below it moves bytes. So the
//! status codes, the routing and the format negotiation are all tested without
//! binding a port, and the socket layer has almost no logic left to be wrong
//! about.
//!
//! # Shutdown
//!
//! [`Handle::stop`] sets a flag and then connects to the listener once, to wake
//! the blocked `accept`. Polling with a timeout would cost either idle CPU or
//! accept latency; this costs one loopback connection, once.
//!
//! Connections already open are allowed to finish their current request. A
//! keep-alive connection sitting idle is not interrupted, so a shutdown can
//! take up to [`Config::read_timeout`] to complete.

use std::io::{BufReader, BufWriter, ErrorKind, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use afrolink_primitives::codec::Encode;
use afrolink_rpc::{ChainView, QueryError, answer};

use crate::route::{Format, Route, RouteError};
use crate::wire::{HttpResponse, Request, Status, WireError, read_request, write_response};
use crate::{Config, json, route};

/// Turn a request into an answer, without touching a socket.
///
/// # Panics
/// Never. Every failure path produces a status code.
#[must_use]
pub fn respond<V: ChainView + ?Sized>(view: &V, request: &Request) -> HttpResponse {
    let route = match route::route(request) {
        Ok(route) => route,
        Err(error) => return from_route_error(&error),
    };

    match route {
        Route::Preflight => HttpResponse {
            status: Status::NoContent,
            content_type: crate::wire::CONTENT_TYPE_JSON,
            body: Vec::new(),
            extra: Vec::new(),
        }
        .with_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .with_header("Access-Control-Allow-Headers", "content-type, accept")
        .with_header("Access-Control-Max-Age", "86400"),

        // The route table is documentation, so it is JSON whatever was asked
        // for. A developer who reaches `/` has not yet learned to ask.
        Route::Index => HttpResponse::json(Status::Ok, json::index()),

        Route::Health => match view.tip_height() {
            Ok(height) => HttpResponse::json(
                Status::Ok,
                format!("{{\"status\":\"ok\",\"height\":{}}}", height.0),
            ),
            // A node whose store will not answer is not healthy, and saying so
            // is the entire point of the endpoint.
            Err(_) => HttpResponse::error(Status::Unavailable, "node cannot read its own store"),
        },

        Route::Chain(query) => {
            let format = match route::format(request) {
                Ok(format) => format,
                Err(error) => return from_route_error(&error),
            };
            match answer(view, &query) {
                Ok(response) => {
                    let body = match format {
                        Format::Binary => HttpResponse::binary(Status::Ok, response.to_bytes()),
                        Format::Json => HttpResponse::json(Status::Ok, json::response(&response)),
                    };
                    // The answer depends on `Accept`, so any cache between here
                    // and the client has to key on it.
                    body.with_header("Vary", "Accept")
                }
                Err(error) => from_query_error(&error),
            }
        }
    }
}

fn from_route_error(error: &RouteError) -> HttpResponse {
    let response = HttpResponse::error(error.status(), &error.message());
    match error {
        RouteError::MethodNotAllowed { allow } => response.with_header("Allow", allow),
        RouteError::NotFound | RouteError::BadRequest(_) => response,
    }
}

fn from_query_error(error: &QueryError) -> HttpResponse {
    match error {
        // Safe to echo: the client already knew the height, it asked for it.
        QueryError::NoSuchHeight(height) => HttpResponse::error(
            Status::NotFound,
            &format!("height {height} is not available on this node"),
        ),
        // The block is here but its certificate is not — which happens
        // transiently at the tip. Retrying is the right response, so say 503.
        QueryError::NoCommit(height) => HttpResponse::error(
            Status::Unavailable,
            &format!("height {height} has no commit stored yet"),
        ),
        // Deliberately not echoed. A backend message carries file paths and
        // database internals, and this endpoint answers strangers.
        QueryError::Backend(_) => {
            HttpResponse::error(Status::InternalError, "the node could not read its state")
        }
    }
}

/// A running server's remote control.
///
/// Cloneable and `Send`, so a signal handler or a test can stop a server that
/// is blocked in `accept`.
#[derive(Debug, Clone)]
pub struct Handle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Handle {
    /// The address the server is listening on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Ask the accept loop to stop.
    ///
    /// Sets the flag, then makes one connection to wake `accept`. The
    /// connection is closed immediately and never becomes a request.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(self.addr) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Whether a stop has been requested.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// A bound listener, ready to serve.
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    config: Config,
    stop: Arc<AtomicBool>,
}

impl Server {
    /// Bind a listener.
    ///
    /// # Errors
    /// Whatever binding the address produced.
    pub fn bind(addr: impl ToSocketAddrs, config: Config) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        Ok(Self {
            listener,
            addr,
            config,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The address actually bound.
    ///
    /// Port 0 is the normal way to run this in a test, so the caller has to be
    /// able to ask which port it got.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// A handle that can stop this server.
    #[must_use]
    pub fn handle(&self) -> Handle {
        Handle {
            addr: self.addr,
            stop: Arc::clone(&self.stop),
        }
    }

    /// Serve until [`Handle::stop`] is called.
    ///
    /// Borrows the view rather than owning it, so a node can keep the
    /// authoritative copy and the read/write split stays visible to the borrow
    /// checker instead of living in a comment.
    ///
    /// # Errors
    /// Only a listener failure that is not recoverable by continuing.
    pub fn run<V: ChainView + Sync + ?Sized>(&self, view: &V) -> std::io::Result<()> {
        let live = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            loop {
                let stream = match self.listener.accept() {
                    Ok((stream, _peer)) => stream,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        if self.stop.load(Ordering::SeqCst) {
                            break;
                        }
                        // Descriptor exhaustion and similar transient failures
                        // would otherwise spin this loop at full speed.
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                };

                if self.stop.load(Ordering::SeqCst) {
                    break;
                }

                if live.load(Ordering::SeqCst) >= self.config.max_connections {
                    // Refused on this thread, without spawning. Queuing instead
                    // would turn a load spike into an unbounded backlog, which
                    // is the same failure with a longer fuse.
                    refuse(stream, &self.config);
                    continue;
                }

                live.fetch_add(1, Ordering::SeqCst);
                let live = &live;
                scope.spawn(move || {
                    serve_connection(stream, view, &self.config, &self.stop);
                    live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        Ok(())
    }
}

/// Tell a client the node is at capacity, then close.
fn refuse(stream: TcpStream, config: &Config) {
    let _ = stream.set_write_timeout(Some(config.write_timeout));
    let mut writer = BufWriter::new(&stream);
    let response = HttpResponse::error(Status::Unavailable, "node is at capacity");
    let _ = write_response(&mut writer, &response, false, config);
    let _ = writer.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Read and answer requests on one connection until it ends.
fn serve_connection<V: ChainView + ?Sized>(
    stream: TcpStream,
    view: &V,
    config: &Config,
    stop: &AtomicBool,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(config.read_timeout));
    let _ = stream.set_write_timeout(Some(config.write_timeout));

    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(write_half);

    for _ in 0..config.max_requests_per_connection {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let (response, keep_alive) = match read_request(&mut reader, config) {
            Ok(request) => {
                let response = respond(view, &request);
                let keep = request.keep_alive && response.status.allows_keep_alive();
                (response, keep)
            }
            // The ordinary end of a keep-alive connection. Nothing to answer.
            Err(WireError::Closed) => break,
            Err(error) => {
                // After a parse failure the position in the byte stream is no
                // longer known, so the connection must not be reused — that is
                // exactly the desync `wire` refuses to be half of.
                (
                    HttpResponse::error(error.status(), &error.to_string()),
                    false,
                )
            }
        };

        if write_response(&mut writer, &response, keep_alive, config).is_err() {
            break;
        }
        if !keep_alive {
            break;
        }
    }

    if let Ok(stream) = writer.into_inner() {
        let _ = stream.shutdown(Shutdown::Both);
    }
}
