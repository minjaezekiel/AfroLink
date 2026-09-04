//! The daemon: opening a store, joining a network, and driving consensus.
//!
//! # What was missing until this existed
//!
//! Every piece below was written, tested and reachable from nothing but
//! `cargo test`. The executor could execute, the consensus driver could decide,
//! the transport could gossip and the store could persist — and no artefact in
//! the workspace put them in the same process and let go. This is that artefact,
//! and assembling it is where the seams between those crates finally get used in
//! anger rather than described.
//!
//! # The clock lives here and nowhere else
//!
//! [`Node`] has no clock: timeouts reach it as `Event::Timeout` and it returns
//! `Action::ScheduleTimeout` rather than sleeping. That is what makes the
//! deterministic Byzantine simulator possible, and it means *something* has to
//! own the real clock. This loop is that something, and it is the only place in
//! the workspace that reads the time to decide anything.
//!
//! # A node that is behind does not propose
//!
//! The rule that makes block sync and consensus fit together. A validator that
//! has fallen behind is entitled to propose the moment its turn comes round, and
//! a block it built on stale state would be voted down by everyone who is not
//! behind — wasting a round and, on a small validator set, stalling the chain
//! while it happens. So a node that knows a peer holds a height it does not
//! catches up first and proposes second.
//!
//! # Failing to persist is fatal
//!
//! A node that cannot write its own chain stops. Carrying on would mean serving
//! queries about blocks that will not survive a restart, and voting on a history
//! only this process can see.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use afrolink_crypto::hash::{Domain, hash};
use afrolink_executor::GenesisLimits;
use afrolink_http::{Config as HttpConfig, Server};
use afrolink_node::SignRecord;
use afrolink_node::{Node, SharedNode};
use afrolink_p2p::addrbook::AddrBook;
use afrolink_p2p::manager::{Limits, Manager};
use afrolink_p2p::peer::PeerId;
use afrolink_p2p::transport::Transport;
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_store::ChainStore;

use crate::chain::{Blocks, LiveChain, Persist};
use crate::config::Config;
use crate::driver::{Beat, Driver, StopWatchdog, Timings};
use crate::identity;

/// Why the daemon could not start, or had to stop.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// A key file was missing, malformed or too permissive.
    #[error(transparent)]
    Key(#[from] crate::identity::KeyError),
    /// The database could not be opened, read or written.
    #[error("store: {0}")]
    Store(String),
    /// The data directory holds no genesis document.
    #[error("no genesis in {0}: run `afrolinkd init` first")]
    NoGenesis(String),
    /// The signing record could not be opened.
    #[error("{0}")]
    Signing(String),
    /// The genesis file is not a genesis document.
    #[error("{0} is not a genesis document")]
    BadGenesis(String),
    /// The genesis file does not match the chain in the store.
    #[error(
        "{0} does not match the genesis this store was built on; \
         a node cannot change the chain it is already following"
    )]
    GenesisChanged(String),
    /// A socket could not be bound.
    #[error("cannot bind {what} on {addr}: {source}")]
    Bind {
        /// Which listener.
        what: &'static str,
        /// The address asked for.
        addr: String,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The peer-to-peer transport failed to start.
    #[error("p2p: {0}")]
    Transport(String),
    /// A write to the chain store failed while running.
    #[error("halted: {0}")]
    Halted(String),
}

impl From<crate::driver::Halted> for RunError {
    fn from(halted: crate::driver::Halted) -> Self {
        Self::Halted(halted.0)
    }
}

impl From<afrolink_store::StoreError> for RunError {
    fn from(e: afrolink_store::StoreError) -> Self {
        Self::Store(e.to_string())
    }
}

/// Take the genesis from the data directory into the store, once and only once.
///
/// The file is what an operator hands around and compares hashes of; the store is
/// what the node runs on. On a fresh directory the file becomes the store's
/// genesis. On every start after that they are **compared**, and a mismatch is
/// fatal.
///
/// The comparison is the part worth having. Editing a genesis file beside a store
/// that already holds blocks is an easy mistake — copying a colleague's file into
/// a directory that is already running, say — and it produces a node whose blocks
/// were built under rules its genesis no longer describes. Without this check that
/// node starts, and finds out at the first state root it computes.
fn adopt_genesis(
    config: &Config,
    store: &ChainStore,
) -> Result<afrolink_executor::Genesis, RunError> {
    let path = config.genesis_path();
    let on_disk = std::fs::read(&path).ok();

    match (store.genesis()?, on_disk) {
        (Some(stored), Some(bytes)) => {
            if stored.to_bytes() != bytes {
                return Err(RunError::GenesisChanged(path.display().to_string()));
            }
            Ok(stored)
        }
        // A store that already holds a chain, and a genesis file somebody removed.
        // The store's copy is the one the blocks were built under, so it wins.
        (Some(stored), None) => Ok(stored),
        (None, Some(bytes)) => {
            let genesis = decode_exact::<afrolink_executor::Genesis>(&bytes)
                .map_err(|_| RunError::BadGenesis(path.display().to_string()))?;
            store.put_genesis(&genesis)?;
            log(&format!(
                "adopted genesis {}",
                hash(Domain::GenesisId, &bytes).to_hex()
            ));
            Ok(genesis)
        }
        (None, None) => Err(RunError::NoGenesis(config.data_dir.display().to_string())),
    }
}

/// Run a node until it is asked to stop.
///
/// # Errors
/// Returns a [`RunError`] if the node cannot start, or if it had to halt.
pub fn start(config: &Config, stop: &Arc<AtomicBool>) -> Result<(), RunError> {
    let limits = GenesisLimits::devnet();

    // -- keys ---------------------------------------------------------------
    let node_key = identity::load(&config.node_key_path())?;
    let consensus_key = identity::load(&config.consensus_key_path())?;
    let peer_id = PeerId::new(node_key.public_key());

    // -- store and state ----------------------------------------------------
    let store = Arc::new(ChainStore::open(config.db_path())?);
    let genesis = adopt_genesis(config, &store)?;
    let chain_id = genesis.chain_id.clone();
    let validators = genesis.validators.clone();

    // The fast path is a single root lookup; replay is the repair path, and its
    // app-hash check is what turns a corrupted store into a refusal to start
    // rather than a silent fork.
    let (state, tip, replayed) = store.open_state(limits)?;
    log(&format!(
        "{} on {} — resuming at height {} ({})",
        config.moniker,
        chain_id,
        tip.header.height.0,
        if replayed {
            "replayed from genesis"
        } else {
            "loaded from the state tree"
        }
    ));

    // Opened before the node runs, and fatal if it cannot be read: a validator
    // whose signing history is unknown must not sign.
    let signing = Arc::new(
        crate::signing::FileSignRecord::open(config.sign_state_path())
            .map_err(RunError::Signing)?,
    );
    if let Some((height, round, step)) = signing.last() {
        log(&format!(
            "last signed  height {} round {} {step:?}",
            height.0, round.0
        ));
    }
    let node = Node::new(
        chain_id.clone(),
        consensus_key,
        validators,
        state.clone(),
        &tip,
    )
    .with_sign_record(signing);
    let is_validator = node.is_proposer(afrolink_primitives::Round(0))
        || node.address() != afrolink_crypto::Address::from_public_key(&node_key.public_key());
    let _ = is_validator;
    let shared = Arc::new(SharedNode::new(node));

    // -- what queries read, and what a failed write does --------------------
    let published = Arc::new(Mutex::new(state));
    let halted: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let sink = Arc::new(Persist::new(
        Arc::clone(&store),
        Arc::clone(&published),
        Arc::clone(&halted),
    ));

    // -- peers --------------------------------------------------------------
    let mut manager = Manager::new(
        peer_id,
        AddrBook::new(&node_key),
        Limits {
            max_outbound: config.max_outbound,
            max_inbound: config.max_inbound,
            ..Limits::default()
        },
    );
    for seed in &config.seeds {
        // Seeds go into the address book rather than being dialled directly, so
        // they are subject to the same group-diversity rule as any other
        // candidate. A seed list that bypassed it would be a list of addresses an
        // operator can use to eclipse their own node by accident.
        manager.book_mut().add(*seed, seed.group());
    }

    // Last run's peers, dialled before the book. A restart is when an eclipse is
    // cheapest — every outbound slot is on offer at once, drawn from a book an
    // attacker has had hours to shape — and this keeps two of them off the table.
    // The file is consumed by reading it, so a crash-loop is not pinned to peers
    // that may be the reason it is looping.
    let anchors = crate::anchors::take(&config.anchors_path());
    if !anchors.is_empty() {
        log(&format!(
            "dialling {} anchor{} from the last run first",
            anchors.len(),
            if anchors.len() == 1 { "" } else { "s" }
        ));
        manager.seed_anchors(anchors);
    }

    let transport = Transport::start(
        chain_id.clone(),
        node_key,
        Arc::clone(&shared),
        manager,
        config.p2p_listen,
        Arc::new(Blocks(Arc::clone(&store))),
        sink,
    )
    .map_err(|e| RunError::Transport(e.to_string()))?;
    log(&format!(
        "peer id {} listening on {}",
        hex::encode(peer_id.key().to_bytes()),
        transport.local_addr()
    ));

    // -- queries ------------------------------------------------------------
    let http = match config.rpc_listen {
        Some(addr) => {
            let server =
                Server::bind(addr, HttpConfig::default()).map_err(|source| RunError::Bind {
                    what: "the query server",
                    addr: addr.to_string(),
                    source,
                })?;
            log(&format!("queries on http://{}", server.local_addr()));
            let view = LiveChain::new(chain_id, Arc::clone(&store), Arc::clone(&published));
            let submit = Arc::clone(&shared);
            let handle = server.handle();
            std::thread::spawn(move || {
                if let Err(e) = server.run(&view, &*submit) {
                    log(&format!("query server stopped: {e}"));
                }
            });
            Some(handle)
        }
        None => {
            log("queries disabled");
            None
        }
    };

    // -- the loop -----------------------------------------------------------
    let outcome = drive(config, &transport, &shared, stop, &halted);

    log("stopping");
    // Bounded from here on. `docker stop` allows ten seconds, Kubernetes thirty
    // and systemd ninety, and each then sends SIGKILL; a stop that outlives the
    // shortest of those has lost the work it was trying to finish anyway. An exit
    // we choose can say why in the log, and a SIGKILL cannot.
    let _watchdog = StopWatchdog::start();
    // Before the transport is torn down, while there is still a peer set to read.
    let anchors = transport.anchors();
    if let Err(e) = crate::anchors::put(&config.anchors_path(), &anchors) {
        log(&format!("could not write anchors: {e}"));
    } else if !anchors.is_empty() {
        log(&format!(
            "kept {} anchor(s) for the next run",
            anchors.len()
        ));
    }
    transport.handle().stop();
    if let Some(handle) = http {
        handle.stop();
    }
    outcome
}

/// The consensus loop.
///
/// Thin on purpose. Everything it used to do lives in [`crate::driver::Driver`],
/// which the cluster harness drives too — see that module for why a second
/// hand-written copy of this loop was a liability rather than a convenience.
fn drive(
    config: &Config,
    transport: &Transport,
    shared: &Arc<SharedNode>,
    stop: &Arc<AtomicBool>,
    halted: &Arc<Mutex<Option<String>>>,
) -> Result<(), RunError> {
    let mut driver = Driver::new(
        Timings::from_config(config),
        Arc::clone(halted),
        Instant::now(),
    );
    while !stop.load(Ordering::SeqCst) {
        // The `?` is the point: a node that cannot write its own chain stops
        // here, and the type system is what makes that unmissable.
        if let Beat::Committed(height) = driver.step(Instant::now(), transport, shared, true)? {
            log(&format!("height {}", height.0));
        }
        std::thread::sleep(driver.poll());
    }
    Ok(())
}

/// One line to standard error, with a timestamp.
///
/// No logging framework, deliberately: a payments daemon's dependency tree is a
/// supply-chain surface, and what this needs is a line of text with a time on it.
pub fn log(message: &str) {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    eprintln!("[{millis}] {message}");
}
