//! What an operator configures, and how it is read off disk.
//!
//! # Why this parser exists rather than a dependency
//!
//! The workspace has no serde and no TOML crate, and this is not the file to
//! introduce one for. The format is a deliberately small thing: `key = value`,
//! one per line, `#` to end of line is a comment, unknown keys are an **error**
//! rather than a shrug.
//!
//! Refusing unknown keys is the part worth arguing for. A config parser that
//! ignores what it does not understand is how an operator sets `max_inbound` in a
//! file whose field is spelled `max_peers` and never finds out — the node runs,
//! reports nothing wrong, and is configured as though the line were absent. On a
//! validator that difference is money.
//!
//! # What is not configurable
//!
//! Consensus rules. Block size, the unbonding period, the quorum threshold and
//! every other number a validator must agree with its peers about live in
//! genesis and in governance, never here. A node that could be told its own
//! consensus parameters by a local file is a node that can be forked off the
//! network by an editing mistake.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use afrolink_crypto::PublicKey;
use afrolink_p2p::peer::{PeerAddr, PeerId};

/// Why a configuration file was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Unreadable {
        /// The file asked for.
        path: String,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// A line was not `key = value`.
    #[error("line {line}: expected `key = value`, got `{text}`")]
    Malformed {
        /// One-based line number.
        line: usize,
        /// The offending line.
        text: String,
    },
    /// A key this build does not know.
    #[error("line {line}: unknown setting `{key}`")]
    UnknownKey {
        /// One-based line number.
        line: usize,
        /// The key as written.
        key: String,
    },
    /// A value that could not be read as what its key requires.
    #[error("line {line}: `{key}` cannot be `{value}`: {why}")]
    BadValue {
        /// One-based line number.
        line: usize,
        /// The key.
        key: String,
        /// The value as written.
        value: String,
        /// What was wrong with it.
        why: String,
    },
    /// The same key twice.
    #[error("line {line}: `{key}` is set more than once")]
    Duplicate {
        /// One-based line number.
        line: usize,
        /// The key.
        key: String,
    },
}

/// How this node runs.
#[derive(Debug, Clone)]
pub struct Config {
    /// A name for this node, used only in logs.
    pub moniker: String,
    /// Where the database and keys live.
    pub data_dir: PathBuf,
    /// Where peers connect.
    pub p2p_listen: SocketAddr,
    /// Where peers should be told to connect, if that differs from
    /// [`Self::p2p_listen`].
    ///
    /// # Why a node cannot work this out for itself
    ///
    /// A node advertises its listening address in the handshake so that the
    /// network can learn about it at all — without it, a node is dialable only
    /// by whoever already dialled it, and the topology stays anchored on
    /// whoever ran the seeds.
    ///
    /// The bound address is the right answer for a node on one concrete
    /// interface. It is the wrong answer twice over for a node behind NAT, a
    /// load balancer or a port mapping, and it is *no* answer for the default
    /// `0.0.0.0`, which means "every interface" to a listener and nothing to a
    /// dialler. In all three cases the operator is the only party that knows,
    /// so this is where they say.
    ///
    /// Left unset, the node advertises its bound address when that address is
    /// concrete and advertises nothing when it is not. Advertising nothing is a
    /// working state, not a broken one: the node dials out and is simply never
    /// dialled.
    ///
    /// CometBFT's `external_address` and Bitcoin's `-externalip` are the same
    /// knob for the same reason.
    pub advertise: Option<SocketAddr>,
    /// Where clients query, or `None` to serve no queries at all.
    ///
    /// Optional because a validator has no business exposing a public read
    /// endpoint: the cheapest thing on this network to point a botnet at is an
    /// RPC port on a machine that also signs blocks.
    pub rpc_listen: Option<SocketAddr>,
    /// Peers to dial on startup.
    pub seeds: Vec<PeerAddr>,
    /// Outbound connections. Each must be into a distinct address group.
    pub max_outbound: usize,
    /// Inbound connections accepted.
    pub max_inbound: usize,
    /// How long to wait for a proposal before prevoting nil.
    pub timeout_propose_ms: u64,
    /// How long to wait for prevotes before precommitting nil.
    pub timeout_prevote_ms: u64,
    /// How long to wait for precommits before moving to the next round.
    pub timeout_precommit_ms: u64,
    /// Shortest time between one commit and the next proposal.
    ///
    /// Without it a chain with an empty mempool commits empty blocks as fast as
    /// the machine can sign them, which is a way to fill a disk with nothing.
    pub block_interval_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            moniker: "afrolink-node".to_owned(),
            data_dir: PathBuf::from("./afrolink-data"),
            // All interfaces for peers: a node nobody can reach cannot be dialled,
            // and unreachable nodes are what makes a network a star.
            p2p_listen: "0.0.0.0:26656"
                .parse()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 26656))),
            // Unset: the node advertises its bound address if that address names
            // one interface, and otherwise says nothing at all.
            advertise: None,
            // Loopback for queries: exposing it is a decision, not a default.
            rpc_listen: Some(
                "127.0.0.1:26657"
                    .parse()
                    .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 26657))),
            ),
            seeds: Vec::new(),
            max_outbound: 8,
            max_inbound: 40,
            timeout_propose_ms: 3_000,
            timeout_prevote_ms: 1_000,
            timeout_precommit_ms: 1_000,
            block_interval_ms: 1_000,
        }
    }
}

impl Config {
    /// Read a configuration file.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`]: an unreadable file, a malformed line,
    /// an unknown key, a duplicate key, or a value of the wrong shape.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Read a configuration from text.
    ///
    /// # Errors
    /// As [`Self::load`], minus the read failure.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        let mut seen: Vec<String> = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line = index.saturating_add(1);
            // A comment runs to the end of the line, so a seed list can be
            // annotated without a second syntax for it.
            let content = raw.split('#').next().unwrap_or("").trim();
            if content.is_empty() {
                continue;
            }
            let Some((key, value)) = content.split_once('=') else {
                return Err(ConfigError::Malformed {
                    line,
                    text: content.to_owned(),
                });
            };
            let key = key.trim().to_owned();
            let value = value.trim();
            if seen.contains(&key) {
                return Err(ConfigError::Duplicate { line, key });
            }
            seen.push(key.clone());
            config.set(line, &key, value)?;
        }
        Ok(config)
    }

    fn set(&mut self, line: usize, key: &str, value: &str) -> Result<(), ConfigError> {
        let bad = |why: &str| ConfigError::BadValue {
            line,
            key: key.to_owned(),
            value: value.to_owned(),
            why: why.to_owned(),
        };
        match key {
            "moniker" => self.moniker = value.to_owned(),
            "data_dir" => self.data_dir = PathBuf::from(value),
            "p2p_listen" => {
                self.p2p_listen = value.parse().map_err(|_| bad("not a host:port address"))?;
            }
            "advertise" => {
                // "auto" rather than an empty value, matching `rpc_listen`'s
                // "off": what a node tells the network about itself should be
                // written down, not left blank.
                self.advertise = if value.eq_ignore_ascii_case("auto") {
                    None
                } else {
                    Some(value.parse().map_err(|_| bad("not a host:port address"))?)
                };
            }
            "rpc_listen" => {
                // "off" rather than an empty value, so switching the query server
                // off is something written down rather than something left blank.
                self.rpc_listen = if value.eq_ignore_ascii_case("off") {
                    None
                } else {
                    Some(value.parse().map_err(|_| bad("not a host:port address"))?)
                };
            }
            "seeds" => {
                self.seeds = parse_seeds(value).map_err(|why| bad(&why))?;
            }
            "max_outbound" => self.max_outbound = parse_positive(value).map_err(|why| bad(&why))?,
            "max_inbound" => self.max_inbound = parse_positive(value).map_err(|why| bad(&why))?,
            "timeout_propose_ms" => {
                self.timeout_propose_ms = parse_millis(value).map_err(|why| bad(&why))?;
            }
            "timeout_prevote_ms" => {
                self.timeout_prevote_ms = parse_millis(value).map_err(|why| bad(&why))?;
            }
            "timeout_precommit_ms" => {
                self.timeout_precommit_ms = parse_millis(value).map_err(|why| bad(&why))?;
            }
            "block_interval_ms" => {
                self.block_interval_ms = value.parse().map_err(|_| bad("not a number"))?;
            }
            _ => {
                return Err(ConfigError::UnknownKey {
                    line,
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// The file this node's network key lives in.
    #[must_use]
    pub fn node_key_path(&self) -> PathBuf {
        self.data_dir.join("node_key")
    }

    /// The file this node's consensus key lives in.
    ///
    /// Separate from the network key on purpose: a node that relays blocks holds
    /// no stake and signs no votes, so running one must not require the key that
    /// does. They are different files so that they can one day live on different
    /// machines.
    #[must_use]
    pub fn consensus_key_path(&self) -> PathBuf {
        self.data_dir.join("consensus_key")
    }

    /// The file recording what this validator has already signed.
    ///
    /// Beside the consensus key, and created with it. Tendermint splitting the
    /// key from its state into files that could be copied separately is exactly
    /// how the two get out of sync, and an out-of-sync pair is a double-sign.
    #[must_use]
    pub fn sign_state_path(&self) -> PathBuf {
        self.data_dir.join("consensus_key.state")
    }

    /// The file the genesis document lives in.
    #[must_use]
    pub fn genesis_path(&self) -> PathBuf {
        self.data_dir.join("genesis")
    }

    /// The directory the database lives in.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("chain.redb")
    }

    /// The file holding the peers to dial first after a restart.
    ///
    /// See [`crate::anchors`] for why it exists and why it is deleted on read.
    #[must_use]
    pub fn anchors_path(&self) -> PathBuf {
        self.data_dir.join("anchors")
    }
}

/// `hex@host:port, hex@host:port`
fn parse_seeds(value: &str) -> Result<Vec<PeerAddr>, String> {
    let mut seeds = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((id, addr)) = entry.split_once('@') else {
            return Err(format!("`{entry}` is not `<node-id-hex>@<host:port>`"));
        };
        // The identity is required rather than optional, and that is the whole
        // difference between a seed list and a list of addresses. Dialling an
        // address without knowing whose it is means accepting whoever answers,
        // which is exactly the position an on-path attacker wants a new node in.
        let bytes = hex::decode(id.trim()).map_err(|_| format!("`{id}` is not hex"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("`{id}` is not a 32-byte node id"))?;
        let key =
            PublicKey::from_bytes(&bytes).map_err(|_| format!("`{id}` is not a valid key"))?;
        let socket: SocketAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("`{addr}` is not a host:port address"))?;
        seeds.push(PeerAddr::new(PeerId::new(key), socket));
    }
    Ok(seeds)
}

fn parse_positive(value: &str) -> Result<usize, String> {
    let n: usize = value.parse().map_err(|_| "not a number".to_owned())?;
    if n == 0 {
        // Zero outbound connections is a node that cannot join a network, and
        // zero inbound is one nobody can join through. Both are almost certainly
        // a mistake and neither has a use worth the confusion of allowing it.
        return Err("must be at least 1".to_owned());
    }
    Ok(n)
}

fn parse_millis(value: &str) -> Result<u64, String> {
    let n: u64 = value.parse().map_err(|_| "not a number".to_owned())?;
    if n == 0 {
        // A consensus timeout of zero fires before any message can arrive, so
        // every round times out and the chain never commits. It looks like a
        // "fast" setting and is a halt.
        return Err("a consensus timeout of zero never lets a round finish".to_owned());
    }
    Ok(n)
}

/// The configuration file written by `afrolinkd init`.
///
/// Every setting appears, commented with what it does, because a config file
/// whose defaults are invisible is one an operator edits by guesswork.
#[must_use]
pub fn template(config: &Config) -> String {
    let seeds = config
        .seeds
        .iter()
        .map(|s| format!("{}@{}", hex::encode(s.id.key().to_bytes()), s.addr))
        .collect::<Vec<_>>()
        .join(", ");
    let rpc = config
        .rpc_listen
        .map_or_else(|| "off".to_owned(), |a| a.to_string());
    format!(
        "# afrolinkd configuration.\n\
         #\n\
         # Consensus rules are NOT here. Block size, the unbonding period and the\n\
         # quorum threshold live in genesis and in governance, because a node that\n\
         # could be told its own consensus parameters by a local file is a node an\n\
         # editing mistake can fork off the network.\n\
         #\n\
         # Unknown settings are an error rather than a warning: a config parser\n\
         # that ignores what it does not understand is how a misspelled line goes\n\
         # unnoticed forever.\n\
         \n\
         # A name for this node. Appears in logs and nowhere else.\n\
         moniker = {moniker}\n\
         \n\
         # Where the database, the keys and the genesis document live.\n\
         data_dir = {data_dir}\n\
         \n\
         # Where peers connect. All interfaces by default: a node nobody can reach\n\
         # cannot be dialled, and unreachable nodes are what turn a network into a\n\
         # star with somebody else at the centre.\n\
         p2p_listen = {p2p}\n\
         \n\
         # What to tell peers about where they can reach this node. `auto` uses\n\
         # the address above, which is right for a node on one concrete\n\
         # interface and wrong for one behind NAT, a load balancer or a port\n\
         # mapping — and is no answer at all for `0.0.0.0`, which names every\n\
         # interface to a listener and nothing to a dialler. A node that\n\
         # advertises nothing dials out and is never dialled, which is a working\n\
         # state and the right one for a node that does not want to be reached.\n\
         advertise = {advertise}\n\
         \n\
         # Where clients query. Loopback by default, `off` to serve nothing —\n\
         # exposing a read endpoint on a machine that signs blocks is a decision,\n\
         # not a default.\n\
         rpc_listen = {rpc}\n\
         \n\
         # Peers to dial at startup, as `<node-id-hex>@<host:port>`, comma\n\
         # separated. The identity is required: dialling an address without\n\
         # knowing whose it is means accepting whoever answers.\n\
         seeds = {seeds}\n\
         \n\
         # Connections this node makes. Each must be into a distinct address\n\
         # group, which is the eclipse defence — so raising this past the number\n\
         # of distinct groups the node knows about buys nothing.\n\
         max_outbound = {max_outbound}\n\
         \n\
         # Connections this node accepts.\n\
         max_inbound = {max_inbound}\n\
         \n\
         # Consensus timeouts, in milliseconds. These are local patience, not\n\
         # consensus rules: a node with different values still agrees with the\n\
         # network about what committed, it just waits differently before voting\n\
         # nil. Too short on a slow link means voting nil on proposals that were\n\
         # merely late.\n\
         timeout_propose_ms = {propose}\n\
         timeout_prevote_ms = {prevote}\n\
         timeout_precommit_ms = {precommit}\n\
         \n\
         # Shortest time between a commit and the next proposal. Without it a\n\
         # chain with an empty mempool commits empty blocks as fast as the machine\n\
         # can sign them.\n\
         block_interval_ms = {interval}\n",
        moniker = config.moniker,
        data_dir = config.data_dir.display(),
        p2p = config.p2p_listen,
        advertise = config
            .advertise
            .map_or_else(|| "auto".to_owned(), |a| a.to_string()),
        rpc = rpc,
        seeds = seeds,
        max_outbound = config.max_outbound,
        max_inbound = config.max_inbound,
        propose = config.timeout_propose_ms,
        prevote = config.timeout_prevote_ms,
        precommit = config.timeout_precommit_ms,
        interval = config.block_interval_ms,
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_parse_as_themselves() {
        // The template `init` writes must be readable by the parser that reads
        // it. Obvious, and exactly the kind of thing that rots silently when a
        // field is added to one and not the other.
        let written = template(&Config::default());
        let read = Config::parse(&written).expect("the template this build writes must parse");
        let defaults = Config::default();
        assert_eq!(read.moniker, defaults.moniker);
        assert_eq!(read.p2p_listen, defaults.p2p_listen);
        assert_eq!(read.rpc_listen, defaults.rpc_listen);
        assert_eq!(read.max_outbound, defaults.max_outbound);
        assert_eq!(read.max_inbound, defaults.max_inbound);
        assert_eq!(read.block_interval_ms, defaults.block_interval_ms);
        assert_eq!(read.data_dir, defaults.data_dir);
    }

    #[test]
    fn a_misspelled_setting_is_an_error_rather_than_a_shrug() {
        // The reason this parser refuses unknown keys. An operator who writes
        // `max_peers` and is not told is running a node configured as though the
        // line were not there.
        let error = Config::parse("max_peers = 100").unwrap_err();
        assert!(
            matches!(error, ConfigError::UnknownKey { .. }),
            "got {error}"
        );
    }

    #[test]
    fn the_same_setting_twice_is_refused() {
        // Otherwise which one wins is a matter of parser order, and an operator
        // who left an old line above a new one has no way to tell which is live.
        let error = Config::parse("max_inbound = 10\nmax_inbound = 20").unwrap_err();
        assert!(
            matches!(error, ConfigError::Duplicate { .. }),
            "got {error}"
        );
    }

    #[test]
    fn a_consensus_timeout_of_zero_is_refused() {
        // It reads like a "fast" setting and is a halt: every round times out
        // before a single message can arrive, so nothing ever commits.
        let error = Config::parse("timeout_propose_ms = 0").unwrap_err();
        assert!(matches!(error, ConfigError::BadValue { .. }), "got {error}");
    }

    #[test]
    fn a_node_cannot_be_configured_with_no_way_to_connect() {
        assert!(Config::parse("max_outbound = 0").is_err());
        assert!(Config::parse("max_inbound = 0").is_err());
    }

    #[test]
    fn comments_and_blank_lines_are_not_settings() {
        let config = Config::parse(
            "# a comment\n\
             \n\
             moniker = nairobi   # trailing comment\n",
        )
        .unwrap();
        assert_eq!(config.moniker, "nairobi");
    }

    #[test]
    fn a_seed_without_an_identity_is_refused() {
        // The whole difference between a seed list and a list of addresses.
        // Dialling an address without knowing whose it is means accepting
        // whoever answers, which is the position an on-path attacker wants a new
        // node to be in.
        assert!(Config::parse("seeds = 203.0.113.9:26656").is_err());
    }

    #[test]
    fn a_seed_round_trips_through_the_template() {
        let id = hex::encode(
            afrolink_crypto::SecretKey::from_bytes(&[7; 32])
                .public_key()
                .to_bytes(),
        );
        let config = Config::parse(&format!("seeds = {id}@203.0.113.9:26656")).unwrap();
        assert_eq!(config.seeds.len(), 1);
        let again = Config::parse(&template(&config)).unwrap();
        assert_eq!(again.seeds, config.seeds);
    }

    #[test]
    fn the_query_server_can_be_switched_off_in_words() {
        assert_eq!(Config::parse("rpc_listen = off").unwrap().rpc_listen, None);
        assert!(
            Config::parse("rpc_listen = ").is_err(),
            "an empty value is a mistake, not a way to disable it"
        );
    }

    #[test]
    fn a_line_that_is_not_a_setting_is_reported_with_its_number() {
        let error = Config::parse("moniker = ok\nthis is not a setting\n").unwrap_err();
        let ConfigError::Malformed { line, .. } = error else {
            panic!("expected a malformed line, got {error}");
        };
        assert_eq!(line, 2, "an operator needs to be told where to look");
    }
}
