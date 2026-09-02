//! Making a data directory a node can start from.
//!
//! # Why the genesis file is bytes rather than text
//!
//! Every node on a chain must agree, byte for byte, on its genesis document —
//! the validator set, the allocations, the council, the parameters. A text format
//! makes that a question about parsers: two implementations that disagree about
//! whether a number is signed, or how a duplicate key resolves, produce two
//! different chains from one file, and the operators find out at the first block.
//! Tendermint has shipped consensus incidents of exactly this shape.
//!
//! So genesis is written with the same canonical codec the ledger uses, and
//! `init` prints its hash. Two operators compare one 64-character string and know
//! they are on the same chain. That is a better property than a file they can
//! read and misread, and the readable form is a `show-genesis` away rather than
//! being the thing consensus depends on.

use std::path::{Path, PathBuf};

use afrolink_consensus::{CountryCode, Validator, ValidatorSet};
use afrolink_crypto::Address;
use afrolink_crypto::hash::{Domain, hash};
use afrolink_executor::{Allocation, ChainParams, Council, Genesis, GenesisLimits};
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{Amount, ChainId, Denom, Timestamp};

use crate::config::{self, Config};
use crate::identity;
use crate::run::log;

/// Why a data directory could not be created.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// A file could not be written.
    #[error("cannot write {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// A key could not be created.
    #[error(transparent)]
    Key(#[from] identity::KeyError),
    /// The chain id was not acceptable.
    #[error("chain id: {0}")]
    ChainId(String),
    /// The genesis file offered was not a genesis document.
    #[error("{path} is not a genesis document")]
    BadGenesis {
        /// The file.
        path: String,
    },
    /// The directory already holds a chain.
    #[error("{path} already holds a genesis; refusing to replace a chain")]
    Exists {
        /// The directory.
        path: String,
    },
    /// The genesis document was refused by the rules it must satisfy.
    #[error("genesis: {0}")]
    Refused(String),
}

/// Create a data directory: keys, a genesis document and a configuration file.
///
/// With `join`, the genesis at that path is adopted rather than a new one being
/// made — which is how a node joins a chain that already exists.
///
/// # Errors
/// Returns an [`InitError`] if anything already present would have to be
/// replaced, or if the genesis cannot be written.
pub fn init(
    dir: &Path,
    chain_id: &str,
    moniker: &str,
    join: Option<&Path>,
) -> Result<(), InitError> {
    let config = Config {
        moniker: moniker.to_owned(),
        data_dir: dir.to_path_buf(),
        ..Config::default()
    };
    let io = |path: &Path| {
        let path = path.display().to_string();
        move |source: std::io::Error| InitError::Io {
            path: path.clone(),
            source,
        }
    };

    if config.genesis_path().exists() {
        // Replacing a genesis is replacing the chain. The store beside it would
        // then hold blocks from a chain the genesis no longer describes, which is
        // a node that starts and then refuses every block it has.
        return Err(InitError::Exists {
            path: dir.display().to_string(),
        });
    }
    std::fs::create_dir_all(dir).map_err(io(dir))?;

    // Keys first: a genesis that names this node as a validator needs its
    // consensus key to exist before it can name it.
    let node_key = identity::create(&config.node_key_path())?;
    let consensus_key = identity::create(&config.consensus_key_path())?;

    let genesis = match join {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(io(path))?;
            decode_exact::<Genesis>(&bytes).map_err(|_| InitError::BadGenesis {
                path: path.display().to_string(),
            })?
        }
        None => devnet_genesis(chain_id, &consensus_key)?,
    };

    // Checked before it is written, not at first start. A genesis that cannot
    // produce a state is a data directory that looks complete and is not.
    let mut trial = afrolink_state::MemoryStore::new();
    genesis
        .apply(&mut trial, GenesisLimits::devnet())
        .map_err(|e| InitError::Refused(e.to_string()))?;

    let bytes = genesis.to_bytes();
    std::fs::write(config.genesis_path(), &bytes).map_err(io(&config.genesis_path()))?;
    let config_path = dir.join("config");
    std::fs::write(&config_path, config::template(&config)).map_err(io(&config_path))?;

    log(&format!("chain      {}", genesis.chain_id));
    log(&format!(
        "genesis    {}",
        hash(Domain::GenesisId, &bytes).to_hex()
    ));
    log(&format!(
        "node id    {}",
        hex::encode(node_key.public_key().to_bytes())
    ));
    log(&format!(
        "validator  {}",
        Address::from_public_key(&consensus_key.public_key())
    ));
    log(&format!("config     {}", config_path.display()));
    log("compare the genesis hash with every other operator before starting");
    Ok(())
}

/// A one-validator chain, for a machine to talk to itself on.
///
/// Explicitly a devnet: one validator means one country, no fault tolerance and
/// a validator set that cannot lose anybody. A real chain's genesis is negotiated
/// between its founding validators and adopted with `--join`, not generated by
/// whoever ran `init` first.
fn devnet_genesis(
    chain_id: &str,
    consensus_key: &afrolink_crypto::SecretKey,
) -> Result<Genesis, InitError> {
    let chain_id = ChainId::new(chain_id).map_err(|e| InitError::ChainId(e.to_string()))?;
    let address = Address::from_public_key(&consensus_key.public_key());
    let validators = ValidatorSet::new(vec![Validator::new(
        consensus_key.public_key(),
        1,
        CountryCode::UNSPECIFIED,
    )])
    .map_err(|e| InitError::Refused(e.to_string()))?;

    Ok(Genesis {
        chain_id,
        genesis_time: Timestamp::from_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
                .unwrap_or(0),
        ),
        validators,
        // AFRI has no issuer by construction: it is minted here and never again.
        issuers: Vec::new(),
        attestors: Vec::new(),
        council: Council::devnet(address),
        params: ChainParams::devnet(),
        allocations: vec![Allocation {
            address,
            denom: Denom::native(),
            amount: Amount::from_afri(1_000_000),
        }],
    })
}

/// Where `init` puts things by default.
#[must_use]
pub fn default_dir() -> PathBuf {
    PathBuf::from("./afrolink-data")
}
