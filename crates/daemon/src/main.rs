//! `afrolinkd` — the node.
//!
//! Everything else in this workspace is a library that a test drives. This is the
//! one artefact that runs on its own: it opens a database, loads a genesis, joins
//! a network, drives consensus against a real clock and serves queries, until
//! somebody stops it.
//!
//! ```text
//! afrolinkd init  [--dir D] [--chain-id C] [--moniker M] [--join GENESIS]
//! afrolinkd start [--dir D] [--config F]
//! afrolinkd show  [--dir D]
//! ```
//!
//! # No argument-parsing dependency
//!
//! Three subcommands and eight flags do not justify one. The parser below is
//! forty lines and refuses what it does not recognise, for the same reason the
//! configuration parser does: a flag silently ignored is a node running as
//! something other than what it was told to be.

#![deny(missing_docs)]

mod chain;
mod config;
mod identity;
mod init;
mod run;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use config::Config;
use run::log;

const USAGE: &str = "\
afrolinkd — an AfroLink node

USAGE:
    afrolinkd init  [OPTIONS]     create keys, a genesis document and a config
    afrolinkd start [OPTIONS]     run the node
    afrolinkd show  [OPTIONS]     print this node's identity and chain

OPTIONS:
    --dir <PATH>          data directory              [default: ./afrolink-data]
    --config <PATH>       config file                 [default: <dir>/config]
    --chain-id <ID>       chain to create             [init only]
    --moniker <NAME>      a name for this node        [init only]
    --join <PATH>         adopt an existing genesis   [init only]
    -h, --help            print this
";

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            log(&format!("error: {message}"));
            ExitCode::FAILURE
        }
    }
}

/// What the command line asked for.
#[derive(Debug)]
struct Args {
    command: String,
    dir: PathBuf,
    config: Option<PathBuf>,
    chain_id: String,
    moniker: String,
    join: Option<PathBuf>,
}

fn dispatch() -> Result<(), String> {
    let args = parse(std::env::args().skip(1).collect())?;
    match args.command.as_str() {
        "init" => init::init(
            &args.dir,
            &args.chain_id,
            &args.moniker,
            args.join.as_deref(),
        )
        .map_err(|e| e.to_string()),
        "start" => start(&args),
        "show" => show(&args),
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn parse(argv: Vec<String>) -> Result<Args, String> {
    let mut args = Args {
        command: String::new(),
        dir: init::default_dir(),
        config: None,
        chain_id: "afrolink-devnet".to_owned(),
        moniker: "afrolink-node".to_owned(),
        join: None,
    };
    let mut rest = argv.into_iter();
    let Some(command) = rest.next() else {
        return Err(format!("no command given\n\n{USAGE}"));
    };
    if command == "-h" || command == "--help" {
        return Err(USAGE.to_owned());
    }
    args.command = command;

    while let Some(flag) = rest.next() {
        // Every flag takes a value, so the shape is uniform and a missing value
        // is caught here rather than becoming the next flag's value.
        let mut value = || rest.next().ok_or_else(|| format!("`{flag}` needs a value"));
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value()?),
            "--config" => args.config = Some(PathBuf::from(value()?)),
            "--chain-id" => args.chain_id = value()?,
            "--moniker" => args.moniker = value()?,
            "--join" => args.join = Some(PathBuf::from(value()?)),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => {
                // Refused rather than ignored. A node started with a misspelled
                // `--dir` writes a whole new chain into a whole new directory and
                // reports nothing wrong.
                return Err(format!("unknown option `{other}`\n\n{USAGE}"));
            }
        }
    }
    Ok(args)
}

fn load_config(args: &Args) -> Result<Config, String> {
    let path = args
        .config
        .clone()
        .unwrap_or_else(|| args.dir.join("config"));
    if !path.exists() {
        return Err(format!(
            "no config at {}: run `afrolinkd init --dir {}` first",
            path.display(),
            args.dir.display()
        ));
    }
    let mut config = Config::load(&path).map_err(|e| e.to_string())?;
    // The directory the operator named on the command line wins over the one
    // written in the file, so moving a data directory does not require editing
    // the file inside it.
    if args.dir != init::default_dir() {
        config.data_dir = args.dir.clone();
    }
    Ok(config)
}

fn start(args: &Args) -> Result<(), String> {
    let config = load_config(args)?;
    let stop = Arc::new(AtomicBool::new(false));

    // The workspace forbids `unsafe`, and installing a signal handler needs it —
    // so this is one of the few places a dependency earns its place. A daemon
    // that can only be stopped with SIGKILL leaves its peers holding half-open
    // connections and its operator unable to tell a clean stop from a crash.
    let flag = Arc::clone(&stop);
    if ctrlc::set_handler(move || {
        if flag.swap(true, Ordering::SeqCst) {
            // Asked twice. The operator wants out now, and refusing them is how a
            // daemon earns a habit of `kill -9`.
            std::process::exit(130);
        }
        log("received interrupt; finishing the current step");
    })
    .is_err()
    {
        log("warning: could not install a signal handler; stop this node with SIGKILL");
    }

    run::start(&config, &stop).map_err(|e| e.to_string())
}

fn show(args: &Args) -> Result<(), String> {
    let config = load_config(args)?;
    let node_key = identity::load(&config.node_key_path()).map_err(|e| e.to_string())?;
    let consensus_key = identity::load(&config.consensus_key_path()).map_err(|e| e.to_string())?;
    let genesis =
        std::fs::read(config.genesis_path()).map_err(|e| format!("cannot read genesis: {e}"))?;
    let document = afrolink_primitives::codec::decode_exact::<afrolink_executor::Genesis>(&genesis)
        .map_err(|_| "the genesis file is not a genesis document".to_owned())?;

    log(&format!("moniker    {}", config.moniker));
    log(&format!("chain      {}", document.chain_id));
    log(&format!(
        "genesis    {}",
        afrolink_crypto::hash::hash(afrolink_crypto::hash::Domain::GenesisId, &genesis).to_hex()
    ));
    log(&format!(
        "node id    {}",
        hex::encode(node_key.public_key().to_bytes())
    ));
    log(&format!(
        "validator  {}",
        afrolink_crypto::Address::from_public_key(&consensus_key.public_key())
    ));
    log(&format!("p2p        {}", config.p2p_listen));
    log(&format!(
        "rpc        {}",
        config
            .rpc_listen
            .map_or_else(|| "off".to_owned(), |a| a.to_string())
    ));
    Ok(())
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

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_misspelled_option_is_refused_rather_than_ignored() {
        // A node started with `--dirr` writes a whole new chain into a whole new
        // directory and reports nothing wrong.
        let error = parse(argv(&["start", "--dirr", "/tmp/x"])).unwrap_err();
        assert!(error.contains("unknown option"), "{error}");
    }

    #[test]
    fn an_option_without_a_value_does_not_swallow_the_next_one() {
        let error = parse(argv(&["start", "--dir"])).unwrap_err();
        assert!(error.contains("needs a value"), "{error}");
    }

    #[test]
    fn no_command_is_an_error_with_the_usage_attached() {
        let error = parse(Vec::new()).unwrap_err();
        assert!(error.contains("USAGE"), "{error}");
    }

    #[test]
    fn the_command_and_its_options_are_read_in_full() {
        let args = parse(argv(&[
            "init",
            "--dir",
            "/tmp/node",
            "--chain-id",
            "afrolink-1",
            "--moniker",
            "nairobi",
        ]))
        .unwrap();
        assert_eq!(args.command, "init");
        assert_eq!(args.dir, PathBuf::from("/tmp/node"));
        assert_eq!(args.chain_id, "afrolink-1");
        assert_eq!(args.moniker, "nairobi");
        assert!(args.join.is_none());
    }
}
