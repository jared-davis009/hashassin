#![deny(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::crack::CrackOpts;
use commands::gen_hashes::HashesOpts;
use commands::gen_passwords::PasswordsOpts;
use commands::rainbow_table::RainbowOpts;
use commands::server::ServerOpts;
use dotenvy::dotenv;

mod commands;

#[derive(Parser, Debug)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

/// Determine what to do
#[derive(Subcommand, Debug)]
enum Command {
    /// Generate passwords
    GenPasswords(PasswordsOpts),

    /// Generate hashes
    GenHashes(HashesOpts),

    /// Create rainbow table
    GenRainbowTable(RainbowOpts),
    Crack(CrackOpts),
    Server(ServerOpts),
}
#[tokio::main]
async fn main() -> Result<()> {
    // Read environment variables
    dotenv().ok();

    // Initialize logger
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    match opts.command {
        Command::GenPasswords(opts) => commands::gen_passwords::do_passwords(opts)?,
        Command::GenHashes(opts) => commands::gen_hashes::gen_hashes(opts)?,
        Command::GenRainbowTable(opts) => commands::rainbow_table::do_rainbow(opts)?,
        Command::Crack(opts) => commands::crack::do_cracks(opts)?,
        Command::Server(opts) => commands::server::server(opts).await?,
    }

    Ok(())
}
