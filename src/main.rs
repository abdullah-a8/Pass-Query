use clap::Parser;

mod models;
mod pass_cli;
mod search;
mod selection;

/// Fast Proton Pass password search
#[derive(Parser)]
#[command(name = "pp")]
#[command(about = "Search Proton Pass and print password to stdout")]
#[command(version)]
struct Cli {
    /// Search query (item name)
    query: String,
}

fn main() {
    let _cli = Cli::parse();
    println!("Hello, world!");
}
