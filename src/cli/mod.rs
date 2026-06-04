use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "senv",
    version,
    about = "Encrypted .env replacement with first-class TUI",
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(last = true)]
    exec: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Tui,
    Init,
    Import {
        path: PathBuf,
    },
    Set {
        kv: String,
        #[arg(long)]
        personal: bool,
    },
    List,
    Export,
    Diff,
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();

    let result = match (cli.command, cli.exec.is_empty()) {
        (Some(Command::Tui), _) | (None, true) => crate::tui::run(),
        (None, false) => crate::inject::exec::run(cli.exec),
        (Some(Command::Init), _) => crate::core::ops::init(),
        (Some(Command::Import { path }), _) => crate::core::ops::import(&path),
        (Some(Command::Set { kv, personal }), _) => crate::core::ops::set(&kv, personal),
        (Some(Command::List), _) => crate::core::ops::list(),
        (Some(Command::Export), _) => crate::inject::export::run(),
        (Some(Command::Diff), _) => crate::core::ops::diff(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
