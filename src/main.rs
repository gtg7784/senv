use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,senv=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    senv::cli::run()
}
