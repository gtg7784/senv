use std::process::Command;

use anyhow::{Context, Result};

pub fn run(argv: Vec<String>) -> Result<()> {
    if argv.is_empty() {
        anyhow::bail!("no command provided after `--`");
    }
    let pairs = crate::core::ops::collect_env_pairs()?;

    let program = &argv[0];
    let mut cmd = Command::new(program);
    cmd.args(&argv[1..]);
    for (key, value) in pairs {
        cmd.env(key, value);
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to execute: {}", program))?;

    std::process::exit(status.code().unwrap_or(1));
}
