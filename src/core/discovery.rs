use std::path::Path;
use std::process::Command;

use anyhow::Result;

use crate::tui::App;

pub fn populate(app: &mut App) -> Result<()> {
    if let Some(name) = current_project_name() {
        app.project_name = name;
    }
    app.git_remote = git_remote_url();

    let vault_path = Path::new(crate::storage::VAULT_FILENAME);
    let identity_account = crate::crypto::identity::DEFAULT_ACCOUNT;
    if vault_path.exists()
        && crate::crypto::identity::exists(identity_account)
        && crate::crypto::identity::unlock(app).is_ok()
    {
        return Ok(());
    }

    if let Ok(rows) = crate::core::ops::import_env_file(Path::new(".env")) {
        app.rows = rows;
        crate::core::ops::mark_missing_against_example(&mut app.rows, Path::new(".env.example"));
    }

    Ok(())
}

fn current_project_name() -> Option<String> {
    std::env::current_dir()
        .ok()?
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

fn git_remote_url() -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if url.is_empty() { None } else { Some(url) }
}
