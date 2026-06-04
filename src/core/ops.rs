use std::path::Path;

use anyhow::Result;

use crate::tui::App;

pub fn init() -> Result<()> {
    anyhow::bail!("`senv init` is not implemented yet")
}

pub fn import(_path: &Path) -> Result<()> {
    anyhow::bail!("`senv import` is not implemented yet")
}

pub fn set(_kv: &str, _personal: bool) -> Result<()> {
    anyhow::bail!("`senv set` is not implemented yet")
}

pub fn list() -> Result<()> {
    anyhow::bail!("`senv list` is not implemented yet")
}

pub fn diff() -> Result<()> {
    anyhow::bail!("`senv diff` is not implemented yet")
}

pub fn confirm_delete(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn toggle_scoped(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn reload_from_disk(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn commit_edit(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn commit_new_secret(_app: &mut App) -> Result<()> {
    Ok(())
}
