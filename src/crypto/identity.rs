use anyhow::Result;

use crate::tui::App;

pub fn lock(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn unlock(_app: &mut App) -> Result<()> {
    Ok(())
}
