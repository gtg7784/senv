use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::tui::{App, SecretRow};

pub fn init() -> Result<()> {
    anyhow::bail!("`senv init` is not implemented yet")
}

pub fn import(path: &Path) -> Result<()> {
    let rows = import_env_file(path)?;
    println!("Imported {} entries from {}", rows.len(), path.display());
    for row in &rows {
        let bytes = match &row.shared {
            Some(secret) => {
                let exposed: &str = secret.expose_secret();
                exposed.len()
            }
            None => 0,
        };
        println!("  {}  ({} bytes)", row.key, bytes);
    }
    Ok(())
}

pub fn import_env_file(path: &Path) -> Result<Vec<SecretRow>> {
    if !path.exists() {
        anyhow::bail!("file not found: {}", path.display());
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    let mut rows = Vec::new();
    for item in dotenvy::from_read_iter(content.as_bytes()) {
        let (key, value) =
            item.with_context(|| format!("failed to parse {}", path.display()))?;
        rows.push(SecretRow {
            key,
            shared: Some(SecretString::from(value)),
            scoped: None,
            missing_in_example: false,
        });
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(rows)
}

pub fn mark_missing_against_example(rows: &mut Vec<SecretRow>, example_path: &Path) {
    if !example_path.exists() {
        return;
    }
    let Ok(content) = fs::read_to_string(example_path) else {
        return;
    };
    let example_keys: HashSet<String> = dotenvy::from_read_iter(content.as_bytes())
        .filter_map(|r| r.ok().map(|(k, _)| k))
        .collect();
    let current_keys: HashSet<String> = rows.iter().map(|r| r.key.clone()).collect();

    for key in example_keys.difference(&current_keys) {
        rows.push(SecretRow {
            key: key.clone(),
            shared: None,
            scoped: None,
            missing_in_example: true,
        });
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
}

pub fn set(_kv: &str, _personal: bool) -> Result<()> {
    anyhow::bail!("`senv set` is not implemented yet")
}

pub fn list() -> Result<()> {
    let rows = import_env_file(Path::new(".env"))?;
    if rows.is_empty() {
        println!("(no entries)");
        return Ok(());
    }
    for row in &rows {
        if let Some(secret) = &row.shared {
            let exposed: &str = secret.expose_secret();
            println!("🔒 {}  ({} bytes)", row.key, exposed.len());
        }
    }
    Ok(())
}

pub fn diff() -> Result<()> {
    let env_path = Path::new(".env");
    let example_path = Path::new(".env.example");

    if !example_path.exists() {
        anyhow::bail!(".env.example not found");
    }

    let env_keys: HashSet<String> = if env_path.exists() {
        import_env_file(env_path)?
            .into_iter()
            .map(|r| r.key)
            .collect()
    } else {
        HashSet::new()
    };

    let example_content = fs::read_to_string(example_path)?;
    let example_keys: HashSet<String> = dotenvy::from_read_iter(example_content.as_bytes())
        .filter_map(|r| r.ok().map(|(k, _)| k))
        .collect();

    let mut missing: Vec<&String> = example_keys.difference(&env_keys).collect();
    let mut extra: Vec<&String> = env_keys.difference(&example_keys).collect();
    missing.sort();
    extra.sort();

    if missing.is_empty() && extra.is_empty() {
        println!("✓ .env matches .env.example");
        return Ok(());
    }
    for key in &missing {
        println!("⚠ missing in .env: {}", key);
    }
    for key in &extra {
        println!("+ extra in .env:   {}", key);
    }
    Ok(())
}

pub fn confirm_delete(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn toggle_scoped(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn reload_from_disk(app: &mut App) -> Result<()> {
    crate::core::discovery::populate(app)
}

pub fn commit_edit(_app: &mut App) -> Result<()> {
    Ok(())
}

pub fn commit_new_secret(_app: &mut App) -> Result<()> {
    Ok(())
}
