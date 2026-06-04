use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::identity;
use crate::storage::{vault_file, EncryptedEntry, Vault, VAULT_FILENAME};
use crate::tui::{App, SecretRow};

pub fn init() -> Result<()> {
    let vault_path = Path::new(VAULT_FILENAME);
    if vault_path.exists() {
        anyhow::bail!(
            "{} already exists; refusing to overwrite",
            vault_path.display()
        );
    }

    let account = identity::DEFAULT_ACCOUNT;
    let recipient = if identity::exists(account) {
        identity::load(account)?.to_public()
    } else {
        identity::generate_and_store(account)
            .context("generate and store age identity")?
    };

    let mut vault = Vault::new(recipient.to_string());
    vault.mac = vault_file::compute_mac(&vault);
    vault_file::write(vault_path, &vault)?;

    println!("✓ Initialized {}", vault_path.display());
    println!("  recipient: {}", recipient);
    println!("  identity stored in OS keyring");
    println!(
        "    service: {}  account: {}",
        identity::KEYRING_SERVICE,
        account
    );
    Ok(())
}

pub fn import(path: &Path) -> Result<()> {
    let rows = import_env_file(path)?;

    let account = identity::DEFAULT_ACCOUNT;
    if !identity::exists(account) {
        anyhow::bail!("no identity found in keyring; run `senv init` first");
    }
    let id = identity::load(account)?;
    let recipient = id.to_public();

    let vault_path = Path::new(VAULT_FILENAME);
    let mut vault = if vault_path.exists() {
        vault_file::read(vault_path)?
    } else {
        Vault::new(recipient.to_string())
    };

    let mut count = 0_usize;
    for row in &rows {
        if let Some(secret) = &row.shared {
            let exposed: &str = secret.expose_secret();
            let ciphertext = vault_file::encrypt_value(exposed, &recipient)?;
            vault.secrets.insert(
                row.key.clone(),
                EncryptedEntry {
                    shared: ciphertext,
                    scoped: Default::default(),
                },
            );
            count += 1;
        }
    }

    vault.mac = vault_file::compute_mac(&vault);
    vault_file::write(vault_path, &vault)?;

    println!(
        "✓ Encrypted {} entries from {} into {}",
        count,
        path.display(),
        vault_path.display()
    );
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
