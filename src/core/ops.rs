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
    let count = import_silent(path)?;
    println!(
        "✓ Encrypted {} entries from {} into {}",
        count,
        path.display(),
        VAULT_FILENAME
    );
    Ok(())
}

pub fn import_silent(path: &Path) -> Result<usize> {
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
    Ok(count)
}

pub fn build_import_preview(path: &Path) -> Result<crate::tui::ImportPreview> {
    let rows = import_env_file(path)?;
    let entries: Vec<(String, usize)> = rows
        .iter()
        .map(|r| {
            let len = r
                .shared
                .as_ref()
                .map(|s| {
                    let exposed: &str = s.expose_secret();
                    exposed.len()
                })
                .unwrap_or(0);
            (r.key.clone(), len)
        })
        .collect();
    Ok(crate::tui::ImportPreview {
        source: path.to_path_buf(),
        entries,
    })
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

pub fn compute_diff(app: &mut App) -> Vec<crate::tui::DiffEntry> {
    use crate::tui::{DiffEntry, DiffKind};

    let example_path = Path::new(".env.example");
    if !example_path.exists() {
        push_activity(app, "no .env.example in cwd".to_string());
        return Vec::new();
    }
    let Ok(content) = fs::read_to_string(example_path) else {
        push_activity(app, "cannot read .env.example".to_string());
        return Vec::new();
    };
    let example_keys: HashSet<String> = dotenvy::from_read_iter(content.as_bytes())
        .filter_map(|r| r.ok().map(|(k, _)| k))
        .collect();
    let current_keys: HashSet<String> = app.rows.iter().map(|r| r.key.clone()).collect();

    let mut all: Vec<String> = example_keys.union(&current_keys).cloned().collect();
    all.sort();

    all.into_iter()
        .map(|key| {
            let kind = match (
                example_keys.contains(&key),
                current_keys.contains(&key),
            ) {
                (true, false) => DiffKind::Missing,
                (false, true) => DiffKind::Extra,
                _ => DiffKind::Match,
            };
            DiffEntry { key, kind }
        })
        .collect()
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

pub fn commit_edit(app: &mut App) -> Result<()> {
    let key_name = app
        .edit_key_name
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no key being edited"))?;
    let new_value = app.edit_buffer.lines().join("\n");

    let mut found = false;
    for row in app.rows.iter_mut() {
        if row.key == key_name {
            row.shared = Some(SecretString::from(new_value.clone()));
            row.missing_in_example = false;
            found = true;
            break;
        }
    }
    if !found {
        anyhow::bail!("key '{}' no longer in rows", key_name);
    }

    save_app_rows_to_vault(app)?;
    push_activity(app, format!("set {}", key_name));
    Ok(())
}

pub fn commit_new_secret(app: &mut App) -> Result<()> {
    let raw = app.edit_buffer.lines().join("\n");
    let trimmed = raw.trim();
    let (key, value) = trimmed
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE"))?;
    let key = key.trim().to_string();
    let value = value.trim().to_string();

    if key.is_empty() {
        anyhow::bail!("empty key");
    }
    if app.rows.iter().any(|r| r.key == key && r.shared.is_some()) {
        anyhow::bail!("key '{}' already exists; use edit instead", key);
    }

    if let Some(row) = app.rows.iter_mut().find(|r| r.key == key) {
        row.shared = Some(SecretString::from(value.clone()));
        row.missing_in_example = false;
    } else {
        app.rows.push(SecretRow {
            key: key.clone(),
            shared: Some(SecretString::from(value.clone())),
            scoped: None,
            missing_in_example: false,
        });
        app.rows.sort_by(|a, b| a.key.cmp(&b.key));
    }

    save_app_rows_to_vault(app)?;
    push_activity(app, format!("add {}", key));
    Ok(())
}

fn save_app_rows_to_vault(app: &App) -> Result<()> {
    let vault_path = Path::new(VAULT_FILENAME);

    let account = identity::DEFAULT_ACCOUNT;
    if !identity::exists(account) {
        anyhow::bail!("no identity in keyring; run `senv init` first");
    }
    let id = identity::load(account)?;
    let recipient = id.to_public();

    let mut vault = if vault_path.exists() {
        vault_file::read(vault_path)?
    } else {
        Vault::new(recipient.to_string())
    };

    let mut new_secrets = std::collections::BTreeMap::new();
    for row in &app.rows {
        if let Some(secret) = &row.shared {
            let exposed: &str = secret.expose_secret();
            let ciphertext = vault_file::encrypt_value(exposed, &recipient)?;
            let scoped = vault
                .secrets
                .get(&row.key)
                .map(|e| e.scoped.clone())
                .unwrap_or_default();
            new_secrets.insert(
                row.key.clone(),
                EncryptedEntry {
                    shared: ciphertext,
                    scoped,
                },
            );
        }
    }
    vault.secrets = new_secrets;
    vault.schema = app
        .schema
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    vault.mac = vault_file::compute_mac(&vault);
    vault_file::write(vault_path, &vault)?;

    Ok(())
}

pub fn commit_schema_edit(app: &mut App) -> Result<()> {
    let key_name = app
        .edit_key_name
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no key being edited"))?;
    let new_desc = app.edit_buffer.lines().join("\n").trim().to_string();

    if new_desc.is_empty() {
        app.schema.remove(&key_name);
    } else {
        app.schema.insert(key_name.clone(), new_desc);
    }

    save_app_rows_to_vault(app)?;
    push_activity(app, format!("schema {}", key_name));
    Ok(())
}

fn push_activity(app: &mut App, msg: String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    app.activity.push(crate::tui::ActivityLine {
        time: format!("{:02}:{:02}", h, m),
        message: msg,
    });
    if app.activity.len() > 100 {
        app.activity.remove(0);
    }
}

pub fn collect_env_pairs() -> Result<Vec<(String, String)>> {
    let vault_path = Path::new(VAULT_FILENAME);

    if vault_path.exists() {
        let account = identity::DEFAULT_ACCOUNT;
        if !identity::exists(account) {
            anyhow::bail!("vault exists but no identity in keyring; run `senv init`");
        }
        let id = identity::load(account)?;
        let vault = vault_file::read(vault_path)?;
        if !vault_file::verify_mac(&vault) {
            anyhow::bail!("vault integrity check failed (BLAKE3 MAC mismatch)");
        }
        let mut pairs = Vec::with_capacity(vault.secrets.len());
        for (key, entry) in &vault.secrets {
            if entry.shared.is_empty() {
                continue;
            }
            let pt = vault_file::decrypt_value(&entry.shared, &id)
                .with_context(|| format!("decrypt {}", key))?;
            pairs.push((key.clone(), pt));
        }
        Ok(pairs)
    } else if Path::new(".env").exists() {
        let rows = import_env_file(Path::new(".env"))?;
        let mut pairs = Vec::with_capacity(rows.len());
        for row in rows {
            if let Some(secret) = row.shared {
                let v: &str = secret.expose_secret();
                pairs.push((row.key, v.to_string()));
            }
        }
        Ok(pairs)
    } else {
        anyhow::bail!("no .env.age or .env found in cwd")
    }
}
