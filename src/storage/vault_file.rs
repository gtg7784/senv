use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use age::x25519;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use tempfile::NamedTempFile;

use crate::storage::Vault;

pub fn read(path: &Path) -> Result<Vault> {
    if path.is_symlink() {
        anyhow::bail!(
            "vault path is a symlink, refusing to follow: {}",
            path.display()
        );
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let vault: Vault = serde_json::from_str(&content)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(vault)
}

pub fn write(path: &Path, vault: &Vault) -> Result<()> {
    if path.is_symlink() {
        anyhow::bail!(
            "vault path is a symlink, refusing to follow: {}",
            path.display()
        );
    }
    let json = serde_json::to_string_pretty(vault).context("serialize vault")?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).ok();
    let mut tmp = NamedTempFile::new_in(dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    tmp.write_all(json.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| anyhow!("persist temp file: {e}"))?;

    #[cfg(unix)]
    {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

pub fn encrypt_value(plaintext: &str, recipients: &[x25519::Recipient]) -> Result<String> {
    if recipients.is_empty() {
        anyhow::bail!("at least one recipient required");
    }
    let refs: Vec<&dyn age::Recipient> =
        recipients.iter().map(|r| r as &dyn age::Recipient).collect();
    let encryptor = age::Encryptor::with_recipients(refs.into_iter())
        .map_err(|e| anyhow!("age encryptor: {e}"))?;
    let mut ciphertext = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|e| anyhow!("wrap_output: {e}"))?;
        writer.write_all(plaintext.as_bytes())?;
        writer.finish().map_err(|e| anyhow!("finish: {e}"))?;
    }
    Ok(BASE64.encode(&ciphertext))
}

pub fn decrypt_value(b64: &str, identity: &x25519::Identity) -> Result<String> {
    let ciphertext = BASE64
        .decode(b64)
        .map_err(|e| anyhow!("base64 decode: {e}"))?;
    let decryptor = age::Decryptor::new(&ciphertext[..])
        .map_err(|e| anyhow!("age decryptor: {e}"))?;
    let identities: Vec<&dyn age::Identity> = vec![identity];
    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .map_err(|e| anyhow!("decrypt: {e}"))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    String::from_utf8(plaintext).map_err(|e| anyhow!("utf8: {e}"))
}

pub fn compute_mac(vault: &Vault) -> String {
    let mut data = Vec::new();
    for (k, entry) in &vault.secrets {
        data.extend_from_slice(k.as_bytes());
        data.push(0);
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0);
    }
    for r in &vault.recipients {
        data.extend_from_slice(r.as_bytes());
        data.push(0);
    }
    let hash = blake3::hash(&data);
    format!("blake3-v1:{}", hash.to_hex())
}

pub fn verify_mac(vault: &Vault) -> bool {
    if vault.mac.is_empty() {
        return vault.secrets.is_empty();
    }
    let expected = compute_mac(vault);
    constant_time_eq::constant_time_eq(vault.mac.as_bytes(), expected.as_bytes())
}
