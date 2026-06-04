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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::EncryptedEntry;
    use age::x25519;
    use tempfile::tempdir;

    fn make_entry(shared: &str) -> EncryptedEntry {
        EncryptedEntry {
            shared: shared.to_string(),
            scoped: Default::default(),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip_single() {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        let ciphertext = encrypt_value("hello world", &[recipient]).unwrap();
        let decrypted = decrypt_value(&ciphertext, &identity).unwrap();
        assert_eq!("hello world", decrypted);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_multi_recipient() {
        let id_a = x25519::Identity::generate();
        let id_b = x25519::Identity::generate();
        let recipients = vec![id_a.to_public(), id_b.to_public()];
        let ciphertext = encrypt_value("shared", &recipients).unwrap();

        assert_eq!("shared", decrypt_value(&ciphertext, &id_a).unwrap());
        assert_eq!("shared", decrypt_value(&ciphertext, &id_b).unwrap());
    }

    #[test]
    fn encrypt_with_empty_recipients_fails() {
        assert!(encrypt_value("foo", &[]).is_err());
    }

    #[test]
    fn decrypt_with_wrong_identity_fails() {
        let id_a = x25519::Identity::generate();
        let id_b = x25519::Identity::generate();
        let ciphertext = encrypt_value("hi", &[id_a.to_public()]).unwrap();
        assert!(decrypt_value(&ciphertext, &id_b).is_err());
    }

    #[test]
    fn compute_mac_is_deterministic() {
        let mut vault = Vault::new("age1abc".to_string());
        vault.secrets.insert("KEY1".into(), make_entry("ct"));
        let mac1 = compute_mac(&vault);
        let mac2 = compute_mac(&vault);
        assert_eq!(mac1, mac2);
        assert!(mac1.starts_with("blake3-v1:"));
    }

    #[test]
    fn compute_mac_changes_when_secrets_change() {
        let mut vault = Vault::new("age1abc".to_string());
        let empty_mac = compute_mac(&vault);
        vault.secrets.insert("KEY1".into(), make_entry("ct"));
        assert_ne!(empty_mac, compute_mac(&vault));
    }

    #[test]
    fn compute_mac_changes_when_recipients_change() {
        let mut vault = Vault::new("age1abc".to_string());
        let one_mac = compute_mac(&vault);
        vault.recipients.push("age1xyz".to_string());
        assert_ne!(one_mac, compute_mac(&vault));
    }

    #[test]
    fn verify_mac_accepts_matching_mac() {
        let mut vault = Vault::new("age1abc".to_string());
        vault.secrets.insert("KEY1".into(), make_entry("ct"));
        vault.mac = compute_mac(&vault);
        assert!(verify_mac(&vault));
    }

    #[test]
    fn verify_mac_rejects_tampered_secrets() {
        let mut vault = Vault::new("age1abc".to_string());
        vault.secrets.insert("KEY1".into(), make_entry("ct"));
        vault.mac = compute_mac(&vault);
        vault
            .secrets
            .insert("KEY1".into(), make_entry("tampered"));
        assert!(!verify_mac(&vault));
    }

    #[test]
    fn verify_mac_empty_passes_for_empty_secrets() {
        let vault = Vault::new("age1abc".to_string());
        assert!(verify_mac(&vault));
    }

    #[test]
    fn read_write_roundtrip_with_decryption() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.age");

        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        let mut vault = Vault::new(recipient.to_string());
        let ciphertext = encrypt_value("secret_value", &[recipient]).unwrap();
        vault.secrets.insert("KEY".into(), make_entry(&ciphertext));
        vault.mac = compute_mac(&vault);

        write(&path, &vault).unwrap();
        let loaded = read(&path).unwrap();

        assert_eq!(vault.version, loaded.version);
        assert_eq!(vault.recipients, loaded.recipients);
        assert_eq!(vault.mac, loaded.mac);
        let pt = decrypt_value(&loaded.secrets["KEY"].shared, &identity).unwrap();
        assert_eq!("secret_value", pt);
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_symlink() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.age");
        let link = dir.path().join("link.age");

        let vault = Vault::new("age1abc".to_string());
        write(&real, &vault).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = read(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_symlink() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.age");
        let link = dir.path().join("link.age");

        let vault = Vault::new("age1abc".to_string());
        write(&real, &vault).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(write(&link, &vault).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn written_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("perm.age");
        let vault = Vault::new("age1abc".to_string());
        write(&path, &vault).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
