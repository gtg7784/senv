use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub mod vault_file;

pub const VAULT_VERSION: &str = "1.0";
pub const VAULT_FILENAME: &str = ".env.age";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Vault {
    pub version: String,
    pub created: String,
    pub recipients: Vec<String>,
    pub secrets: BTreeMap<String, EncryptedEntry>,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub schema: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptedEntry {
    #[serde(default)]
    pub shared: String,
    #[serde(default)]
    pub scoped: BTreeMap<String, String>,
}

impl Vault {
    pub fn new(recipient_pubkey: String) -> Self {
        Self {
            version: VAULT_VERSION.to_string(),
            created: now_unix_seconds(),
            recipients: vec![recipient_pubkey],
            secrets: BTreeMap::new(),
            mac: String::new(),
            schema: BTreeMap::new(),
        }
    }
}

fn now_unix_seconds() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_new_initializes_correctly() {
        let v = Vault::new("age1xyz".to_string());
        assert_eq!(v.version, VAULT_VERSION);
        assert_eq!(v.recipients, vec!["age1xyz".to_string()]);
        assert!(v.secrets.is_empty());
        assert!(v.schema.is_empty());
        assert!(v.mac.is_empty());
    }

    #[test]
    fn vault_serde_full_roundtrip() {
        let mut vault = Vault::new("age1abc".to_string());
        vault.secrets.insert(
            "FOO".into(),
            EncryptedEntry {
                shared: "ct".into(),
                scoped: Default::default(),
            },
        );
        vault.schema.insert("FOO".into(), "the foo key".into());
        vault.mac = "blake3-v1:deadbeef".into();

        let json = serde_json::to_string(&vault).unwrap();
        let loaded: Vault = serde_json::from_str(&json).unwrap();

        assert_eq!(vault.version, loaded.version);
        assert_eq!(vault.recipients, loaded.recipients);
        assert_eq!(vault.secrets["FOO"].shared, loaded.secrets["FOO"].shared);
        assert_eq!(vault.schema, loaded.schema);
        assert_eq!(vault.mac, loaded.mac);
    }

    #[test]
    fn vault_serde_backward_compat_no_schema() {
        let json =
            r#"{"version":"1.0","created":"0","recipients":["age1abc"],"secrets":{},"mac":""}"#;
        let vault: Vault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.recipients, vec!["age1abc".to_string()]);
        assert!(vault.schema.is_empty());
        assert!(vault.secrets.is_empty());
    }

    #[test]
    fn encrypted_entry_serde_optional_scoped() {
        let json = r#"{"shared":"ct"}"#;
        let entry: EncryptedEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.shared, "ct");
        assert!(entry.scoped.is_empty());
    }
}
