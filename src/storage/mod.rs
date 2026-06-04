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
        }
    }
}

fn now_unix_seconds() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}
