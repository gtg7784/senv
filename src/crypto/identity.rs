use std::sync::OnceLock;

use age::secrecy::ExposeSecret;
use age::x25519;
use anyhow::{anyhow, Context, Result};

use crate::tui::{App, UnlockState};

pub const KEYRING_SERVICE: &str = "senv";
pub const DEFAULT_ACCOUNT: &str = "default-identity";

static STORE_INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn ensure_default_store() -> Result<()> {
    let r = STORE_INIT.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            let store = apple_native_keyring_store::keychain::Store::new()
                .map_err(|e| format!("init macOS keychain: {e}"))?;
            keyring_core::set_default_store(store);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            let store = linux_keyutils_keyring_store::Store::new()
                .map_err(|e| format!("init linux keyutils: {e}"))?;
            keyring_core::set_default_store(store);
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            let store = windows_native_keyring_store::Store::new()
                .map_err(|e| format!("init windows credential store: {e}"))?;
            keyring_core::set_default_store(store);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err::<(), String>("no OS keychain backend on this platform".to_string())
        }
    });
    r.clone().map_err(|e| anyhow!(e))
}

fn entry(account: &str) -> Result<keyring_core::Entry> {
    ensure_default_store()?;
    keyring_core::Entry::new(KEYRING_SERVICE, account)
        .context("create keyring entry")
}

pub fn exists(account: &str) -> bool {
    if ensure_default_store().is_err() {
        return false;
    }
    let Ok(e) = keyring_core::Entry::new(KEYRING_SERVICE, account) else {
        return false;
    };
    e.get_password().is_ok()
}

pub fn generate_and_store(account: &str) -> Result<x25519::Recipient> {
    let identity = x25519::Identity::generate();
    let secret = identity.to_string();
    let secret_str: &str = secret.expose_secret();

    entry(account)?
        .set_password(secret_str)
        .context("keyring set_password")?;

    Ok(identity.to_public())
}

pub fn load(account: &str) -> Result<x25519::Identity> {
    let secret_str = entry(account)?
        .get_password()
        .context("keyring get_password")?;
    secret_str
        .parse::<x25519::Identity>()
        .map_err(|e| anyhow!("parse age identity: {e}"))
}

pub fn delete(account: &str) -> Result<()> {
    let e = entry(account)?;
    match e.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(err) => Err(anyhow!("keyring delete: {err}")),
    }
}

pub fn lock(app: &mut App) -> Result<()> {
    app.unlock = UnlockState::Locked;
    Ok(())
}

pub fn unlock(app: &mut App) -> Result<()> {
    let _identity = load(DEFAULT_ACCOUNT)
        .context("no identity in keyring (run `senv init` first)")?;
    app.unlock = UnlockState::Unlocked;
    Ok(())
}
