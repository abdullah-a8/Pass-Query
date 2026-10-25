//! pq-sync's three secrets: the Proton personal access token, the
//! 1Password service account token, and the key of the state file's field
//! hashes. On macOS they live in the login Keychain, readable without a
//! prompt only by the pq-sync binary that stored them (after an upgrade,
//! macOS asks once). Elsewhere, or with `PQ_SYNC_SECRETS_FROM_ENV=1`, they
//! come from the environment (`PQ_SYNC_PROTON_TOKEN`, `PQ_SYNC_OP_TOKEN`,
//! `PQ_SYNC_STATE_KEY` as hex), for a service manager that injects them.

use anyhow::{Context, Result, bail};

use super::secret::SecretString;

/// The Keychain service all three are stored under.
pub const SERVICE: &str = "pq-sync";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secret {
    ProtonToken,
    OpToken,
    StateKey,
}

impl Secret {
    fn account(self) -> &'static str {
        match self {
            Secret::ProtonToken => "proton-personal-access-token",
            Secret::OpToken => "1password-service-account-token",
            Secret::StateKey => "state-key",
        }
    }

    fn env_var(self) -> &'static str {
        match self {
            Secret::ProtonToken => "PQ_SYNC_PROTON_TOKEN",
            Secret::OpToken => "PQ_SYNC_OP_TOKEN",
            Secret::StateKey => "PQ_SYNC_STATE_KEY",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Secret::ProtonToken => "Proton Pass personal access token",
            Secret::OpToken => "1Password service account token",
            Secret::StateKey => "state key",
        }
    }
}

fn from_env() -> bool {
    !cfg!(target_os = "macos")
        || std::env::var_os("PQ_SYNC_SECRETS_FROM_ENV").is_some_and(|v| v == "1")
}

/// The stored secret, or `None` when there is none.
pub fn get(secret: Secret) -> Result<Option<SecretString>> {
    if from_env() {
        return Ok(std::env::var(secret.env_var())
            .ok()
            .filter(|value| !value.is_empty())
            .map(SecretString::new));
    }
    keychain::get(secret.account())
}

pub fn set(secret: Secret, value: &SecretString) -> Result<()> {
    if from_env() {
        bail!(
            "secrets come from the environment here: set {} instead",
            secret.env_var()
        );
    }
    keychain::set(secret.account(), value)
}

/// The state key as bytes, made and stored on first use.
pub fn state_key() -> Result<Vec<u8>> {
    if let Some(hex) = get(Secret::StateKey)? {
        return unhex(hex.expose()).context("the stored state key is not hex");
    }
    if from_env() {
        bail!("{} is not set", Secret::StateKey.env_var());
    }
    let key = random_key()?;
    set(Secret::StateKey, &SecretString::new(hex(&key)))?;
    Ok(key)
}

fn random_key() -> Result<Vec<u8>> {
    use std::io::Read;
    let mut key = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut key))
        .context("read /dev/urandom")?;
    Ok(key)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if text.len() < 32 || !text.len().is_multiple_of(2) {
        bail!("bad length");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("not hex"))
        .collect()
}

#[cfg(target_os = "macos")]
mod keychain {
    use anyhow::{Context, Result};
    use security_framework::passwords::{get_generic_password, set_generic_password};

    use super::{SERVICE, SecretString};

    /// errSecItemNotFound.
    const NOT_FOUND: i32 = -25300;

    pub fn get(account: &str) -> Result<Option<SecretString>> {
        match get_generic_password(SERVICE, account) {
            Ok(bytes) => {
                let value = String::from_utf8(bytes)
                    .map_err(|_| anyhow::anyhow!("the Keychain item {account} is not text"))?;
                Ok(Some(SecretString::new(value)))
            }
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(anyhow::anyhow!(
                "could not read {account} from the Keychain (error {})",
                e.code()
            )),
        }
    }

    pub fn set(account: &str, value: &SecretString) -> Result<()> {
        set_generic_password(SERVICE, account, value.expose().as_bytes())
            .with_context(|| format!("could not store {account} in the Keychain"))
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use super::SecretString;
    use anyhow::Result;

    pub fn get(_account: &str) -> Result<Option<SecretString>> {
        Ok(None)
    }

    pub fn set(_account: &str, _value: &SecretString) -> Result<()> {
        anyhow::bail!("no Keychain on this system")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_hex() {
        let key = random_key().unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(unhex(&hex(&key)).unwrap(), key);
        assert!(unhex("abc").is_err());
        assert!(unhex(&"zz".repeat(16)).is_err());
        assert!(unhex("00").is_err(), "too short to be a key");
    }
}
