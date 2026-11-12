use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::io::Write;

use crate::register::AccountData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_pub_key: String,
    pub license: String,
    pub id: String,
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {path}"))?;
        serde_json::from_str(&data).with_context(|| "failed to parse config JSON")
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let parent = Path::new(path).parent().filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temp.write_all(json.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist(path).with_context(|| format!("failed to replace config at {path}"))?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn from_account_data(account: &AccountData, token: &str, priv_key_der: &[u8]) -> Self {
        let peer = &account.config.peers[0];
        let ep_v4 = peer.endpoint.v4.trim_end_matches(":0").to_string();
        let ep_v6 = peer.endpoint.v6.clone();
        let ep_v6 = ep_v6
            .trim_start_matches('[')
            .trim_end_matches("]:0")
            .trim_end_matches(":0")
            .to_string();

        Self {
            private_key: base64::engine::general_purpose::STANDARD.encode(priv_key_der),
            endpoint_v4: ep_v4,
            endpoint_v6: ep_v6,
            endpoint_pub_key: peer.public_key.clone(),
            license: account.account.license.clone().unwrap_or_default(),
            id: account.id.clone(),
            access_token: token.to_string(),
            ipv4: account.config.interface.addresses.v4.clone(),
            ipv6: account.config.interface.addresses.v6.clone(),
        }
    }

    pub fn get_ec_private_key_der(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.private_key)
            .with_context(|| "failed to decode private key from base64")
    }

    pub fn get_endpoint_pub_key_der(&self) -> Result<Vec<u8>> {
        let pem = pem::parse(&self.endpoint_pub_key)
            .with_context(|| "failed to parse endpoint public key PEM")?;
        Ok(pem.contents().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Config {
        Config {
            private_key: "test-only".into(),
            endpoint_v4: "192.0.2.1".into(),
            endpoint_v6: "2001:db8::1".into(),
            endpoint_pub_key: String::new(),
            license: String::new(),
            id: "test-device".into(),
            access_token: "test-token".into(),
            ipv4: "100.96.0.2".into(),
            ipv6: "fd00::2".into(),
        }
    }

    #[test]
    fn save_replaces_an_existing_config_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "old contents").unwrap();
        let cfg = example();
        cfg.save(path.to_str().unwrap()).unwrap();
        let loaded = Config::load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.id, cfg.id);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn save_restricts_permissions_even_when_replacing_a_public_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "old contents").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        example().save(path.to_str().unwrap()).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
