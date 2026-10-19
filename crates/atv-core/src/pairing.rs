//! Authenticated controller keys, persisted only in the receiver's private storage.
use crate::error::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct PairingStore {
    path: Option<PathBuf>,
    keys: HashMap<Vec<u8>, [u8; 32]>,
    attempts: Vec<Instant>,
}

impl PairingStore {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let mut keys = HashMap::new();
        if let Some(ref path) = path {
            match fs::read_to_string(path) {
                Ok(content) => {
                    for line in content.lines() {
                        let (id, key) = line
                            .split_once(':')
                            .ok_or_else(|| Error::Protocol("invalid pairing store".into()))?;
                        let id = hex::decode(id)
                            .map_err(|_| Error::Protocol("invalid paired identifier".into()))?;
                        let key: [u8; 32] =
                            hex::decode(key)
                                .ok()
                                .and_then(|k| k.try_into().ok())
                                .ok_or_else(|| Error::Protocol("invalid paired key".into()))?;
                        keys.insert(id, key);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Self {
            path,
            keys,
            attempts: Vec::new(),
        })
    }

    pub fn begin_setup(&mut self) -> Result<()> {
        let now = Instant::now();
        self.attempts
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if self.attempts.len() >= 5 {
            return Err(Error::Protocol(
                "pairing rate limit; retry in one minute".into(),
            ));
        }
        self.attempts.push(now);
        Ok(())
    }

    pub fn key(&self, id: &[u8]) -> Option<[u8; 32]> {
        self.keys.get(id).copied()
    }

    pub fn insert(&mut self, id: &[u8], key: [u8; 32]) -> Result<()> {
        if id.is_empty() || id.len() > 256 || self.keys.len() >= 32 && !self.keys.contains_key(id) {
            return Err(Error::Protocol(
                "invalid or excessive paired controllers".into(),
            ));
        }
        let mut keys = self.keys.clone();
        keys.insert(id.to_vec(), key);
        if let Some(ref path) = self.path {
            let tmp = path.with_extension("tmp");
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp)?;
            for (id, key) in &keys {
                writeln!(file, "{}:{}", hex::encode(id), hex::encode(key))?;
            }
            file.sync_all()?;
            fs::rename(tmp, path)?;
        }
        self.keys = keys;
        Ok(())
    }
}

pub fn verify_signature(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(key)
        .map_err(|_| Error::Crypto("invalid controller key".into()))?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| Error::Crypto("invalid controller signature".into()))?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::Crypto("controller signature mismatch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn signatures_reject_other_keys_changed_messages_and_missing_proofs() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key().to_bytes();
        let proof = key
            .sign(b"ephemeral-client:controller-id:ephemeral-server")
            .to_bytes();
        assert!(verify_signature(
            &public,
            b"ephemeral-client:controller-id:ephemeral-server",
            &proof
        )
        .is_ok());
        assert!(verify_signature(&public, b"changed-session", &proof).is_err());
        assert!(verify_signature(
            &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            b"ephemeral-client:controller-id:ephemeral-server",
            &proof
        )
        .is_err());
        assert!(verify_signature(&public, b"message", &[]).is_err());
    }
    #[test]
    fn paired_keys_survive_restart_and_unknown_controllers_fail_closed() {
        let path = std::env::temp_dir().join(format!("remote-tv-pairing-{}", uuid::Uuid::new_v4()));
        let mut store = PairingStore::load(Some(path.clone())).unwrap();
        assert_eq!(store.key(b"unknown"), None);
        store.insert(b"phone", [7; 32]).unwrap();
        assert_eq!(
            PairingStore::load(Some(path.clone()))
                .unwrap()
                .key(b"phone"),
            Some([7; 32])
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(&path, "corrupt").unwrap();
        assert!(PairingStore::load(Some(path.clone())).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn pairing_attempts_are_limited_across_connections() {
        let mut store = PairingStore::load(None).unwrap();
        for _ in 0..5 {
            store.begin_setup().unwrap();
        }
        assert!(store.begin_setup().is_err());
        store.attempts.clear();
        assert!(store.begin_setup().is_ok());
    }
}
