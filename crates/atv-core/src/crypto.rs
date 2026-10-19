//! Cryptographic primitives, ported from `fake_atv.py`
//! (`CompanionCipher`, `hkdf_expand`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::Error;

/// ChaCha20Poly1305 with separate input/output keys and counter-based
/// nonces, exactly like `fake_atv.CompanionCipher`.
pub struct CompanionCipher {
    output: ChaCha20Poly1305,
    input: ChaCha20Poly1305,
    out_counter: u64,
    in_counter: u64,
    nonce_length: usize,
}

impl CompanionCipher {
    pub fn new(output_key: &[u8], input_key: &[u8], nonce_length: usize) -> Result<Self, Error> {
        if output_key.len() != 32 || input_key.len() != 32 {
            return Err(Error::Crypto("ChaCha20Poly1305 keys must be 32 bytes".into()));
        }
        Ok(Self {
            output: ChaCha20Poly1305::new(Key::from_slice(output_key)),
            input: ChaCha20Poly1305::new(Key::from_slice(input_key)),
            out_counter: 0,
            in_counter: 0,
            nonce_length,
        })
    }

    fn counter_nonce(&self, counter: u64) -> [u8; 12] {
        let mut result = [0u8; 12];
        let pad_len = 12usize.saturating_sub(self.nonce_length);
        let le = counter.to_le_bytes();
        let copy_len = (12 - pad_len).min(le.len());
        result[pad_len..pad_len + copy_len].copy_from_slice(&le[..copy_len]);
        result
    }

    fn explicit_nonce(nonce: &[u8]) -> [u8; 12] {
        let mut padded = [0u8; 12];
        if nonce.len() < 12 {
            padded[12 - nonce.len()..].copy_from_slice(nonce);
        } else {
            padded.copy_from_slice(&nonce[..12]);
        }
        padded
    }

    pub fn encrypt(
        &mut self,
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let nonce_bytes = match nonce {
            None => {
                let n = self.counter_nonce(self.out_counter);
                self.out_counter += 1;
                n
            }
            Some(n) => Self::explicit_nonce(n),
        };
        self.output
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: data,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| Error::Crypto("ChaCha20Poly1305 encrypt failed".into()))
    }

    pub fn decrypt(
        &mut self,
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let nonce_bytes = match nonce {
            None => {
                let n = self.counter_nonce(self.in_counter);
                self.in_counter += 1;
                n
            }
            Some(n) => Self::explicit_nonce(n),
        };
        self.input
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: data,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| Error::Crypto("ChaCha20Poly1305 decrypt failed".into()))
    }
}

/// HKDF-SHA512 with a 32-byte output, like `fake_atv.hkdf_expand`.
pub fn hkdf_expand(salt: &str, info: &str, shared_secret: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha512>::new(Some(salt.as_bytes()), shared_secret);
    let mut okm = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA512 output length");
    okm
}
