//! SRP-6a server session, Apple Pair-Setup variant.
//!
//! Ported from the `srptools` Python package (SRPContext/SRPServerSession)
//! as configured by `fake_atv._reset_pairing_session`:
//! SHA-512, the RFC 5054 3072-bit group, 128-bit salt, and a fixed server
//! private key `b` (32 bytes of 0xaa, the Companion signing key bytes).
//!
//! All integers serialize to their minimal big-endian byte representation
//! (matching srptools' `int_to_bytes`); only `pad()` left-pads to the prime
//! width.

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::error::Error;

/// RFC 5054 3072-bit prime (srptools `PRIME_3072`).
pub const PRIME_3072_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6\
3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411\
7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08\
CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760273\
3EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

const GENERATOR: u64 = 5;
const SALT_BITS: usize = 128;

/// Minimal big-endian bytes of a bigint (srptools `int_to_bytes`).
pub fn int_to_bytes(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        // Python: hex(0) -> "0" -> "00" -> b"\x00"
        return vec![0];
    }
    value.to_bytes_be()
}

fn sha512_int(data: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&Sha512::digest(data))
}

/// Server-side SRP session for one pair-setup attempt.
pub struct SrpServer {
    n: BigUint,
    g: BigUint,
    verifier: BigUint,
    server_private: BigUint,
    salt: Vec<u8>,
    server_public: BigUint,
    client_public: Option<BigUint>,
    session_key: Option<Vec<u8>>,
    key_proof: Option<Vec<u8>>,
}

impl SrpServer {
    /// Create a session with a fresh random 128-bit salt.
    pub fn new(pin: u32, server_private: &[u8]) -> Self {
        let mut salt_bytes = [0u8; SALT_BITS / 8];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        Self::with_salt(pin, server_private, &salt_bytes)
    }

    /// Create a session with an explicit salt (raw bytes, as generated).
    pub fn with_salt(pin: u32, server_private: &[u8], salt: &[u8]) -> Self {
        let n = BigUint::parse_bytes(PRIME_3072_HEX.as_bytes(), 16).expect("valid prime");
        let g = BigUint::from(GENERATOR);
        // k = H(N | PAD(g))
        let k = sha512_int(&[int_to_bytes(&n), pad(&g, &n)].concat());

        // x = H(s | H(I | ":" | P)), I = "Pair-Setup", P = decimal PIN
        let inner = Sha512::digest(format!("Pair-Setup:{pin}").as_bytes());
        let x = sha512_int(&[salt, &inner].concat());

        // v = g^x % N
        let verifier = g.modpow(&x, &n);

        // b = fixed server private (32 bytes of 0xaa in fake_atv)
        let server_private = BigUint::from_bytes_be(server_private);

        // B = (k*v + g^b) % N
        let server_public = (&k * &verifier + g.modpow(&server_private, &n)) % &n;

        Self {
            n,
            g,
            verifier,
            server_private,
            salt: salt.to_vec(),
            server_public,
            client_public: None,
            session_key: None,
            key_proof: None,
        }
    }

    /// Salt as sent in the M2 TLV (minimal bytes).
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Server public key B as sent in the M2 TLV (minimal bytes).
    pub fn public_key(&self) -> Vec<u8> {
        int_to_bytes(&self.server_public)
    }

    /// Process the client's public key A (SRPServerSession.process).
    pub fn process(&mut self, client_public: &[u8]) -> Result<(), Error> {
        let a = BigUint::from_bytes_be(client_public);
        if &a % &self.n == BigUint::zero() {
            return Err(Error::Srp("client public key is zero mod N".into()));
        }

        // u = H(PAD(A) | PAD(B))
        let u = sha512_int(
            &[
                pad(&a, &self.n),
                pad(&self.server_public, &self.n),
            ]
            .concat(),
        );

        // S = (A * v^u) ^ b % N
        let premaster = (&a * self.verifier.modpow(&u, &self.n)) % &self.n;
        let premaster = premaster.modpow(&self.server_private, &self.n);

        // K = H(S)
        let session_key = Sha512::digest(int_to_bytes(&premaster)).to_vec();

        // M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
        let hn = sha512_int(&int_to_bytes(&self.n));
        let hg = sha512_int(&int_to_bytes(&self.g));
        let xor = int_to_bytes(&(hn ^ hg));
        let mut proof_input =
            Vec::with_capacity(xor.len() + 64 + self.salt.len() + 2 * 384 + 64);
        proof_input.extend_from_slice(&xor);
        proof_input.extend_from_slice(&Sha512::digest(b"Pair-Setup"));
        proof_input.extend_from_slice(&self.salt);
        proof_input.extend_from_slice(&int_to_bytes(&a));
        proof_input.extend_from_slice(&int_to_bytes(&self.server_public));
        proof_input.extend_from_slice(&session_key);
        let key_proof = Sha512::digest(&proof_input).to_vec();

        self.client_public = Some(a);
        self.session_key = Some(session_key);
        self.key_proof = Some(key_proof);
        Ok(())
    }

    /// Verify the client's proof M1 (SRPServerSession.verify_proof).
    pub fn verify_proof(&self, proof: &[u8]) -> bool {
        self.key_proof.as_deref() == Some(proof)
    }

    /// H(A | M | K), sent back in the M4 TLV (srptools `key_proof_hash`).
    pub fn key_proof_hash(&self) -> Result<Vec<u8>, Error> {
        let a = self.client_public.as_ref().ok_or_else(|| {
            Error::Srp("process() must be called before key_proof_hash()".into())
        })?;
        let proof = self.key_proof.as_ref().unwrap();
        let key = self.session_key.as_ref().unwrap();
        let mut input = Vec::with_capacity(384 + 64 + 64);
        input.extend_from_slice(&int_to_bytes(a));
        input.extend_from_slice(proof);
        input.extend_from_slice(key);
        Ok(Sha512::digest(&input).to_vec())
    }

    /// The 64-byte SRP session key K (srptools `session.key`, unhexlified).
    pub fn session_key(&self) -> Result<&[u8], Error> {
        self.session_key
            .as_deref()
            .ok_or_else(|| Error::Srp("process() must be called first".into()))
    }
}

/// Left-pad the minimal byte representation of `value` to the byte width of
/// the prime (srptools `SRPContext.pad`).
fn pad(value: &BigUint, prime: &BigUint) -> Vec<u8> {
    let width = int_to_bytes(prime).len();
    let bytes = int_to_bytes(value);
    let mut padded = vec![0u8; width.saturating_sub(bytes.len())];
    padded.extend_from_slice(&bytes);
    padded
}
