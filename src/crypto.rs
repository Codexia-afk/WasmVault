use anyhow::{Context, Result};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sha2::{Digest, Sha256};
use hex;

pub struct Crypto;

impl Crypto {
    pub fn hash_binary(wasm_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(wasm_bytes);
        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn verify_signature(wasm_bytes: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<bool> {
        let pub_key_bytes = hex::decode(public_key_hex).context("Invalid hex in public key")?;
        let sig_bytes = hex::decode(signature_hex).context("Invalid hex in signature")?;

        let verifying_key = VerifyingKey::try_from(pub_key_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Invalid ed25519 public key: {}", e))?;

        let signature = Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Invalid ed25519 signature format: {}", e))?;

        Ok(verifying_key.verify(wasm_bytes, &signature).is_ok())
    }
}
