//! Repository signing identity helpers.

use p256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::commit::CommitSigner;

const P256_SECRET_KEY_LEN: usize = 32;
const P256_SIGNATURE_LEN: usize = 64;
const P256_PUB_MULTICODEC_VARINT: [u8; 2] = [0x80, 0x24];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoSigningKey {
    secret_key_bytes: [u8; P256_SECRET_KEY_LEN],
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid P-256 signing key hex: expected 64 lowercase or uppercase hex characters")]
    InvalidSigningKeyHex,

    #[error("invalid P-256 signing key")]
    InvalidSigningKey,

    #[error("invalid P-256 public key")]
    InvalidPublicKey,

    #[error("invalid P-256 signature")]
    InvalidSignature,

    #[error("P-256 signature verification failed")]
    VerificationFailed,

    #[error("failed to sign with P-256 key")]
    SigningFailed,
}

impl RepoSigningKey {
    pub fn from_p256_hex(value: &str) -> Result<Self, IdentityError> {
        let bytes = decode_fixed_hex::<P256_SECRET_KEY_LEN>(value)?;
        SigningKey::from_slice(&bytes).map_err(|_| IdentityError::InvalidSigningKey)?;
        Ok(Self {
            secret_key_bytes: bytes,
        })
    }

    pub fn to_p256_hex(&self) -> String {
        encode_hex(&self.secret_key_bytes)
    }

    pub fn public_key_multibase(&self) -> Result<String, IdentityError> {
        let key = self.signing_key()?;
        public_key_multibase(key.verifying_key())
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        Ok(*self.signing_key()?.verifying_key())
    }

    fn signing_key(&self) -> Result<SigningKey, IdentityError> {
        SigningKey::from_slice(&self.secret_key_bytes).map_err(|_| IdentityError::InvalidSigningKey)
    }
}

impl CommitSigner for RepoSigningKey {
    fn sign_commit(&self, signable_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.signing_key().map_err(|error| error.to_string())?;
        let digest = Sha256::digest(signable_bytes);
        let signature: Signature = key
            .sign_prehash(&digest)
            .map_err(|_| IdentityError::SigningFailed.to_string())?;
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().to_vec())
    }
}

pub fn public_key_multibase(verifying_key: &VerifyingKey) -> Result<String, IdentityError> {
    let point = verifying_key.to_encoded_point(true);
    let bytes = point.as_bytes();
    if bytes.len() != 33 {
        return Err(IdentityError::InvalidPublicKey);
    }

    let mut multikey = Vec::with_capacity(P256_PUB_MULTICODEC_VARINT.len() + bytes.len());
    multikey.extend_from_slice(&P256_PUB_MULTICODEC_VARINT);
    multikey.extend_from_slice(bytes);
    Ok(format!("z{}", bs58::encode(multikey).into_string()))
}

pub fn verify_p256_signature(
    verifying_key: &VerifyingKey,
    signable_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), IdentityError> {
    if signature_bytes.len() != P256_SIGNATURE_LEN {
        return Err(IdentityError::InvalidSignature);
    }
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| IdentityError::InvalidSignature)?;
    let digest = Sha256::digest(signable_bytes);
    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| IdentityError::VerificationFailed)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], IdentityError> {
    if value.len() != N * 2 {
        return Err(IdentityError::InvalidSigningKeyHex);
    }

    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, IdentityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(IdentityError::InvalidSigningKeyHex),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::decode_dag_cbor;
    use crate::cid::dag_cbor_cid;
    use crate::commit::{Did, RepoRev, SignedCommit, UnsignedCommit};

    const TEST_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn parses_and_serializes_p256_secret_key_hex() {
        let key = RepoSigningKey::from_p256_hex(TEST_KEY_HEX).unwrap();

        assert_eq!(key.to_p256_hex(), TEST_KEY_HEX);
    }

    #[test]
    fn rejects_invalid_secret_keys() {
        assert!(RepoSigningKey::from_p256_hex("01").is_err());
        assert!(RepoSigningKey::from_p256_hex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        assert!(RepoSigningKey::from_p256_hex(
            "gg00000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
    }

    #[test]
    fn encodes_p256_public_key_as_multikey_multibase() {
        let key = RepoSigningKey::from_p256_hex(TEST_KEY_HEX).unwrap();
        let public_key = key.public_key_multibase().unwrap();

        assert!(public_key.starts_with('z'));
        let decoded = bs58::decode(public_key.trim_start_matches('z'))
            .into_vec()
            .unwrap();
        assert_eq!(&decoded[..2], &P256_PUB_MULTICODEC_VARINT);
        assert_eq!(decoded.len(), 35);
        assert!(matches!(decoded[2], 0x02 | 0x03));
    }

    #[test]
    fn signs_and_verifies_commit_signable_bytes() {
        let key = RepoSigningKey::from_p256_hex(TEST_KEY_HEX).unwrap();
        let unsigned = UnsignedCommit::new(
            Did::new("did:web:example.com").unwrap(),
            dag_cbor_cid(b"mst-root"),
            RepoRev::new("2222222222222").unwrap(),
            None,
        );

        let signed = unsigned.sign_with(&key).unwrap();
        assert_eq!(signed.sig.len(), P256_SIGNATURE_LEN);
        verify_p256_signature(
            &key.verifying_key().unwrap(),
            &signed.signable_bytes().unwrap(),
            &signed.sig,
        )
        .unwrap();

        let block = signed.encode_block().unwrap();
        let decoded: SignedCommit = decode_dag_cbor(&block.bytes).unwrap();
        assert_eq!(decoded.sig, signed.sig);
    }
}
