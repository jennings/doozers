//! Sealing and opening with AES-256-GCM (`aws-lc-rs`), under a random 96-bit nonce per seal.

use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use giles_store::SealedValue;
use zeroize::Zeroizing;

/// The algorithm name stored with every sealed value.
pub(super) const ALGORITHM: &str = "aes-256-gcm";

/// Key length in bytes: 256 bits.
pub(super) const KEY_LEN: usize = 32;

/// Raw key material, wiped from memory when dropped.
pub(super) type KeyBytes = Zeroizing<[u8; KEY_LEN]>;

/// Fresh random key material.
pub(super) fn random_key() -> KeyBytes {
    let mut bytes = Zeroizing::new([0_u8; KEY_LEN]);
    getrandom::fill(bytes.as_mut()).expect("the OS random number generator failed");
    bytes
}

/// Why a sealed value didn't open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum OpenError {
    /// It was sealed with an algorithm this binary doesn't know.
    #[error("was sealed with an unknown algorithm")]
    UnknownAlgorithm,
    /// The nonce has the wrong length, the tag doesn't match, or the associated data differs:
    /// the wrong key, or a damaged or moved value.
    #[error("doesn't authenticate under this key")]
    Unauthentic,
}

/// An AES-256-GCM key. `aws-lc-rs` wipes its copy of the key when it's dropped.
pub(super) struct Key(RandomizedNonceKey);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Key {
    pub(super) fn new(bytes: &KeyBytes) -> Self {
        Self(
            RandomizedNonceKey::new(&AES_256_GCM, bytes.as_ref())
                .expect("a 32-byte key is valid for AES-256-GCM"),
        )
    }

    /// Seals `plaintext`, binding `aad` to it: opening needs the same `aad`.
    pub(super) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> SealedValue {
        let mut buffer = plaintext.to_vec();
        let nonce = self
            .0
            .seal_in_place_append_tag(Aad::from(aad), &mut buffer)
            .expect("AES-GCM sealing fails only if the random number generator does");
        SealedValue {
            algorithm: ALGORITHM.to_owned(),
            nonce: nonce.as_ref().to_vec(),
            ciphertext: buffer,
        }
    }

    /// Opens `sealed`, which must have been sealed by this key with the same `aad`.
    pub(super) fn open(
        &self,
        aad: &[u8],
        sealed: &SealedValue,
    ) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        if sealed.algorithm != ALGORITHM {
            return Err(OpenError::UnknownAlgorithm);
        }
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| OpenError::Unauthentic)?;
        let mut buffer = Zeroizing::new(sealed.ciphertext.clone());
        let len = self
            .0
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                buffer.as_mut_slice(),
            )
            .map_err(|_| OpenError::Unauthentic)?
            .len();
        buffer.truncate(len);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_opens_only_with_its_key_and_associated_data() {
        let key = Key::new(&random_key());
        let sealed = key.seal(b"ssh/prod", b"hunter2");
        assert_eq!(sealed.algorithm, ALGORITHM);
        assert!(!sealed.ciphertext.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(
            key.open(b"ssh/prod", &sealed).unwrap().as_slice(),
            b"hunter2"
        );

        assert_eq!(key.open(b"ssh/test", &sealed), Err(OpenError::Unauthentic));
        let other = Key::new(&random_key());
        assert_eq!(
            other.open(b"ssh/prod", &sealed),
            Err(OpenError::Unauthentic)
        );
        let mut flipped = sealed.clone();
        flipped.ciphertext[0] ^= 1;
        assert_eq!(key.open(b"ssh/prod", &flipped), Err(OpenError::Unauthentic));
        let short = SealedValue {
            nonce: vec![0; 8],
            ..sealed.clone()
        };
        assert_eq!(key.open(b"ssh/prod", &short), Err(OpenError::Unauthentic));
        let unknown = SealedValue {
            algorithm: "rot13".into(),
            ..sealed
        };
        assert_eq!(
            key.open(b"ssh/prod", &unknown),
            Err(OpenError::UnknownAlgorithm)
        );
    }

    #[test]
    fn sealing_twice_uses_a_fresh_nonce() {
        let key = Key::new(&random_key());
        let a = key.seal(b"x", b"same");
        let b = key.seal(b"x", b"same");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
