//! Generating keys and describing them: the public key line, the fingerprint, and the type shown
//! on the page.

use rand_core::OsRng;
use rsa::signature::{SignatureEncoding, Signer};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::sha2::{Sha256, Sha512};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey, Signature};

/// A type of key Doozers can generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum KeyType {
    /// Ed25519: the default.
    #[default]
    Ed25519,
    /// RSA with a 3072-bit key.
    Rsa3072,
    /// RSA with a 4096-bit key.
    Rsa4096,
    /// ECDSA on P-256.
    EcdsaP256,
    /// ECDSA on P-384.
    EcdsaP384,
    /// ECDSA on P-521.
    EcdsaP521,
}

impl KeyType {
    /// Every type, in the order the page offers them.
    pub const ALL: [Self; 6] = [
        Self::Ed25519,
        Self::Rsa3072,
        Self::Rsa4096,
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
    ];

    /// The form value of the type.
    pub fn id(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa3072 => "rsa-3072",
            Self::Rsa4096 => "rsa-4096",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::EcdsaP521 => "ecdsa-p521",
        }
    }

    /// The name the page shows.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
            Self::EcdsaP256 => "ECDSA P-256",
            Self::EcdsaP384 => "ECDSA P-384",
            Self::EcdsaP521 => "ECDSA P-521",
        }
    }

    /// The type with form value `id`.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }
}

/// Generates a key of `kind` from the operating system's randomness. RSA takes seconds, so call
/// this on a blocking thread.
pub(super) fn generate(kind: KeyType) -> Result<PrivateKey, ssh_key::Error> {
    let mut rng = OsRng;
    let curve = |curve| Algorithm::Ecdsa { curve };
    match kind {
        KeyType::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519),
        KeyType::Rsa3072 => rsa(&mut rng, 3072),
        KeyType::Rsa4096 => rsa(&mut rng, 4096),
        KeyType::EcdsaP256 => PrivateKey::random(&mut rng, curve(EcdsaCurve::NistP256)),
        KeyType::EcdsaP384 => PrivateKey::random(&mut rng, curve(EcdsaCurve::NistP384)),
        KeyType::EcdsaP521 => PrivateKey::random(&mut rng, curve(EcdsaCurve::NistP521)),
    }
}

fn rsa(rng: &mut OsRng, bits: usize) -> Result<PrivateKey, ssh_key::Error> {
    PrivateKey::new(KeypairData::from(RsaKeypair::random(rng, bits)?), "")
}

/// The `rsa` key of an `ssh-key` RSA key pair.
///
/// `ssh-key` 0.6.7 builds this wrongly (it passes the prime `p` twice, so the key never validates)
/// and so can't sign with an RSA key; this passes `p` and `q`.
pub(crate) fn rsa_private_key(pair: &RsaKeypair) -> Result<rsa::RsaPrivateKey, ssh_key::Error> {
    let big = |n: &ssh_key::Mpint| rsa::BigUint::try_from(n);
    let key = rsa::RsaPrivateKey::from_components(
        big(&pair.public.n)?,
        big(&pair.public.e)?,
        big(&pair.private.d)?,
        vec![big(&pair.private.p)?, big(&pair.private.q)?],
    )
    .map_err(|_| ssh_key::Error::Crypto)?;
    key.validate().map_err(|_| ssh_key::Error::Crypto)?;
    Ok(key)
}

/// Signs `data` with `key` as the SSH signature algorithm of the key's type: `ssh-ed25519` or
/// `ecdsa-sha2-<curve>` by `ssh-key`, and for RSA `rsa-sha2-256` or `rsa-sha2-512` as `rsa_hash`
/// says. RSA never signs with SHA-1 (`ssh-rsa`), which OpenSSH 8.8 and later refuses.
///
/// # Errors
///
/// [`ssh_key::Error::Crypto`] when the key can't sign, or `rsa_hash` isn't SHA-256 or SHA-512 for
/// an RSA key.
pub(crate) fn sign(
    key: &PrivateKey,
    rsa_hash: HashAlg,
    data: &[u8],
) -> Result<Signature, ssh_key::Error> {
    let KeypairData::Rsa(pair) = key.key_data() else {
        return Ok(Signer::try_sign(key, data)?);
    };
    let private = rsa_private_key(pair)?;
    let signature = match rsa_hash {
        HashAlg::Sha256 => rsa::pkcs1v15::SigningKey::<Sha256>::new(private)
            .try_sign(data)
            .map(|s| s.to_vec()),
        HashAlg::Sha512 => rsa::pkcs1v15::SigningKey::<Sha512>::new(private)
            .try_sign(data)
            .map(|s| s.to_vec()),
        _ => return Err(ssh_key::Error::Crypto),
    }
    .map_err(|_| ssh_key::Error::Crypto)?;
    Signature::new(
        Algorithm::Rsa {
            hash: Some(rsa_hash),
        },
        signature,
    )
}

/// What the table stores about a key's public half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PublicParts {
    /// The SSH algorithm name: `ssh-ed25519`.
    pub(super) algorithm: String,
    /// `<algorithm> <base64>`, without a comment.
    pub(super) public_key: String,
    /// `SHA256:...`, as `ssh-keygen -l` prints it.
    pub(super) fingerprint: String,
}

pub(super) fn public_parts(key: &PrivateKey) -> Result<PublicParts, ssh_key::Error> {
    let public = PublicKey::new(key.public_key().key_data().clone(), "");
    Ok(PublicParts {
        algorithm: public.algorithm().to_string(),
        public_key: public.to_openssh()?.trim_end().to_owned(),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// The type of the stored public key as the page shows it (`Ed25519`, `RSA 3072`,
/// `ECDSA P-256`), or the SSH algorithm name if it can't be read.
pub(super) fn type_label(public_key: &str) -> String {
    let Ok(parsed) = PublicKey::from_openssh(public_key) else {
        return public_key.split(' ').next().unwrap_or_default().to_owned();
    };
    match parsed.key_data() {
        KeyData::Ed25519(_) => "Ed25519".to_owned(),
        KeyData::Rsa(key) => {
            let bits = key.n.as_positive_bytes().map_or(0, |n| {
                n.first()
                    .map_or(0, |first| n.len() * 8 - first.leading_zeros() as usize)
            });
            format!("RSA {bits}")
        }
        KeyData::Ecdsa(key) => match key.curve() {
            EcdsaCurve::NistP256 => "ECDSA P-256".to_owned(),
            EcdsaCurve::NistP384 => "ECDSA P-384".to_owned(),
            EcdsaCurve::NistP521 => "ECDSA P-521".to_owned(),
        },
        other => other.algorithm().to_string(),
    }
}
