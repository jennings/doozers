//! Reading the private keys users upload.
//!
//! Every supported format ends as an unencrypted [`PrivateKey`] of one of the supported types
//! (Ed25519, RSA, ECDSA on P-256, P-384, or P-521). `ssh-key` reads OpenSSH files, encrypted or
//! not. The PEM formats it doesn't read are decoded here with the RustCrypto crates and converted:
//! PKCS#1 RSA, SEC1 EC, PKCS#8 (plain, or `ENCRYPTED PRIVATE KEY` with PBES2), and the legacy
//! OpenSSL encryption of the first two (`Proc-Type: 4,ENCRYPTED`, which
//! `ssh-keygen -m PEM -N <passphrase>` writes). Nothing here logs or returns key material, and
//! every message names what the user can do about it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use md5::{Digest, Md5};
use pkcs8::der::asn1::{BitStringRef, OctetStringRef};
use pkcs8::der::{Decode, Header, Reader, SliceReader, Tag, TagNumber};
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyInfo, ObjectIdentifier, PrivateKeyInfo};
use rsa::pkcs1::DecodeRsaPrivateKey;
use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::{Algorithm, Cipher, EcdsaCurve, PrivateKey};
use zeroize::Zeroizing;

/// The largest upload, in bytes. A private key file is a few kilobytes.
pub const MAX_UPLOAD_BYTES: usize = 64 * 1024;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const DSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// An upload couldn't be turned into a key. The messages are for the person who uploaded it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyFileError {
    /// The upload is longer than [`MAX_UPLOAD_BYTES`].
    #[error("that file is larger than {} KiB, so it isn't a private key", MAX_UPLOAD_BYTES / 1024)]
    TooLarge,
    /// Nothing was pasted or chosen.
    #[error("paste a private key or choose a key file")]
    Empty,
    /// The text isn't a private key in a format Doozers reads.
    #[error(
        "that isn't a private key Doozers can read; use an OpenSSH, PKCS#1 RSA, SEC1 EC, or \
         PKCS#8 private key in PEM text"
    )]
    NotAKey,
    /// The user pasted a public key.
    #[error("that is a public key; upload the private key, or generate a key here instead")]
    PublicKey,
    /// A PuTTY key file.
    #[error(
        "PuTTY key files aren't supported; convert it with `puttygen key.ppk -O private-openssh \
         -o key` and upload `key`"
    )]
    Putty,
    /// A DSA key.
    #[error("DSA keys aren't supported: OpenSSH 10.0 removed DSA; use Ed25519, RSA, or ECDSA")]
    Dsa,
    /// A FIDO security key.
    #[error(
        "security keys (`sk-` keys) aren't supported: their private key stays on the hardware \
         token, which Doozers doesn't have"
    )]
    SecurityKey,
    /// An algorithm or curve Doozers can't sign with.
    #[error("{0}; use Ed25519, RSA, or ECDSA on P-256, P-384, or P-521")]
    UnsupportedAlgorithm(String),
    /// A PEM block of another kind.
    #[error(
        "`{0}` isn't a supported private key format; use an OpenSSH, PKCS#1 RSA, SEC1 EC, or \
         PKCS#8 private key"
    )]
    UnsupportedFormat(String),
    /// The key is encrypted with a cipher Doozers doesn't read.
    #[error(
        "the key is encrypted with {0}, which Doozers can't read; convert it with \
         `ssh-keygen -p -f <file>` (which writes the OpenSSH format) and upload the result"
    )]
    UnsupportedCipher(String),
    /// The key's encryption settings ask for more memory or time than any real key needs, which
    /// is how a crafted file would try to exhaust the server.
    #[error(
        "the key's encryption settings ask for too much work to try ({0}); re-encrypt it with \
         `ssh-keygen -p -f <file>` and upload the result"
    )]
    TooExpensive(String),
    /// The key is encrypted and no passphrase was given.
    #[error("the key is passphrase-protected; enter its passphrase")]
    PassphraseRequired,
    /// The passphrase doesn't decrypt the key.
    #[error("the passphrase is wrong")]
    WrongPassphrase,
    /// The key data is damaged or incomplete.
    #[error("the key is damaged or incomplete: {0}")]
    Malformed(String),
}

fn malformed(error: impl std::fmt::Display) -> KeyFileError {
    KeyFileError::Malformed(error.to_string())
}

/// Reads a private key from the text of an upload, decrypting it with `passphrase` if it is
/// encrypted. A passphrase given for an unencrypted key is ignored, and so is an empty one.
///
/// The key's comment, if the format has one, stays on the returned key.
///
/// # Errors
///
/// [`KeyFileError`], saying why the upload isn't an acceptable key.
pub fn parse_private_key(
    input: &[u8],
    passphrase: Option<&str>,
) -> Result<PrivateKey, KeyFileError> {
    if input.len() > MAX_UPLOAD_BYTES {
        return Err(KeyFileError::TooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| KeyFileError::NotAKey)?;
    // A browser sends a textarea's line breaks as CRLF.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let text = text.trim();
    if text.is_empty() {
        return Err(KeyFileError::Empty);
    }
    if text.starts_with("PuTTY-User-Key-File-") {
        return Err(KeyFileError::Putty);
    }
    let passphrase = passphrase.filter(|p| !p.is_empty());
    let Some(block) = Pem::find(text) else {
        let first = text.split_whitespace().next().unwrap_or_default();
        return Err(
            if first.starts_with("ssh-") || first.starts_with("ecdsa-") || first.starts_with("sk-")
            {
                KeyFileError::PublicKey
            } else {
                KeyFileError::NotAKey
            },
        );
    };
    let key = match block.label.as_str() {
        "OPENSSH PRIVATE KEY" => openssh(&block.text, passphrase)?,
        "RSA PRIVATE KEY" => {
            let der = block.der(passphrase)?;
            decrypted_as(block.is_encrypted(), || rsa_from_pkcs1(&der))?
        }
        "EC PRIVATE KEY" => {
            let der = block.der(passphrase)?;
            decrypted_as(block.is_encrypted(), || ec_from_sec1(&der))?
        }
        "PRIVATE KEY" => from_pkcs8(&block.der(None)?)?,
        "ENCRYPTED PRIVATE KEY" => {
            let passphrase = passphrase.ok_or(KeyFileError::PassphraseRequired)?;
            let der = decrypt_pkcs8(&block.body()?, passphrase)?;
            decrypted_as(true, || from_pkcs8(&der))?
        }
        "DSA PRIVATE KEY" => return Err(KeyFileError::Dsa),
        other => return Err(KeyFileError::UnsupportedFormat(other.to_owned())),
    };
    supported(&key)?;
    Ok(key)
}

/// Runs `parse` on what decryption produced. Decrypting with the wrong passphrase sometimes gets
/// past the padding check and yields garbage, which then fails to parse: that is a wrong
/// passphrase, not a damaged key.
fn decrypted_as(
    encrypted: bool,
    parse: impl FnOnce() -> Result<PrivateKey, KeyFileError>,
) -> Result<PrivateKey, KeyFileError> {
    match parse() {
        Err(KeyFileError::Malformed(_)) if encrypted => Err(KeyFileError::WrongPassphrase),
        result => result,
    }
}

/// Refuses the algorithms `ssh-key` can read but Doozers can't sign with.
fn supported(key: &PrivateKey) -> Result<(), KeyFileError> {
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } => Ok(()),
        Algorithm::Ecdsa { .. } => Ok(()),
        Algorithm::Dsa => Err(KeyFileError::Dsa),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256 => Err(KeyFileError::SecurityKey),
        other => Err(KeyFileError::UnsupportedAlgorithm(format!(
            "The key algorithm {other} isn't supported"
        ))),
    }
}

/// The most bcrypt-pbkdf rounds an OpenSSH key may ask for. `ssh-keygen -a` defaults to 16 and
/// each round costs on the order of ten milliseconds, so 1024 is generous. The file's own value
/// could be 4,294,967,295.
const MAX_BCRYPT_ROUNDS: u32 = 1024;

/// An OpenSSH private key file, decrypted if it has to be.
fn openssh(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyFileError> {
    let key = PrivateKey::from_openssh(text).map_err(malformed)?;
    // The public half of an encrypted key is readable, so refuse before asking for a passphrase.
    supported(&key)?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    if let ssh_key::Kdf::Bcrypt { rounds, .. } = key.kdf()
        && *rounds > MAX_BCRYPT_ROUNDS
    {
        return Err(KeyFileError::TooExpensive(format!(
            "bcrypt rounds is over {MAX_BCRYPT_ROUNDS}"
        )));
    }
    let passphrase = passphrase.ok_or(KeyFileError::PassphraseRequired)?;
    key.decrypt(passphrase).map_err(|error| match error {
        ssh_key::Error::Crypto => KeyFileError::WrongPassphrase,
        other => malformed(other),
    })
}

/// One PEM block of the upload.
struct Pem {
    /// What follows `BEGIN `: `RSA PRIVATE KEY`.
    label: String,
    /// The block's lines from `BEGIN` to `END`, joined by `\n`.
    text: String,
    /// The RFC 1421 headers (`Proc-Type`, `DEK-Info`), name and value.
    headers: Vec<(String, String)>,
    /// The base64 lines of the body.
    base64: String,
}

impl Pem {
    /// The first block in `text`, if it has a `BEGIN` line and a matching `END` line.
    fn find(text: &str) -> Option<Self> {
        let mut lines = text.lines().map(str::trim);
        let label = lines.find_map(|line| {
            line.strip_prefix("-----BEGIN ")?
                .strip_suffix("-----")
                .map(str::to_owned)
        })?;
        let end = format!("-----END {label}-----");
        let mut block = vec![format!("-----BEGIN {label}-----")];
        let mut headers = Vec::new();
        let mut base64 = String::new();
        let mut in_headers = true;
        for line in lines {
            block.push(line.to_owned());
            if line == end {
                return Some(Self {
                    label,
                    text: block.join("\n"),
                    headers,
                    base64,
                });
            }
            if in_headers && let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            } else if line.is_empty() {
                in_headers = false;
            } else {
                in_headers = false;
                base64.push_str(line);
            }
        }
        None
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether the body is encrypted with OpenSSL's legacy scheme.
    fn is_encrypted(&self) -> bool {
        self.header("Proc-Type")
            .is_some_and(|value| value.contains("ENCRYPTED"))
    }

    /// The decoded body, still encrypted if the block is.
    fn body(&self) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
        STANDARD
            .decode(&self.base64)
            .map(Zeroizing::new)
            .map_err(|_| malformed("the PEM text isn't valid base64"))
    }

    /// The body's DER, decrypting the legacy OpenSSL encryption if the block has it.
    fn der(&self, passphrase: Option<&str>) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
        let mut body = self.body()?;
        if !self.is_encrypted() {
            return Ok(body);
        }
        let dek = self
            .header("DEK-Info")
            .ok_or_else(|| malformed("the encrypted key has no DEK-Info header"))?;
        let (name, iv) = dek.split_once(',').unwrap_or((dek, ""));
        let name = name.trim();
        let cipher = match name.to_ascii_uppercase().as_str() {
            "AES-128-CBC" => Cipher::Aes128Cbc,
            "AES-192-CBC" => Cipher::Aes192Cbc,
            "AES-256-CBC" => Cipher::Aes256Cbc,
            _ => return Err(KeyFileError::UnsupportedCipher(name.to_owned())),
        };
        let iv = decode_hex(iv.trim())
            .filter(|iv| iv.len() == 16)
            .ok_or_else(|| malformed("the DEK-Info IV isn't 16 bytes of hex"))?;
        let passphrase = passphrase.ok_or(KeyFileError::PassphraseRequired)?;
        let (key_len, _) = cipher
            .key_and_iv_size()
            .expect("AES-CBC has a key and an IV");
        let key = evp_bytes_to_key(passphrase.as_bytes(), &iv[..8], key_len);
        if body.is_empty() || body.len() % 16 != 0 {
            return Err(malformed(
                "the encrypted body isn't a whole number of blocks",
            ));
        }
        cipher
            .decrypt(&key, &iv, &mut body, None)
            .map_err(|_| KeyFileError::WrongPassphrase)?;
        // PKCS#7 padding: a wrong key almost always breaks it.
        let pad = usize::from(*body.last().expect("the body isn't empty"));
        if pad == 0
            || pad > 16
            || body[body.len() - pad..]
                .iter()
                .any(|b| usize::from(*b) != pad)
        {
            return Err(KeyFileError::WrongPassphrase);
        }
        let len = body.len() - pad;
        body.truncate(len);
        Ok(body)
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one iteration: the key of a legacy encrypted PEM file.
/// `D1 = MD5(passphrase || salt)`, `Dn = MD5(D(n-1) || passphrase || salt)`, concatenated until
/// there are `len` bytes.
fn evp_bytes_to_key(passphrase: &[u8], salt: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut previous: Vec<u8> = Vec::new();
    while key.len() < len {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(passphrase);
        digest.update(salt);
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(len);
    key
}

fn rsa_from_pkcs1(der: &[u8]) -> Result<PrivateKey, KeyFileError> {
    let key = rsa::RsaPrivateKey::from_pkcs1_der(der).map_err(malformed)?;
    rsa_key(&key)
}

fn rsa_key(key: &rsa::RsaPrivateKey) -> Result<PrivateKey, KeyFileError> {
    let pair = RsaKeypair::try_from(key).map_err(malformed)?;
    PrivateKey::new(KeypairData::from(pair), "").map_err(malformed)
}

/// The parts of a SEC1 `ECPrivateKey` that matter here. The `sec1` crate can't read the key when
/// the curve is given as explicit parameters instead of a name, which LibreSSL's `ssh-keygen -m PEM`
/// (macOS) writes, so the structure is read by hand:
/// `SEQUENCE { INTEGER version, OCTET STRING scalar, [0] parameters, [1] BIT STRING public }`.
struct Sec1 {
    scalar: Zeroizing<Vec<u8>>,
    /// The named curve of `[0]`, if it is a name.
    curve: Option<ObjectIdentifier>,
    /// The public point of `[1]`, if present.
    public: Option<Vec<u8>>,
}

fn read_sec1(der: &[u8]) -> Result<Sec1, KeyFileError> {
    let invalid = |_| malformed("the EC key isn't a SEC1 ECPrivateKey");
    let mut reader = SliceReader::new(der).map_err(invalid)?;
    let outer = Header::decode(&mut reader).map_err(invalid)?;
    outer.tag.assert_eq(Tag::Sequence).map_err(invalid)?;
    reader
        .read_nested(outer.length, |seq| {
            let version = u8::decode(seq)?;
            if version != 1 {
                return Err(Tag::Integer.value_error());
            }
            let scalar = OctetStringRef::decode(seq)?;
            let mut key = Sec1 {
                scalar: Zeroizing::new(scalar.as_bytes().to_vec()),
                curve: None,
                public: None,
            };
            while !seq.is_finished() {
                let header = Header::decode(seq)?;
                let body = seq.read_slice(header.length)?;
                match header.tag {
                    Tag::ContextSpecific {
                        number: TagNumber::N0,
                        ..
                    } => key.curve = ObjectIdentifier::from_der(body).ok(),
                    Tag::ContextSpecific {
                        number: TagNumber::N1,
                        ..
                    } => key.public = BitStringRef::from_der(body)?.as_bytes().map(<[u8]>::to_vec),
                    _ => {}
                }
            }
            Ok(key)
        })
        .map_err(invalid)
}

fn curve_of(oid: ObjectIdentifier) -> Result<EcdsaCurve, KeyFileError> {
    match oid {
        P256 => Ok(EcdsaCurve::NistP256),
        P384 => Ok(EcdsaCurve::NistP384),
        P521 => Ok(EcdsaCurve::NistP521),
        other => Err(KeyFileError::UnsupportedAlgorithm(format!(
            "ECDSA on the curve {other} isn't supported"
        ))),
    }
}

fn explicit_curve() -> KeyFileError {
    KeyFileError::UnsupportedAlgorithm(
        "An ECDSA key that spells out its curve's parameters, and isn't on P-256, P-384, or \
         P-521, isn't supported"
            .to_owned(),
    )
}

/// The size of a field element, and so of a private scalar, on `curve`.
fn scalar_size(curve: EcdsaCurve) -> usize {
    match curve {
        EcdsaCurve::NistP256 => 32,
        EcdsaCurve::NistP384 => 48,
        EcdsaCurve::NistP521 => 66,
    }
}

/// `scalar` as exactly `size` bytes, zero-padded on the left (some writers drop leading zeros), or
/// `None` if it is longer.
fn left_padded(scalar: &[u8], size: usize) -> Option<Zeroizing<Vec<u8>>> {
    let pad = size.checked_sub(scalar.len())?;
    let mut bytes = Zeroizing::new(vec![0u8; size]);
    bytes[pad..].copy_from_slice(scalar);
    Some(bytes)
}

fn ec_from_sec1(der: &[u8]) -> Result<PrivateKey, KeyFileError> {
    let sec1 = read_sec1(der)?;
    let load = |curve: EcdsaCurve| -> Result<Option<PrivateKey>, KeyFileError> {
        let Some(bytes) = left_padded(&sec1.scalar, scalar_size(curve)) else {
            return Ok(None);
        };
        ec_key(curve, |curve| match curve {
            EcdsaCurve::NistP256 => p256::SecretKey::from_slice(&bytes).map(Scalar::P256),
            EcdsaCurve::NistP384 => p384::SecretKey::from_slice(&bytes).map(Scalar::P384),
            EcdsaCurve::NistP521 => p521::SecretKey::from_slice(&bytes).map(Scalar::P521),
        })
        .map(Some)
    };
    if let Some(oid) = sec1.curve {
        return load(curve_of(oid)?)?
            .ok_or_else(|| malformed("the EC key is longer than its curve allows"));
    }
    // The curve's parameters are spelled out, so nothing names it. Try each supported curve and
    // believe the one whose public point for this scalar is the one in the file. A scalar of
    // another curve of the same size (secp256k1) matches none.
    for curve in [
        EcdsaCurve::NistP256,
        EcdsaCurve::NistP384,
        EcdsaCurve::NistP521,
    ] {
        if let Ok(Some(key)) = load(curve)
            && let Some(pair) = key.key_data().ecdsa()
            && sec1.public.as_deref() == Some(pair.public_key_bytes())
        {
            return Ok(key);
        }
    }
    Err(explicit_curve())
}

/// An EC secret scalar of one of the supported curves.
enum Scalar {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

/// Builds the `ssh-key` key for the curve from the secret `load` returns.
fn ec_key<E: std::fmt::Display>(
    curve: EcdsaCurve,
    load: impl FnOnce(EcdsaCurve) -> Result<Scalar, E>,
) -> Result<PrivateKey, KeyFileError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pair = match load(curve).map_err(malformed)? {
        Scalar::P256(secret) => EcdsaKeypair::NistP256 {
            public: secret.public_key().to_encoded_point(false),
            private: EcdsaPrivateKey::from(secret),
        },
        Scalar::P384(secret) => EcdsaKeypair::NistP384 {
            public: secret.public_key().to_encoded_point(false),
            private: EcdsaPrivateKey::from(secret),
        },
        Scalar::P521(secret) => EcdsaKeypair::NistP521 {
            public: secret.public_key().to_encoded_point(false),
            private: EcdsaPrivateKey::from(secret),
        },
    };
    PrivateKey::new(KeypairData::from(pair), "").map_err(malformed)
}

/// A PKCS#8 `PrivateKeyInfo`, whatever algorithm it holds.
fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, KeyFileError> {
    let info = PrivateKeyInfo::try_from(der).map_err(malformed)?;
    match info.algorithm.oid {
        RSA_ENCRYPTION => rsa_key(&rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(malformed)?),
        EC_PUBLIC_KEY => {
            let curve = curve_of(
                info.algorithm
                    .parameters_oid()
                    .map_err(|_| explicit_curve())?,
            )?;
            ec_key(curve, |curve| match curve {
                EcdsaCurve::NistP256 => p256::SecretKey::from_pkcs8_der(der).map(Scalar::P256),
                EcdsaCurve::NistP384 => p384::SecretKey::from_pkcs8_der(der).map(Scalar::P384),
                EcdsaCurve::NistP521 => p521::SecretKey::from_pkcs8_der(der).map(Scalar::P521),
            })
        }
        ED25519 => {
            let key = ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(malformed)?;
            PrivateKey::new(KeypairData::from(Ed25519Keypair::from(&key)), "").map_err(malformed)
        }
        DSA => Err(KeyFileError::Dsa),
        other => Err(KeyFileError::UnsupportedAlgorithm(format!(
            "The key algorithm {other} isn't supported"
        ))),
    }
}

/// The most memory an encrypted PKCS#8 key may ask scrypt for: `N = 2^20`, `r = 8` is 1 GiB, and
/// OpenSSL's own default is `N = 2^14`. Anything over this is refused rather than allocated.
const MAX_SCRYPT_COST: u64 = 1 << 20;
const MAX_SCRYPT_BLOCK_SIZE: u16 = 8;
const MAX_SCRYPT_PARALLELISM: u16 = 1;
/// Ten times OpenSSL's default of 600,000 for PBKDF2-HMAC-SHA256.
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// Refuses encryption parameters that would make the server spend more memory or time than any
/// real key needs. The parameters come from the uploaded file, so they are hostile input.
fn check_kdf_cost(info: &EncryptedPrivateKeyInfo<'_>) -> Result<(), KeyFileError> {
    let Some(params) = info.encryption_algorithm.pbes2() else {
        return Ok(());
    };
    if let Some(scrypt) = params.kdf.scrypt() {
        if scrypt.cost_parameter > MAX_SCRYPT_COST {
            return Err(KeyFileError::TooExpensive(
                "scrypt N is over 2^20".to_owned(),
            ));
        }
        if scrypt.block_size > MAX_SCRYPT_BLOCK_SIZE {
            return Err(KeyFileError::TooExpensive("scrypt r is over 8".to_owned()));
        }
        if scrypt.parallelization > MAX_SCRYPT_PARALLELISM {
            return Err(KeyFileError::TooExpensive("scrypt p is over 1".to_owned()));
        }
    }
    if let Some(pbkdf2) = params.kdf.pbkdf2()
        && pbkdf2.iteration_count > MAX_PBKDF2_ITERATIONS
    {
        return Err(KeyFileError::TooExpensive(
            "the PBKDF2 iteration count is over 10,000,000".to_owned(),
        ));
    }
    Ok(())
}

/// The PKCS#8 DER inside an `ENCRYPTED PRIVATE KEY` body.
fn decrypt_pkcs8(der: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let info = EncryptedPrivateKeyInfo::try_from(der).map_err(malformed)?;
    check_kdf_cost(&info)?;
    match info.decrypt(passphrase) {
        Ok(document) => Ok(Zeroizing::new(document.as_bytes().to_vec())),
        // `pkcs5` reports bad padding, the usual result of a wrong passphrase, as `EncryptFailed`.
        Err(pkcs8::Error::EncryptedPrivateKey(
            pkcs8::pkcs5::Error::DecryptFailed | pkcs8::pkcs5::Error::EncryptFailed,
        )) => Err(KeyFileError::WrongPassphrase),
        Err(pkcs8::Error::EncryptedPrivateKey(error)) => Err(KeyFileError::UnsupportedCipher(
            format!("an encryption scheme Doozers doesn't support ({error})"),
        )),
        Err(error) => Err(malformed(error)),
    }
}
