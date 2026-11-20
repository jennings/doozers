//! Key exchange: the `KEXINIT` the scan sends, reading the server's, the exchange hash of
//! `curve25519-sha256` (RFC 8731 section 3.1, built on RFC 5656 section 4), and checking the host
//! key's signature over it.

use sha2::{Digest as _, Sha256};
use signature::Verifier as _;
use ssh_key::{PublicKey, Signature};

use super::ScanError;
use super::excerpt;
use super::wire::{Reader, put_mpint, put_name_list, put_string};

pub(super) const MSG_DISCONNECT: u8 = 1;
pub(super) const MSG_IGNORE: u8 = 2;
pub(super) const MSG_UNIMPLEMENTED: u8 = 3;
pub(super) const MSG_DEBUG: u8 = 4;
pub(super) const MSG_KEXINIT: u8 = 20;
pub(super) const MSG_KEX_ECDH_INIT: u8 = 30;
pub(super) const MSG_KEX_ECDH_REPLY: u8 = 31;

/// `SSH_DISCONNECT_BY_APPLICATION`.
pub(super) const DISCONNECT_BY_APPLICATION: u32 = 11;

/// The key exchange methods offered, in order. Both compute the same thing.
const KEX_ALGORITHMS: [&str; 2] = ["curve25519-sha256", "curve25519-sha256@libssh.org"];

/// The algorithms a server needs to share with us for the exchange to reach its reply. We never
/// get as far as using them, but a server picks its algorithms before it answers and drops a
/// client that shares none.
const CIPHERS: [&str; 6] = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
];
const MACS: [&str; 5] = [
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
];
const COMPRESSION: [&str; 1] = ["none"];

/// The host key type being scanned and the algorithms to offer for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HostKeyKind {
    /// The name of the key's type in `known_hosts` and in the key blob.
    pub(super) key_type: &'static str,
    /// The host key algorithms to offer, most preferred first. For RSA these are the SHA-2
    /// signature algorithms, never `ssh-rsa` (SHA-1).
    pub(super) algorithms: &'static [&'static str],
}

const KINDS: [HostKeyKind; 5] = [
    HostKeyKind {
        key_type: "ssh-ed25519",
        algorithms: &["ssh-ed25519"],
    },
    HostKeyKind {
        key_type: "ecdsa-sha2-nistp256",
        algorithms: &["ecdsa-sha2-nistp256"],
    },
    HostKeyKind {
        key_type: "ecdsa-sha2-nistp384",
        algorithms: &["ecdsa-sha2-nistp384"],
    },
    HostKeyKind {
        key_type: "ecdsa-sha2-nistp521",
        algorithms: &["ecdsa-sha2-nistp521"],
    },
    HostKeyKind {
        key_type: "ssh-rsa",
        algorithms: &["rsa-sha2-512", "rsa-sha2-256"],
    },
];

impl HostKeyKind {
    /// The kind for the key type OpenSSH's `%t` expands to, or `None` for anything else:
    /// certificates, `sk-` keys, DSA, and unknown names.
    pub(super) fn from_key_type(key_type: &str) -> Option<Self> {
        KINDS.iter().find(|kind| kind.key_type == key_type).copied()
    }
}

/// What the scan needs from the server's `KEXINIT`.
#[derive(Debug)]
pub(super) struct ServerKexInit<'a> {
    kex_algorithms: Vec<&'a [u8]>,
    host_key_algorithms: Vec<&'a [u8]>,
    first_kex_packet_follows: bool,
}

/// The algorithms both sides agreed on.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Negotiated {
    /// Whether the server's first-choice algorithms differ from our first choices, which makes a
    /// key exchange packet it sent with its `KEXINIT` (RFC 4253 section 7) a wrong guess to skip.
    pub(super) skip_guessed_packet: bool,
}

/// Builds our `KEXINIT` payload (the `I_C` of the exchange hash).
pub(super) fn build_kexinit(kind: &HostKeyKind) -> Vec<u8> {
    let mut cookie = [0_u8; 16];
    // The cookie only has to be unpredictable to a network attacker; a failed random source
    // leaves zeros that the exchange survives.
    let _ = aws_lc_rs::rand::fill(&mut cookie);
    let mut out = vec![MSG_KEXINIT];
    out.extend_from_slice(&cookie);
    put_name_list(&mut out, &KEX_ALGORITHMS);
    put_name_list(&mut out, kind.algorithms);
    put_name_list(&mut out, &CIPHERS);
    put_name_list(&mut out, &CIPHERS);
    put_name_list(&mut out, &MACS);
    put_name_list(&mut out, &MACS);
    put_name_list(&mut out, &COMPRESSION);
    put_name_list(&mut out, &COMPRESSION);
    put_name_list(&mut out, &[]);
    put_name_list(&mut out, &[]);
    out.push(0); // first_kex_packet_follows
    out.extend_from_slice(&[0; 4]); // reserved
    out
}

/// Parses the server's `KEXINIT` payload.
pub(super) fn parse_kexinit(payload: &[u8]) -> Result<ServerKexInit<'_>, ScanError> {
    let malformed = || ScanError::Kex("the server's KEXINIT is malformed".into());
    let mut reader = Reader::new(payload);
    if reader.u8() != Some(MSG_KEXINIT) {
        return Err(malformed());
    }
    reader.bytes(16).ok_or_else(malformed)?;
    let kex_algorithms = reader.name_list().ok_or_else(malformed)?;
    let host_key_algorithms = reader.name_list().ok_or_else(malformed)?;
    // The ciphers, MACs, compression, and languages, in both directions.
    for _ in 0..8 {
        reader.string().ok_or_else(malformed)?;
    }
    let first_kex_packet_follows = reader.u8().ok_or_else(malformed)? != 0;
    Ok(ServerKexInit {
        kex_algorithms,
        host_key_algorithms,
        first_kex_packet_follows,
    })
}

/// Picks the algorithms the way RFC 4253 section 7.1 does (the first on the client's list that
/// the server also lists), or fails naming what the server offers.
pub(super) fn negotiate(
    server: &ServerKexInit<'_>,
    kind: &HostKeyKind,
) -> Result<Negotiated, ScanError> {
    if !KEX_ALGORITHMS
        .iter()
        .any(|ours| server.kex_algorithms.contains(&ours.as_bytes()))
    {
        return Err(ScanError::NoCommonAlgorithm(format!(
            "the server offers no key exchange method of {} (it offers {})",
            KEX_ALGORITHMS.join(", "),
            excerpt_list(&server.kex_algorithms),
        )));
    }
    if !kind
        .algorithms
        .iter()
        .any(|ours| server.host_key_algorithms.contains(&ours.as_bytes()))
    {
        return Err(ScanError::NoCommonAlgorithm(format!(
            "the server has no {} host key: it offers no host key algorithm of {} (it offers {})",
            kind.key_type,
            kind.algorithms.join(", "),
            excerpt_list(&server.host_key_algorithms),
        )));
    }
    let guessed_right = server.kex_algorithms.first() == Some(&KEX_ALGORITHMS[0].as_bytes())
        && server.host_key_algorithms.first()
            == kind
                .algorithms
                .first()
                .map(|algorithm| algorithm.as_bytes())
                .as_ref();
    let skip_guessed_packet = server.first_kex_packet_follows && !guessed_right;
    Ok(Negotiated {
        skip_guessed_packet,
    })
}

/// A short, sanitized rendering of a server's list of names.
fn excerpt_list(names: &[&[u8]]) -> String {
    let joined: Vec<u8> = names.join(&b',');
    excerpt(&joined)
}

/// What a `KEX_ECDH_REPLY` carries.
#[derive(Debug)]
pub(super) struct EcdhReply<'a> {
    /// `K_S`, the host key blob.
    pub(super) host_key: &'a [u8],
    /// `Q_S`, the server's ephemeral public key.
    pub(super) server_public: &'a [u8],
    /// The host key's signature over the exchange hash, in the SSH wire form.
    pub(super) signature: &'a [u8],
}

/// Parses a `KEX_ECDH_REPLY` payload.
pub(super) fn parse_ecdh_reply(payload: &[u8]) -> Result<EcdhReply<'_>, ScanError> {
    let malformed = || ScanError::Kex("the server's KEX_ECDH_REPLY is malformed".into());
    let mut reader = Reader::new(payload);
    if reader.u8() != Some(MSG_KEX_ECDH_REPLY) {
        return Err(malformed());
    }
    let host_key = reader.string().ok_or_else(malformed)?;
    let server_public = reader.string().ok_or_else(malformed)?;
    let signature = reader.string().ok_or_else(malformed)?;
    Ok(EcdhReply {
        host_key,
        server_public,
        signature,
    })
}

/// What the exchange hash covers.
pub(super) struct ExchangeInputs<'a> {
    /// `V_C`, our identification string without its line ending.
    pub(super) client_version: &'a [u8],
    /// `V_S`, the server's.
    pub(super) server_version: &'a [u8],
    /// `I_C`, our `KEXINIT` payload.
    pub(super) client_kexinit: &'a [u8],
    /// `I_S`, the server's.
    pub(super) server_kexinit: &'a [u8],
    /// `K_S`, the host key blob.
    pub(super) host_key: &'a [u8],
    /// `Q_C`, our ephemeral public key.
    pub(super) client_public: &'a [u8],
    /// `Q_S`, the server's.
    pub(super) server_public: &'a [u8],
    /// `K`, the raw 32 bytes X25519 produced.
    pub(super) shared_secret: &'a [u8],
}

/// The exchange hash `H` of `curve25519-sha256`: SHA-256 over `V_C`, `V_S`, `I_C`, `I_S`, `K_S`,
/// `Q_C`, `Q_S`, each as a `string`, and the shared secret `K` as an `mpint`.
///
/// The shared secret is the 32 bytes X25519 outputs. SSH reads them as a big-endian number (RFC
/// 8731 section 3.1; OpenSSH does the same), not as the little-endian one RFC 7748 describes.
pub(super) fn exchange_hash(inputs: &ExchangeInputs<'_>) -> [u8; 32] {
    let mut data = Vec::new();
    put_string(&mut data, inputs.client_version);
    put_string(&mut data, inputs.server_version);
    put_string(&mut data, inputs.client_kexinit);
    put_string(&mut data, inputs.server_kexinit);
    put_string(&mut data, inputs.host_key);
    put_string(&mut data, inputs.client_public);
    put_string(&mut data, inputs.server_public);
    put_mpint(&mut data, inputs.shared_secret);
    Sha256::digest(&data).into()
}

/// Checks that `host_key` is a key of `kind` and that `signature` is its signature over `hash`.
pub(super) fn verify_host_key(
    kind: &HostKeyKind,
    host_key: &[u8],
    signature: &[u8],
    hash: &[u8; 32],
) -> Result<(), ScanError> {
    let key = PublicKey::from_bytes(host_key).map_err(|e| {
        ScanError::HostKey(format!(
            "the host key can't be parsed or isn't supported ({e})"
        ))
    })?;
    if key.algorithm().as_str() != kind.key_type {
        return Err(ScanError::HostKey(format!(
            "the server presented a {} key where a {} key was asked for",
            excerpt(key.algorithm().as_str().as_bytes()),
            kind.key_type,
        )));
    }
    let signature = Signature::try_from(signature).map_err(|e| {
        ScanError::BadSignature(format!(
            "the signature can't be parsed or isn't supported ({e})"
        ))
    })?;
    let algorithm = signature.algorithm();
    if !kind.algorithms.contains(&algorithm.as_str()) {
        return Err(ScanError::BadSignature(format!(
            "the signature uses {}, which wasn't offered for a {} key",
            excerpt(algorithm.as_str().as_bytes()),
            kind.key_type,
        )));
    }
    key.key_data().verify(hash, &signature).map_err(|_| {
        ScanError::BadSignature("the signature doesn't match the exchange hash".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    /// Inputs and expected hashes computed with an independent implementation (Python's `hashlib`
    /// over hand-packed `string`s and `mpint`s).
    fn vector(shared_secret: &[u8]) -> [u8; 32] {
        let client_kexinit: Vec<u8> = [
            &[20_u8][..],
            &(0..16).collect::<Vec<u8>>(),
            b"client-kexinit",
        ]
        .concat();
        let server_kexinit: Vec<u8> = [
            &[20_u8][..],
            &(16..32).collect::<Vec<u8>>(),
            b"server-kexinit",
        ]
        .concat();
        let client_public: Vec<u8> = (0..32).collect();
        let server_public: Vec<u8> = (100..132).collect();
        exchange_hash(&ExchangeInputs {
            client_version: b"SSH-2.0-DoozersScan",
            server_version: b"SSH-2.0-OpenSSH_9.9",
            client_kexinit: &client_kexinit,
            server_kexinit: &server_kexinit,
            host_key: b"host-key-blob",
            client_public: &client_public,
            server_public: &server_public,
            shared_secret,
        })
    }

    #[test]
    fn exchange_hash_matches_the_reference_when_the_secret_needs_a_zero_pad() {
        let secret: Vec<u8> = (0x80..0xa0).collect();
        assert_eq!(
            hex(&vector(&secret)),
            "50a751fac8fdd2f80b014b84070d8cca961e69f624543fd0cb74b688fd43cbe5"
        );
    }

    #[test]
    fn exchange_hash_matches_the_reference_when_the_secret_has_leading_zeros() {
        let mut secret = vec![0, 0];
        secret.extend(1..31);
        assert_eq!(
            hex(&vector(&secret)),
            "a41c04e9afb5f370a3a869e8f754f5a81e88b923dabd0b4e0c6ffe3a37fa2234"
        );
    }

    #[test]
    fn kexinit_offers_only_curve25519_and_the_requested_host_keys() {
        let rsa = HostKeyKind::from_key_type("ssh-rsa").expect("rsa is supported");
        let payload = build_kexinit(&rsa);
        let parsed = parse_kexinit(&payload).expect("our own KEXINIT parses");
        assert_eq!(
            parsed.kex_algorithms,
            [&b"curve25519-sha256"[..], b"curve25519-sha256@libssh.org"]
        );
        assert_eq!(
            parsed.host_key_algorithms,
            [&b"rsa-sha2-512"[..], b"rsa-sha2-256"]
        );
        assert!(!parsed.first_kex_packet_follows);
    }

    #[test]
    fn only_plain_host_key_types_are_accepted() {
        for key_type in [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-rsa",
        ] {
            assert_eq!(
                HostKeyKind::from_key_type(key_type).map(|k| k.key_type),
                Some(key_type)
            );
        }
        for key_type in [
            "ssh-ed25519-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "ssh-dss",
            "rsa-sha2-256",
            "NONE",
            "",
        ] {
            assert_eq!(HostKeyKind::from_key_type(key_type), None, "{key_type}");
        }
    }

    #[test]
    fn negotiation_names_what_the_server_offers_when_nothing_matches() {
        let kind = HostKeyKind::from_key_type("ssh-ed25519").expect("supported");
        let mut payload = vec![MSG_KEXINIT];
        payload.extend_from_slice(&[0; 16]);
        put_name_list(&mut payload, &["diffie-hellman-group14-sha256"]);
        put_name_list(&mut payload, &["ssh-ed25519"]);
        for _ in 0..8 {
            put_name_list(&mut payload, &[]);
        }
        payload.extend_from_slice(&[0; 5]);
        let server = parse_kexinit(&payload).expect("parses");
        let error = negotiate(&server, &kind).expect_err("no common key exchange");
        assert!(matches!(error, ScanError::NoCommonAlgorithm(_)));
        assert!(
            error.to_string().contains("diffie-hellman-group14-sha256"),
            "{error}"
        );
    }
}
