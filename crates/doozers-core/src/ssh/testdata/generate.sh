#!/bin/sh
# Regenerates the key fixtures the `ssh` tests read. They are checked in so the tests are
# deterministic and need neither ssh-keygen nor openssl; run this only to add a format.
# Needs ssh-keygen (OpenSSH 10) and openssl. Every encrypted key uses the passphrase below.
# These are throwaway keys: they protect nothing.
set -eu
cd "$(dirname "$0")"
PASS="correct horse battery"

# `name`: OpenSSH format, plain and encrypted.
openssh() { # type bits name
    rm -f "$3" "$3.pub" "$3-encrypted" "$3-encrypted.pub"
    if [ -n "$2" ]; then bits="-b $2"; else bits=""; fi
    ssh-keygen -q -t "$1" $bits -N "" -C "$3@fixture" -f "$3"
    ssh-keygen -q -t "$1" $bits -N "$PASS" -C "$3@fixture" -f "$3-encrypted"
}
# Traditional PEM (PKCS#1 for RSA, SEC1 for EC): plain, and the legacy OpenSSL encryption.
pem() { # openssh-name pem-name
    cp "$1" "$2"
    cp "$1-encrypted" "$2-encrypted"
    ssh-keygen -q -p -m PEM -N "" -P "" -f "$2" >/dev/null
    ssh-keygen -q -p -m PEM -N "$PASS" -P "$PASS" -f "$2-encrypted" >/dev/null
    rm -f "$2.pub" "$2-encrypted.pub"
}
# PKCS#8: plain, and `ENCRYPTED PRIVATE KEY` (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC). An EC key
# goes through `openssl ec -param_enc named_curve` first: the SEC1 files above are LibreSSL's
# `ssh-keygen -m PEM` output, which spells out the curve's parameters instead of naming it.
pkcs8() { # pem-file out-name
    source="$1"
    case "$1" in
    ec-*)
        openssl ec -in "$1" -param_enc named_curve -out "$1.named.tmp" 2>/dev/null
        source="$1.named.tmp"
        ;;
    esac
    openssl pkcs8 -topk8 -nocrypt -in "$source" -out "$2.pem"
    openssl pkcs8 -topk8 -v2 aes-256-cbc -passout "pass:$PASS" -in "$source" -out "$2-encrypted.pem"
    rm -f "$1.named.tmp"
}

openssh ed25519 "" ed25519
openssh rsa 2048 rsa
openssh ecdsa 256 ecdsa-p256
openssh ecdsa 384 ecdsa-p384
openssh ecdsa 521 ecdsa-p521

pem rsa rsa-pkcs1
pem ecdsa-p256 ec-p256-sec1
pem ecdsa-p384 ec-p384-sec1
pem ecdsa-p521 ec-p521-sec1

# ssh-keygen can't write Ed25519 as PKCS#8 here, so this one is a fresh key made by openssl, with
# its public half written in OpenSSH form by hand: the blob is the string "ssh-ed25519" and the 32
# raw bytes of the public key, each with a 4-byte length.
openssl genpkey -algorithm ed25519 -out ed25519-pkcs8-plain.tmp
openssl pkcs8 -topk8 -nocrypt -in ed25519-pkcs8-plain.tmp -out ed25519-pkcs8.pem
openssl pkcs8 -topk8 -v2 aes-256-cbc -passout "pass:$PASS" -in ed25519-pkcs8-plain.tmp \
    -out ed25519-pkcs8-encrypted.pem
openssl pkcs8 -topk8 -scrypt -passout "pass:$PASS" -in ed25519-pkcs8-plain.tmp \
    -out ed25519-pkcs8-scrypt.pem
openssl pkey -in ed25519-pkcs8-plain.tmp -pubout -outform DER > ed25519-pkcs8.pub.tmp
echo "ssh-ed25519 $({ printf '\0\0\0\vssh-ed25519\0\0\0 '; tail -c 32 ed25519-pkcs8.pub.tmp; } | base64 | tr -d '\n') ed25519-pkcs8@fixture" > ed25519-pkcs8.pub
rm -f ed25519-pkcs8-plain.tmp ed25519-pkcs8.pub.tmp

pkcs8 rsa-pkcs1 rsa-pkcs8
pkcs8 ec-p256-sec1 ec-p256-pkcs8
pkcs8 ec-p384-sec1 ec-p384-pkcs8
pkcs8 ec-p521-sec1 ec-p521-pkcs8

# SEC1 as OpenSSL writes it: the curve named, not spelled out. Plain, and legacy-encrypted.
for curve in p256 p384 p521; do
    openssl ec -in "ec-$curve-sec1" -param_enc named_curve -out "ec-$curve-sec1-named" 2>/dev/null
    openssl ec -in "ec-$curve-sec1" -param_enc named_curve -aes128 -passout "pass:$PASS" \
        -out "ec-$curve-sec1-named-encrypted" 2>/dev/null
done

# Legacy encryption with the other two AES key sizes, which `ssh-keygen -m PEM` doesn't write.
openssl rsa -in rsa-pkcs1 -traditional -aes192 -passout "pass:$PASS" -out rsa-pkcs1-aes192 2>/dev/null
openssl rsa -in rsa-pkcs1 -traditional -aes256 -passout "pass:$PASS" -out rsa-pkcs1-aes256 2>/dev/null
openssl ec -in ec-p256-sec1 -aes256 -passout "pass:$PASS" -out ec-p256-sec1-aes256 2>/dev/null

# Keys of kinds Doozers refuses.
openssl genpkey -algorithm ED448 -out ed448-pkcs8.pem
openssl ecparam -name secp256k1 -genkey -noout -out ec-secp256k1-sec1
# The same kind of key with its curve spelled out, as LibreSSL writes keys: a 32-byte scalar that
# must not be taken for a P-256 one.
openssl ecparam -name secp256k1 -genkey -noout -param_enc explicit -out ec-secp256k1-explicit-sec1
openssl dsaparam -genkey -noout 2048 2>/dev/null | openssl dsa -out dsa-traditional 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in dsa-traditional -out dsa-pkcs8.pem

# An OpenSSH-format DSA key: ssh-keygen 10 can't make one, so this is encoded by hand. Its numbers
# are made up (it is not a working DSA key); the tests only need the format recognized as DSA.
python3 - <<'PY'
import base64, struct
s = lambda b: struct.pack(">I", len(b)) + b
mp = lambda n: s(n.to_bytes((n.bit_length() + 8) // 8, "big"))
p, q, g, y, x = 0xF1 << 120 | 1, 0xA7 << 56 | 3, 2, 0x1234567, 0x4321
blob = s(b"ssh-dss") + mp(p) + mp(q) + mp(g) + mp(y)
private = struct.pack(">II", 7, 7) + s(b"ssh-dss") + mp(p) + mp(q) + mp(g) + mp(y) + mp(x) + s(b"fixture")
private += bytes(range(1, 8 - len(private) % 8 + 1)) if len(private) % 8 else b""
body = b"openssh-key-v1\0" + s(b"none") + s(b"none") + s(b"") + struct.pack(">I", 1) + s(blob) + s(private)
b64 = base64.b64encode(body).decode()
lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
open("dsa-openssh", "w").write("\n".join(["-----BEGIN OPENSSH PRIVATE KEY-----"] + lines + ["-----END OPENSSH PRIVATE KEY-----"]) + "\n")
PY

# Hostile encryption settings: files whose key-derivation cost would exhaust the server. None of them
# is ever decrypted, so the ciphertext is filler. The OpenSSH one is `ed25519-encrypted` with its
# bcrypt rounds raised to 4294967295; the PKCS#8 ones are encoded by hand, since openssl won't
# write settings this absurd.
python3 - <<'PY'
import base64, struct

def pem(label, body, width=64):
    b64 = base64.b64encode(body).decode()
    lines = [b64[i:i + width] for i in range(0, len(b64), width)]
    return "\n".join(["-----BEGIN %s-----" % label] + lines + ["-----END %s-----" % label]) + "\n"

# OpenSSH: cipher, kdf name, then the kdf options string (salt string + uint32 rounds).
text = open("ed25519-encrypted").read().split("\n")
body = base64.b64decode("".join(l for l in text if l and not l.startswith("-----")))
head = b"openssh-key-v1\0"
assert body.startswith(head)
pos = len(head)
for _ in range(2):  # cipher, kdf
    (n,) = struct.unpack_from(">I", body, pos)
    pos += 4 + n
(options_len,) = struct.unpack_from(">I", body, pos)
options_end = pos + 4 + options_len
rounds_at = options_end - 4
assert struct.unpack_from(">I", body, rounds_at)[0] < 1024
body = body[:rounds_at] + struct.pack(">I", 0xFFFFFFFF) + body[options_end:]
open("ed25519-bcrypt-rounds", "w").write(pem("OPENSSH PRIVATE KEY", body, 70))

# PKCS#8: EncryptedPrivateKeyInfo with PBES2 parameters.
def tlv(tag, content):
    n = len(content)
    if n < 128:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content

def integer(n):
    return tlv(2, n.to_bytes(n.bit_length() // 8 + 1, "big"))

def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(chunk)
    return tlv(6, out)

def seq(*items):
    return tlv(0x30, b"".join(items))

def encrypted(kdf):
    scheme = seq(oid("2.16.840.1.101.3.4.1.42"), tlv(4, bytes(16)))
    params = seq(kdf, scheme)
    algorithm = seq(oid("1.2.840.113549.1.5.13"), params)
    return seq(algorithm, tlv(4, bytes(48)))

def scrypt(n, r, p):
    return seq(oid("1.3.6.1.4.1.11591.4.11"), seq(tlv(4, bytes(16)), integer(n), integer(r), integer(p)))

def pbkdf2(iterations):
    prf = seq(oid("1.2.840.113549.2.9"), tlv(5, b""))
    return seq(oid("1.2.840.113549.1.5.12"), seq(tlv(4, bytes(16)), integer(iterations), prf))

for name, kdf in {
    "pkcs8-scrypt-n.pem": scrypt(1 << 40, 3, 1),
    "pkcs8-scrypt-r.pem": scrypt(1 << 14, 16, 1),
    "pkcs8-scrypt-p.pem": scrypt(1 << 14, 8, 2),
    "pkcs8-pbkdf2-iterations.pem": pbkdf2(99_999_999),
}.items():
    open(name, "w").write(pem("ENCRYPTED PRIVATE KEY", encrypted(kdf)))
PY

# A PuTTY key file is refused by its first line alone; this is the start of a real one.
cat > putty.ppk <<'PPK'
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: fixture
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ0hM3tYtYQWm1JpqaLnPFd1GeGOOk0Y7AtRqqCr
ZwnT
Private-Lines: 1
AAAAIOQ0hZ0vEJ0Dj2q0wYQfkQ8f6V3yU3uZpN7q7pGSqjvf
Private-MAC: 0000000000000000000000000000000000000000000000000000000000000000
PPK
