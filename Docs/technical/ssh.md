# SSH keys

Code: `crates/doozers-core/src/ssh/` (`doozers_core::ssh`), the rows in `doozers-store`
([Storage](storage.md#ssh-keys)), and the pages in `channels/web/ssh_keys.rs`
([Web channel](web-channel.md#ssh-keys-pages)). Design: the decisions on
[#135 SSH agent relay for environment workspaces](https://github.com/jennings/doozers/issues/135)
and [#136 Per-user SSH keys](https://github.com/jennings/doozers/issues/136).

Each user keeps SSH keys in Doozers. The private keys never leave the core: no page, command, or RPC
returns one. This page covers how the keys are stored, generated, read from uploads, and protected.
The [user page](../user/ssh.md) is the guide.

## Storage

A key is a row of `ssh_keys` and a secret.

- **The row** holds the metadata: `id`, `user_id`, `label`, `algorithm`, `public_key`,
  `fingerprint`, `created_at`, and `last_used_at`. `algorithm` is the SSH name of the public key
  (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, or
  `ecdsa-sha2-nistp521`). `public_key` is `<algorithm> <base64>` and `fingerprint` is the
  `SHA256:...` form that `ssh-keygen -l` prints. `last_used_at` is null until the key first signs.
- **The secret** is at `users/<user>/ssh-keys/<id>`, in the [secret store](secret-store.md). Its
  value is the private key as unencrypted OpenSSH PEM text with an empty comment. The secret store
  seals it like every other value, so the data key and its key file are the only protection that
  matters, and an uploaded key's own passphrase isn't kept.

`ssh_keys` is the only writer of `users/<user>/ssh-keys/`, which follows the secret store's rule
that a feature owns its paths. The `id` is `AUTOINCREMENT`, so an id is never reused and a new key
never meets the sealed value of an old one.

A user can't hold the same key twice (`UNIQUE (user_id, fingerprint)`), but several users can. Each
upload is its own row and its own secret.

**Order of writes.** Adding a key inserts the row first, so its id names the secret, then writes the
secret. If the secret can't be written, the row is deleted again. Deleting a key deletes the row,
then the secret. A secret that can't be deleted is logged at `warn` and the delete still succeeds: a
sealed value nothing refers to is harmless, while a row without a secret would be a key that is
listed and can't sign.

**Backups.** [Backups](backups.md) include the table, since they take `doozers.db` whole, and the
private keys are in them only as the secret store's ciphertext. Restoring them needs the same
`secret.key`.

## Generating keys

`ssh::KeyType` lists what Doozers generates: Ed25519 (the default), RSA with 3072 or 4096 bits, and
ECDSA on P-256, P-384, or P-521. Keys come from the operating system's randomness through the
`ssh-key` crate. RSA generation takes seconds, so the service runs it with `spawn_blocking`. The
debug profile optimizes the RSA crates (`Cargo.toml`), or the tests would take minutes.

DSA and FIDO security keys are not supported. OpenSSH 10.0 removed DSA, and a security key's private
half stays on hardware Doozers doesn't have.

## Reading uploads

`ssh::formats::parse_private_key` turns the text of an upload into an unencrypted
`ssh_key::PrivateKey`, or a `KeyFileError` whose message says what to do. It reads at most 64 KiB.
It turns a browser's CRLF line breaks into LF and ignores whitespace around the key.

| Format | Header | Read by |
| ------ | ------ | ------- |
| OpenSSH, plain or encrypted (bcrypt-pbkdf with any of `ssh-key`'s ciphers) | `OPENSSH PRIVATE KEY` | `ssh-key` |
| PKCS#1 RSA | `RSA PRIVATE KEY` | `rsa` |
| SEC1 EC | `EC PRIVATE KEY` | the structure by hand, then `p256`, `p384`, or `p521` |
| PKCS#8, plain | `PRIVATE KEY` | `pkcs8`, then `rsa`, `p256`/`p384`/`p521`, or `ed25519-dalek` |
| PKCS#8, encrypted | `ENCRYPTED PRIVATE KEY` | `pkcs8` with PBES2: PBKDF2 (SHA-1 or SHA-2) or scrypt, with AES-CBC |
| Legacy OpenSSL encryption of PKCS#1 and SEC1 | `Proc-Type: 4,ENCRYPTED` | `ssh::formats` |

The legacy encryption is what `ssh-keygen -m PEM -N <passphrase>` writes. The key is OpenSSL's
`EVP_BytesToKey` with MD5, one iteration, and the first 8 bytes of the IV as the salt. Doozers
supports `AES-128-CBC`, `AES-192-CBC`, and `AES-256-CBC`, and refuses any other `DEK-Info` cipher
with a message that says to convert the key with `ssh-keygen -p -f <file>`.

- **SEC1 and explicit parameters.** LibreSSL's `ssh-keygen -m PEM`, the one on macOS, writes the
  curve's full parameters where OpenSSL writes its name, and the `sec1` crate can't read that. So
  `ssh::formats` reads the key's scalar and its named curve itself. For a key without a name, the
  scalar's size picks the curve, and the key is accepted only if its public point is the one that
  scalar gives on that curve. A scalar from another 32-byte curve, such as secp256k1, would not
  match.
- **Passphrases.** A passphrase given for an unencrypted key is ignored. An encrypted key without
  one is refused and the message asks for it. A wrong passphrase is refused with "the passphrase is
  wrong". Decrypting with a wrong key sometimes gets past the padding check, so garbage that then
  fails to parse in an encrypted upload also reads as a wrong passphrase.
- **Key-derivation cost.** The encryption settings come from the uploaded file, so they are capped
  before anything is derived. An encrypted PKCS#8 key is refused if its scrypt settings have `N`
  over 2^20, `r` over 8, or `p` over 1, or its PBKDF2 iteration count is over 10,000,000. An OpenSSH
  key is refused if its bcrypt-pbkdf `rounds` is over 1024 (`ssh-keygen -a` defaults to 16). The
  message says to re-encrypt the key with `ssh-keygen -p -f <file>`. `SshKeys::upload` also parses
  on a blocking thread, as `generate` does, because decrypting is slow on purpose.
- **Refused.** PuTTY files (`PuTTY-User-Key-File-`) with the
  `puttygen key.ppk -O private-openssh -o key` command, DSA keys (in any format), `sk-*` keys,
  public keys, and any other algorithm or curve (Ed448, secp256k1) with the list of what is
  supported.

## Permissions

`SshKeys` is the service. It is held by `Runtime::ssh_keys` over the `Store`, the
`Arc<dyn SecretProvider>`, and the clock. Every call takes the user who acts.

| Call | Who |
| ---- | --- |
| `list`, `get`, `generate`, `upload`, `rename`, `delete` | The acting user, on their own keys only. A key of someone else's is `NotFound`, the same as a key that doesn't exist. |
| `all_keys`, `any_key`, `delete_any` | The owner only (`SshKeys::may_administer`, which is the web `may_administer`). Anyone else gets `Forbidden`. |

The owner can see any user's key details and delete a key. The owner can't use another user's key:
`private_key` takes the user whose key it is, and the owner is only that for their own.

No call returns a private key. The signing path, which is inside the core, is the only reader:

| Call | Use |
| ---- | --- |
| `agent_keys(user)` | `user`'s keys in the order an ssh-agent offers them: most recently used first, never-used keys last and newest first. |
| `private_key(user, id)` | The decrypted `ssh_key::PrivateKey` of one of `user`'s keys, read from the secret store. `NotFound` for a key that isn't `user`'s. |
| `touch_used(id, now)` | Sets `last_used_at`. |
| `ssh::keys::sign(key, rsa_hash, data)` | The SSH signature of `data`: `ssh-ed25519` or `ecdsa-sha2-*` by `ssh-key`, and `rsa-sha2-256` or `rsa-sha2-512` for RSA. Never SHA-1. |

`ssh-key` 0.6.7 can't sign with an RSA key: it builds the `rsa` key from the prime `p` twice. So
`ssh::keys::rsa_private_key` rebuilds the key with `p` and `q`, and `sign` uses it with
`rsa::pkcs1v15::SigningKey`.

## Labels

A label is 1 to 100 characters after trimming, with no control characters. Labels needn't be unique.
A generated key's default label is `<user>@doozers`. An uploaded key's is its comment if it has one
that is a valid label, else `<user>@doozers`.

## Tests

`crates/doozers-core/src/ssh/tests.rs` covers the service and every format, and
`channels/web/tests/ssh_keys.rs` the pages. The upload fixtures are in
`crates/doozers-core/src/ssh/testdata/`, checked in so the tests are deterministic.
`testdata/generate.sh` says how they were made with `ssh-keygen` and `openssl`.

The tests that compare against OpenSSH run `ssh-keygen -l` for each generated type's fingerprint and
`ssh-keygen -Y verify` for a signature made with a key read back from the secret store. They print
why they stop when `ssh-keygen` isn't installed.
