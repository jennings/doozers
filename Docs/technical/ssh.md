# SSH keys and the agent relay

Code: `crates/doozers-core/src/ssh/` (`doozers_core::ssh`), the rows in `doozers-store`
([Storage](storage.md#ssh-keys)), and the pages in `channels/web/ssh_keys.rs`
([Web channel](web-channel.md#ssh-keys-pages)). Design: the decisions on
[#135 SSH agent relay for environment workspaces](https://github.com/jennings/doozers/issues/135),
[#136 Per-user SSH keys](https://github.com/jennings/doozers/issues/136), and
[#137 ssh-agent relay](https://github.com/jennings/doozers/issues/137).

Each user keeps SSH keys in Doozers. The private keys never leave the core: no page, command, or RPC
returns one. This page covers how the keys are stored, generated, read from uploads, and protected,
and how a workspace's `ssh` and `git` use them through a relay without ever holding one. The
[user page](../user/ssh.md) is the guide.

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

## How a workspace gets its keys

A workspace gets the keys of exactly one user, its **key user**, or none. The core decides when it
creates the workspace and stores the answer in `workspaces.key_user`
([Storage](storage.md#workspaces)). `workspaces::key_user(session, requester)` is the one place that
decides, from the creating turn's `Session` and the call's requester:

| Session | Key user |
| ------- | -------- |
| Direct conversation (a DM, or a user's web chat) | The session's user |
| Isolated job run | The requester: the creator of a runtime job. A config job has none, so no key user |
| Group conversation | None |

Several users' keys can't be kept apart in one workspace. Every command can connect to the agent
socket, and an SSH connection opened in one user's turn, such as a `ControlMaster`, stays usable in
another's. A group workspace therefore gets no keys, which matches per-user MCP toolsets.

A workspace keeps its key user for its life. `recreate` and `/env reset` pass the record's on to the
new workspace, while the model's own `environment_reset` creates the new workspace from the current
turn like `environment_create` does. Migration `0013` filled `key_user` for existing conversation
rows from the newest `direct` session of their key and left job rows without one.

## The agent relay

An environment plugin that reports the `ssh_relay` capability puts an ssh-agent socket in each
workspace. The socket is `SSH_AUTH_SOCK`, and nothing it carries includes a private key: requests go
to the core, which signs. [Environment workspaces](environments.md#the-ssh-agent-relay) says when
the core opens and ends a relay.

**The stream.** `EnvironmentService.Relay` is a bidirectional stream in `doozers.environment.v1`.
The core's first message is `RelayOpen` with the workspace id. After that the plugin sends
`RelayRequest`s, each an `AgentRequest` (connection number and one agent message without its length
prefix) or an `AgentClosed`, and the core answers each request with an `AgentReply` for the same
connection. Ending either side ends the relay, and the core opens another on the workspace's next
use. [Protocols](protocols.md) lists the messages, and the same stream carries known-hosts lookups
later.

**In the workspace.** The `ssh-agent` subcommand of the workspace helper listens on
`/.doozers/run/ssh-agent.sock` and multiplexes every client connection over its standard input and
output as frames of `u32 length | u8 kind | u64 connection | payload`.
[The Docker plugin's page](environment-docker.md#the-ssh-agent-relay) has the format, and the plugin
runs the helper as a long exec.

**In the core.** `ssh::relay::Relays` keeps one task per workspace. Each task holds an `ssh::Agent`
for the workspace: its key user and the state of its clients' connections. The agent answers one
message at a time, so one workspace's requests are handled in order, and a client waiting on the
core's answer is how the agent protocol works anyway.

### Agent requests

`Agent::handle(connection, message)` always answers with a message. The supported requests are:

| Request | Answer |
| ------- | ------ |
| `REQUEST_IDENTITIES` (11) | `IDENTITIES_ANSWER` (12) with the key user's keys, in the order below. The comment of each is its label |
| `SIGN_REQUEST` (13) | `SIGN_RESPONSE` (14) with the signature, or `FAILURE` |
| `EXTENSION` (27) `session-bind@openssh.com` | `SUCCESS` once the signature verifies, else `FAILURE` (a forwarding bind still restricts the connection) |

Everything else, including adding, removing, and locking keys and every other extension, gets
`SSH_AGENT_FAILURE` (5). So does a message that doesn't parse: a truncated string, a length that
overflows, trailing bytes, or no bytes at all. A failure never ends the relay.

- **Keys are read on every request.** `SshKeys::agent_keys` reads the rows each time, so a key
  deleted on the SSH keys page stops working at the next request, and a new key is offered at once.
  A key that is deleted while its signature is being made fails the request, because `touch_used`
  finds no row.
- **Order.** The most recently used key first (`last_used_at` descending, never-used keys last),
  then the newest (`created_at` descending). OpenSSH servers allow six authentication attempts by
  default (`MaxAuthTries`), so a user with many keys would see "Too many authentication failures"
  without this.
- **Whose keys.** Only the key user's. Another user's key is never listed, and a sign request that
  names one fails whether the blob is right or not. A workspace without a key user answers
  `REQUEST_IDENTITIES` with no keys and fails every signature.
- **Signing.** `ssh::keys::sign` makes the signature on a blocking thread. An RSA key needs flag 2
  (`rsa-sha2-256`) or 4 (`rsa-sha2-512`), and 2 wins if both are set. Flag 0, which asks for SHA-1,
  fails. Other flags are ignored for other key types.
- **`session-bind@openssh.com`.** OpenSSH 8.9 and later tell the agent which host a connection is
  for. The agent verifies the destination's signature over the session id with the host key it
  names. If it verifies, it records the host key's `SHA256:` fingerprint and answers `SUCCESS`.
  Whether the bind says the agent is forwarded doesn't depend on that: a bind with `is_forwarding`
  set is recorded even when the host key doesn't parse or the signature doesn't verify, and the
  answer is then `FAILURE`. OpenSSH goes on using the connection after a failed bind, and `ssh-key`
  can't verify every host key OpenSSH accepts: RSA keys under 2048 bits or over 4096, and `ssh-rsa`
  (SHA-1) signatures. A bind without `is_forwarding` that doesn't verify changes nothing.
- **Forwarded connections.** Any bind with `is_forwarding` set marks the connection for good. Such a
  connection is offered no keys and every sign request on it fails. Clients older than 8.9 never
  send a bind, so for them the check can't apply.
- **Logging.** Each signature updates the key's `last_used_at` and logs at `info` the workspace, the
  user, the key's label, and the bound host key's fingerprint, or `unknown` for a connection that
  never bound. Refusals log at `warn` or `debug`. No log line or error contains a key.
- **State.** The agent keeps a connection's state until the plugin sends `AgentClosed` for it or the
  relay ends. The plugin never reuses a connection number within a relay.
- **Untrusted input.** Every frame comes from a process in the container, and root in the workspace
  can write frames of its own to the helper exec's output, so the relay treats connection numbers,
  `AgentClosed`, and every message as untrusted workspace input. The agent keeps state for at most
  256 connections (`ssh::agent::MAX_CONNECTIONS`). When the table is full, a new `session-bind`
  drops the least recently used connection that isn't forwarded. If every connection is forwarded
  the bind is refused, and a connection whose state the agent couldn't record must not become an
  ordinary connection when a slot frees up later. So the agent remembers the highest connection
  number it has heard from when it refuses a bind. Every connection up to that number that has no
  state is treated as forwarded for good (no keys, no signatures), which costs two integers and no
  per-connection memory. Connections after it are ordinary once there is room. The helper never
  reuses a number, which makes this sound. A connection without state also gets no keys while the
  table is full of forwarded ones, since it could be a forwarded one that has no room yet. A
  workspace that can write frames can ask for its key user's keys anyway, since every command in it
  can connect to the socket.

## Labels

A label is 1 to 100 characters after trimming, with no control characters. Labels needn't be unique.
A generated key's default label is `<user>@doozers`. An uploaded key's is its comment if it has one
that is a valid label, else `<user>@doozers`.

## Tests

`crates/doozers-core/src/ssh/tests.rs` covers the service and every format, and
`channels/web/tests/ssh_keys.rs` the pages. `ssh/agent_tests.rs` covers the agent: key order and
use, other users' keys, every key type's signature verified with the public key, the RSA flags,
deleted and renamed keys between requests, binds (including an RSA host key, and forwarding binds
with bad signatures or host keys), forwarded connections, a flooded connection table, requests it
doesn't serve, and malformed messages. The relay's lifecycle is tested in `workspaces/tests.rs` with
the in-process environment, and the model's text in `core_tools/environment/tests.rs`. The upload
fixtures are in `crates/doozers-core/src/ssh/testdata/`, checked in so the tests are deterministic.
`testdata/generate.sh` says how they were made with `ssh-keygen` and `openssl`.

The tests that compare against OpenSSH run `ssh-keygen -l` for each generated type's fingerprint and
`ssh-keygen -Y verify` for a signature made with a key read back from the secret store. They print
why they stop when `ssh-keygen` isn't installed.
