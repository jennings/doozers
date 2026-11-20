-- The SSH keys users keep in Doozers (doozers_core::ssh): metadata only. Each private key is a
-- secret in the secret store at `users/<user>/ssh-keys/<id>`, sealed there like every other secret.
--
-- `id` is `AUTOINCREMENT` so an id is never reused: a new key never meets the leftover secret of an
-- old one. `algorithm` is the SSH name of the public key (`ssh-ed25519`, `ssh-rsa`,
-- `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`), `public_key` is
-- `<algorithm> <base64>` without a comment, and `fingerprint` is the `SHA256:...` form
-- `ssh-keygen -l` prints. Two users may hold the same key (each has its own row and secret), but
-- one user can't hold it twice. `last_used_at` stays NULL until the key first signs. Times are Unix
-- milliseconds.
CREATE TABLE ssh_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT    NOT NULL CHECK (user_id <> ''),
    label        TEXT    NOT NULL CHECK (label <> ''),
    algorithm    TEXT    NOT NULL CHECK (algorithm <> ''),
    public_key   TEXT    NOT NULL CHECK (public_key <> ''),
    fingerprint  TEXT    NOT NULL CHECK (fingerprint <> ''),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    UNIQUE (user_id, fingerprint)
) STRICT;
