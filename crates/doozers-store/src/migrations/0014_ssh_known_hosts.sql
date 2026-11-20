-- The SSH host keys workspaces trust (doozers_core::ssh::known_hosts), one set per environment
-- instance: instances can sit on different networks, where one name means different servers.
--
-- `host` is the lowercased name or address without brackets or port, and `port` is the port.
-- `key_type` is the SSH name of the key's algorithm and `public_key` is the base64 of its wire
-- blob, as it appears in a `known_hosts` line. A host may have several keys (one per type), so the
-- key is part of the uniqueness. `fingerprint` is the `SHA256:...` form `ssh-keygen -l` prints.
-- `first_seen_at` is Unix milliseconds. The `first_*` columns say which workspace, agent, and user
-- made the first connection that recorded the key; all three are NULL for a key an admin pinned,
-- and `added_by` names that admin (NULL for a key recorded on first use). `last_used_at` stays
-- NULL until a connection is checked against the key.
--
-- `id` is `AUTOINCREMENT` so a deleted row's id is never reused: a page that was open before a
-- delete can't delete the next host recorded.
CREATE TABLE ssh_known_hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    environment     TEXT    NOT NULL CHECK (environment <> ''),
    host            TEXT    NOT NULL CHECK (host <> ''),
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    key_type        TEXT    NOT NULL CHECK (key_type <> ''),
    public_key      TEXT    NOT NULL CHECK (public_key <> ''),
    fingerprint     TEXT    NOT NULL CHECK (fingerprint <> ''),
    first_seen_at   INTEGER NOT NULL,
    first_workspace TEXT,
    first_agent     TEXT,
    first_user      TEXT,
    added_by        TEXT,
    last_used_at    INTEGER,
    UNIQUE (environment, host, port, public_key)
) STRICT;
