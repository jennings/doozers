-- The local secret store (doozers_core::secrets). Only values are encrypted: the core seals each
-- one with a data key and stores the result here, so listing secrets never needs the key.
--
-- `secrets` has one row per secret. `path` is the secret's name, validated by the core: lowercase,
-- so the default BINARY collation needs no case folding. `algorithm`, `nonce`, and `ciphertext`
-- (with its authentication tag) are the sealed value; the core binds `path` into it, so a
-- ciphertext copied onto another row fails to open. `created_by` and `updated_by` are user ids,
-- NULL when no user did it (the operator at the CLI, or Giles itself). Times are Unix milliseconds.
CREATE TABLE secrets (
    path        TEXT    NOT NULL PRIMARY KEY CHECK (path <> ''),
    description TEXT    NOT NULL DEFAULT '',
    algorithm   TEXT    NOT NULL CHECK (algorithm <> ''),
    nonce       BLOB    NOT NULL,
    ciphertext  BLOB    NOT NULL,
    created_at  INTEGER NOT NULL,
    created_by  TEXT    CHECK (created_by <> ''),
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    CHECK (updated_by <> '')
) STRICT;

-- The data key that seals every row of `secrets`, itself sealed ("wrapped") by a key-encryption
-- key from the key source named in `source` (a key file). At most one row, replaced only while
-- `secrets` is empty.
CREATE TABLE secret_key (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    source     TEXT    NOT NULL CHECK (source <> ''),
    algorithm  TEXT    NOT NULL CHECK (algorithm <> ''),
    nonce      BLOB    NOT NULL,
    wrapped    BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
