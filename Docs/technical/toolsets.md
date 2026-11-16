# Toolsets

Code: `crates/giles-core/src/toolsets/` (`giles_core::toolsets`). Design: PLAN sections 7.5, 7.6,
7.9, and 7.10. A toolset is an MCP server; the [MCP client](mcp.md) is the connection, and this
module decides how to reach each toolset (`ToolsetLauncher`), a stdio `[toolset.<instance>]` table
of `giles.toml` or a remote server [stored in the database](#stored-toolsets), and keeps it going
until it is removed or the daemon stops (`ToolsetHost`).

## Connecting

`ToolsetLauncher::new(root, trampoline, sandbox, blobs)` mirrors the [plugin host](plugin-host.md)'s
`Launcher`: `trampoline` is the `giles` binary (run as `giles sandbox-exec`), and `sandbox` is the
host check `serve` runs once; an error refuses every sandboxed server with that message. `blobs` is
the runtime's blob store, where every connection keeps the media its tools return
([MCP Client](mcp.md#mapping-mcp-to-the-toolset-trait)). `.env(f)` replaces the process environment
for `PATH` lookups (tests).

`connect(&ToolsetInstance)` returns an `McpToolset` once the server has answered `initialize`:

- **Stdio** (`command`): `resolve` finds the program, then `launch` starts it in its sandbox (below)
  and hands the command to `McpToolset::connect_stdio` with the `env` values as the secrets to
  scrub.
- **Remote** (`url`): `McpToolset::connect_http` with the bearer token from `auth`, if any. A remote
  toolset with `auth.oauth` signs each user in instead ([Each user's sign-in](#each-users-sign-in)):
  `connect_oauth` returns a `UserOAuthToolset`. OAuth client credentials are for remote channels.

Errors are `giles_types::Error`, prefixed `toolset <instance>:`. `InvalidRequest` means retrying
won't help (the host can't sandbox, an invalid spec, the sandbox trampoline failing at launch with
125 or macOS's 71, rejected credentials); `Unavailable` covers the rest (program not found, a server
that fails to start or answer, an unreachable URL).

## Finding the program

`command` is an absolute path or a name looked up on the operator's `PATH` (`config::find_program`,
the same lookup config loading uses to protect binary directories). A toolset has no component and
no `<root>/plugins/` lookup: a first-party server is configured with `command` like any other.
`ResolvedProgram` keeps both the path as found (`found`) and with links resolved (`program`). The
trampoline runs `program`, so the file granted is the file run, and the
[tool-list cache](#tool-list-cache) is keyed on its SHA-256.

## Grants

The sandbox spec is the configured grants plus what running the server needs (`toolsets/grants.rs`,
PLAN section 7.10). Most servers are scripts installed by a package manager:
`/opt/homebrew/bin/mcp-server-filesystem` links into `/opt/homebrew/lib/node_modules/...`, whose
`#!/usr/bin/env node` runs `/opt/homebrew/bin/node`. The plan:

1. Collect the binaries involved: `found`, `program`, and if `program` starts with `#!`, the
   interpreter (`/usr/bin/env`, or e.g. a venv's `python`) and, for `env [options] <name>`, the
   program `<name>` looked up on the operator's `PATH`. Each is added again with its links resolved,
   since the sandbox checks real paths (a venv's `python` usually links into a shared Python
   installation).
2. Grant each one's **install prefix**: the directory holding `bin/` or `sbin/` for a program in one
   (`/opt/homebrew`, the venv), else the program's own directory; never `/` (`/bin/sh` gets `/bin`).
   The prefix goes to both `read` and `execute`, since interpreters need an `execute` grant and
   their libraries need `read`.
3. Each grant passes the same rule as configured grants (`config::check_grant`): it may not overlap
   the data root (other than the instance's own data directory), the socket directory, or the secret
   store's key file (`ToolsetLauncher::new` takes `core.secret_key_file`). It also may not be the
   operator's home directory or contain it (the launcher's `HOME`, compared as written and with
   links resolved), whatever the data root: `~/bin/server` would otherwise grant all of `~`,
   including `~/.ssh`. A prefix that fails narrows to the program's directory, then to the file
   itself. A program inside the data root gets no grant at all; the backends always let the command
   itself run.
4. Grants inside another grant are dropped; the rest are sorted.

The server's `PATH` is the directory of `found`, then that of a program found through `env`, then
`/usr/bin:/bin`, so `#!/usr/bin/env node` finds the same `node` it would for the operator. Paths
containing `..` (or `:`, for `PATH`) are left out; the spec refuses them.

Configured `write` and `unix` grants can't touch a directory holding the `giles` binary, a plugin,
or a toolset's command (config loading checks that). That doesn't cover script interpreters (the
`#!` interpreter and a program found through `env`): their prefixes are granted read and execute
here, but config loading doesn't know them, so a `write` grant on, say, a Node installation would
let that server replace the `node` other toolsets run. Don't grant `write` on an interpreter's
installation.

**How wide a prefix is.** PLAN section 7.10 grants whole install prefixes, which is what package
managers need (Homebrew's `node` loads libraries from `/opt/homebrew/opt/*`), and it exposes
whatever else lives there: `/opt/homebrew/etc` and `/opt/homebrew/var` for a Homebrew command, all
of `~/.local` for `~/.local/bin/x`, all of `~/.cargo` (including `credentials.toml`) for
`~/.cargo/bin/x`. Only the home directory itself (and `/`) is ruled out. Operators who mind install
servers in a prefix of their own, such as a venv or `npm --prefix`.

## The launch

Like a plugin launch ([Plugin host](plugin-host.md)), without the gRPC parts:

- Data directory `data/toolset/<instance>/` and its `tmp/`, mode 0700, refused if it is a link
  (`plugin_host::prepare_data_dir`). Toolsets have their own data root, `data/toolset/` (PLAN
  section 11.6).
- The spec: `read` and `execute` from the plan (plus configured `read`), configured `write`, `unix`,
  `min_abi`, `network` (off unless granted: the config loader's toolset default), `inherit_env` =
  the names in `env`, and `path` from the plan. No `env`: MCP servers aren't Giles plugins and get
  no handshake variables.
- Sandboxed: the spec goes to `run/sandbox/toolset/<instance>.json` (0600, atomically), and the
  command is `giles sandbox-exec <spec> -- <program> <args>` with the `env` values set on the
  trampoline's process. The trampoline passes exactly those names on (the sandbox's
  [inherited variables](sandbox.md#environment)), so credentials never touch the spec file or
  `argv`.
- `unsandboxed = true`: the program runs directly, with a warning at every launch, the same scrubbed
  environment (`sandbox::scrubbed_env` with the `env` values and the daemon's `LANG` as the
  inherited lookup), and the data directory as the working directory.
- `McpToolset::connect_stdio` spawns it as the leader of its own process group; dropping the
  connection kills the group, and the server exiting takes the rest of the group with it
  ([MCP Client](mcp.md#stdio)). A server also exits when its stdin closes, which covers a core that
  dies without stopping it.
- The connection's media: results to the blob store, and `$media` inputs copied into the server's
  `TMPDIR` (`McpMedia::new(blobs).files_in(spec.tmp_dir())`), which the sandbox lets it read
  ([MCP Client](mcp.md#mapping-mcp-to-the-toolset-trait)).

`env` may not set `HOME`, `TMPDIR`, `PATH`, or `GILES_PLUGIN_DATA`: the sandbox derives them
(`sandbox::DERIVED_ENV`), and config loading refuses them.

## Lifecycle

`ToolsetHost::start(launcher, &registry)` runs in `serve` right after the registry is built
([The `giles` Binary](daemon.md#giles-serve-lifecycle)). For each configured toolset it:

1. Looks up the [tool-list cache](#tool-list-cache) (stdio servers only) and offers a hit at once.
2. Registers a `ManagedToolset` with `Registry::register_toolset`. It stays registered until the
   toolset is [replaced or removed](#changing-toolsets-while-giles-runs), so the dispatcher needs
   nothing beyond the registry.
3. Spawns the instance's supervisor task (`toolsets/lifecycle.rs`, under a `toolset{name=<name>}`
   span), which owns the connection and makes the first start.

`started()` waits for every first start to succeed or fail; `serve` waits for it alongside the
plugin launches before logging `giles started`. `stop()` cancels every supervisor and waits for
them, dropping every connection (a stdio server's process group is killed). It is for shutdown;
after it, nothing starts any more.

`ManagedToolset` is the instance's face:

- `list_tools` and `tool_changes` report what the supervisor offers (a `watch` channel), so the
  registry's tool index follows the cache, each start, and each `list_changed`. As always, a new
  list reaches new sessions only; a running session keeps its snapshot (PLAN section 6.4).
- `call` asks the supervisor for the connection over a channel and calls it. The lease it gets holds
  the connection and counts the call as in flight until the returned events are dropped, so idle
  stop never cuts a call short.
- For a server each user signs in to (`auth.oauth`), `per_user` is true, and `user_tools(user)` asks
  the supervisor for the connection the same way and lists that user's tools over it
  ([Each user's sign-in](#each-users-sign-in)).
- `list_skills` and `get_skill` read the instance's `skills` directories (`skills::discover` on a
  blocking thread, bare names, a later directory overriding an earlier one, broken skills logged and
  skipped), whether or not the server runs. The agent's skill index reads the same directories
  through `Registry::skill_sources` with the `<instance>__` prefix (PLAN sections 6.6 and 7.10),
  which is what the prompt lists and `load_skill` loads, files included.

The supervisor is a loop over four states:

| State     | Leaves on                                     | A call                                  |
| --------- | --------------------------------------------- | --------------------------------------- |
| `Running` | the connection closing, idle stop, shutdown   | gets the connection                     |
| `Idle`    | a call (relaunches, then answers it), shutdown | waits for the relaunch                  |
| `Down`    | the retry time (starts again), shutdown       | fails at once: `Unavailable` with the reason and `retry_after` |
| `Stopped` | (ends the task)                               | fails: `Unavailable`, the toolset is stopped |

Every start lists the tools, offers them, and stores them in the cache. A start whose listing fails
keeps offering the previous list.

**Crashes and failed starts** (PLAN section 7.5): the server exiting (with its status), a lost
connection, or a start that fails with a retryable error leads to `Down` with a restart after
`RESTART_BACKOFF_MIN` (1 s), doubling up to `RESTART_BACKOFF_MAX` (5 min); a connection that lasted
`HEALTHY_RESET` (10 min) starts the backoff over. A non-retryable failure (`InvalidRequest`: the
host can't sandbox, the sandbox trampoline failed with 125 or macOS's 71, rejected credentials, no
shared protocol) isn't retried until it's restarted by hand or Giles restarts, and the instance's
tools are withdrawn, cached or not: every call would fail. While a stdio server will be retried, its
tools stay offered, and calls fail with the reason and when the next attempt is due, as for a server
that's restarting.

**Remote servers** (PLAN section 7.6): the same backoff, but while one is unreachable (at boot or
later) its tools are withdrawn, so new sessions don't get them; sessions that already have them get
`tool unavailable` from the dispatcher, which checks the live index. Giles runs degraded meanwhile:
the other toolsets and everything else work. Remote servers never stop for idleness.

**Idle stop** (`idle_stop`, stdio only): once no call has been in flight for `idle_stop` (counted
from the end of the last call, or the start), the supervisor drops the connection, killing the
server, and goes `Idle`. The tools stay offered (the in-memory list, the same one the cache holds),
and the next call relaunches the server, which also refreshes the list. A server stopped for
idleness didn't crash, so the restart backoff starts over at 1 s; otherwise a server whose
`idle_stop` is under `HEALTHY_RESET` would never reset it.

**Reporting and restart**: each supervisor keeps a `Report` that `ToolsetHost` hands to the admin
service as a `PluginRuntime` (`ToolsetHost` implements `PluginControl`, see
[Admin Service](admin.md#seams-for-later-subsystems)):

| Field          | Value                                                                              |
| -------------- | ---------------------------------------------------------------------------------- |
| `state`        | `Starting` while a start is under way (and before the first), `Running`, `Idle`, `BackingOff { until }` (a `Down` that will be retried), `Failed` (a `Down` that won't), `Stopped` |
| `restarts`     | starts after a crash, a failed start, or a restart request; not the first start, and not the relaunch of an idle server for a call |
| `last_error`   | the reason of the last failed start or crash, as failed calls see it (already scrubbed); kept after the toolset recovers |
| `binary`       | the program of the latest connection (`ResolvedProgram::program`, links resolved); unset for a remote server |
| `version`      | `serverInfo.version` of the latest connection                                      |
| `tool_count`   | the number of tools offered to new sessions, so the cached list while a stdio server starts, and none while a remote server is down |

`pid` is never set: a stdio server runs under the sandbox trampoline, so the process the core
spawned isn't the server, and a remote server has none.

`PluginControl::restart(Kind::Toolset, instance)` (`Control::request_restart`) wakes the supervisor
whatever state it is in, and the supervisor drops the connection and starts again at once. It starts
the backoff over and counts a restart. `Failed` toolsets get a fresh try, as a Giles restart would
give them. A restart while a start is under way abandons that attempt and begins another, so a hung
start can be retried. The old connection closes when its last call ends, so a call still running
keeps the old server alive until it finishes. `restart` answers `false` for an instance the host
doesn't supervise, such as a toolset that couldn't be registered.

## Changing toolsets while Giles runs

A toolset can be added, replaced, and removed without restarting Giles. Each call takes the toolset
as it is, or is to be, in the registry's
[live configuration](registry.md#the-running-configuration): the caller changes the `LiveConfig`
first (`add_toolset`, `replace_toolset`, `remove_toolset`) and then tells the host, because
`register_toolset` checks the live configuration. The host serializes its changes, so two of them
never interleave.

- `add(&ToolsetInstance)` does what boot does for one toolset: the cache lookup, `register_toolset`
  (so the cached tools are offered at once), and a new supervisor. It doesn't wait for the first
  start. A supervisor still running under the same name is stopped first, so a second `add` never
  leaves two. It fails with `RegistryError::NotConfigured` if the instance isn't in the live
  configuration, and does nothing once the host has been stopped.
- `replace(&ToolsetInstance)` stops the old supervisor, then adds the new instance under the same
  name. Stopping drops the old connection, which kills a stdio server's process group, and a call
  still running on it ends as `Unavailable` (`toolset <instance>: stopped`). Its `config_hash`
  differs from the old one's, so the cache lookup misses and nothing is offered until the new server
  answers. Registering replaces the old object and starts a new tool-index generation, which drops
  the old object's watcher, so a late `list_changed` from the old server can't overwrite the new
  list (it can't arrive at all: its connection is gone).
- `remove(&InstanceName)` stops the supervisor, then calls `Registry::unregister_toolset`, which
  withdraws the tools from new sessions. A call still running ends `Unavailable`, and a session that
  took its tools earlier still lists them, but the dispatcher answers a call to one with
  `tool unavailable`: the registry has no such toolset.

Every supervisor has its own cancellation token, a child of the host's, so a stop affects one
toolset and `stop()` still stops all. A stopped supervisor's task ends, and the host waits for that
before it registers the replacement or unregisters the toolset. `stop()` takes the same lock as a
change, so a change in progress finishes first and none starts a supervisor that `stop()` doesn't
wait for. The state the admin service reports follows: a removed toolset is gone from `plugins()`,
and a replaced one starts over as `Starting`.

## Stored toolsets

`toolsets/manager.rs`: the remote MCP servers that the web UI manages are stored in the database
([Storage](storage.md#toolsets)), and `ToolsetManager` is the one place that changes them. There is
one per core, built in `giles serve` after the host has started the toolsets of `giles.toml`. The
web pages, the admin RPCs, and the CLI call it; none touches the table, the live configuration, or
the host. Both sources work side by side, and toolset names stay unique across them.

A stored toolset is a remote server. A web login must not be able to choose a program for Giles to
run on the host, its arguments, its environment, or its sandbox grants: installing and running code
on the host is the operator's, so a stdio server is a `[toolset.<name>]` table of `giles.toml`.
Connecting to a remote server is not, so a `[toolset.<name>]` table with `url` is ignored
([Configuration](config.md#ignored-toolset-tables)): it isn't an instance, and a stored toolset may
use its name. Nothing is migrated from such a table.

`ToolsetManagerOptions` holds the store, the data root, the [secret store](secret-store.md), the
`LiveConfig`, and the `ToolsetHost`. `ToolsetManager::start(options)` loads the stored toolsets, and
the operations are:

- `list()` is every toolset ordered by name ignoring case: the stored ones, each a `ToolsetView`
  with its `spec` (a `ToolsetSpec`, credentials as references), its `created_at` and `updated_at`,
  and a `failure` if it isn't running; and the ones of `giles.toml`, as `ToolsetSource::File` views
  without a spec. `get(name)` is one of them. Names match ignoring ASCII case.
- `add(name, &spec)`, `update(name, &spec, expected_updated_at)`, `rename(old, new)`, and
  `remove(name)`. The error is a `ToolsetManagerError`: `Invalid { key, reason }` (the key is the
  spec key that has the problem, `auth.bearer`, or the root for the name or a conflict), `Exists`
  (the name is stored, ignoring case), `NotFound`, `Stale`, `Refused { reason }` (a rename that an
  agent's globs stand in the way of), `Failed { step, error, undo_errors }` (a step of a rename
  failed and was undone), `Unsupported` (the name is a toolset of `giles.toml`, which is read-only
  here), `Store`, and `Secrets` (the secret store failed). `is_invalid_input()` is true for
  everything the owner can fix in the form: `Invalid`, `Exists`, `Stale`, `Unsupported`, and
  `Refused`.

A spec is stored as JSON with the keys of the `[toolset.<name>]` table (`ToolsetSpec`'s serde form,
so a duration is `"300000ms"`). Credentials are references into the secret store, so no secret value
is in the toolset rows.

### Credentials

`toolsets::credentials` owns the rule. A stored toolset `<name>` owns the secrets at
`toolsets/<name>/...`, with `<name>` in lower case (names are unique ignoring case):
`toolsets/<name>/bearer-token` and `toolsets/<name>/oauth-client-secret`. It also owns each user's
tokens, `users/<user>/toolsets/<name>/oauth-token`, which no spec refers to.

- **In.** A spec given to `add` or `update` may hold `auth.bearer` or `auth.oauth.client_secret` as
  the value itself. `take_literals` moves it out, to be stored at the toolset's path, and leaves
  `{ secret = "toolsets/<name>/bearer-token" }` in its place. A reference must name the toolset's
  own path. A reference to `secrets.toml`, to another toolset's secret, to a user's secret, or to
  the environment is an `Invalid` at `auth.bearer`. A web login therefore can't bind a secret it
  didn't set.
- **Another server.** An `update` whose URL has another scheme, host, or port than the stored one
  refuses a credential given as a reference (an `Invalid` at its key): it must be given as the value
  again. A stolen web session therefore can't point a toolset at its own server and collect the
  stored token. The users' OAuth tokens are deleted on such a change, since they were issued for the
  old server.
- **Validation.** `credential_values` reads the referenced secrets from the store, with the literals
  about to be stored on top, and hands them to `validate_toolset` as `Secrets::from_store`. A
  reference to a secret that isn't stored fails as `no secret "<path>" in the secret store`.
- **Writes.** The literals are put before the row is written. `add` deletes them again if the row
  insert fails. After an `update`, owned secrets the spec no longer references are deleted, such as
  the token when `auth` is dropped, and so are the users' tokens unless the spec still has
  `auth.oauth`. `remove` deletes every owned secret, and a failure there is logged, since the row is
  gone. `add` first deletes whatever a toolset of the same name left behind.
- **Rename.** The plan computes where each owned secret moves (`credentials::moved`) and the spec
  with its references retargeted. The rename copies the secrets after rewriting the agents and
  before renaming the row (`Step::Copied`, undone by deleting the copies), then writes the
  retargeted spec with the row. It deletes the old paths only once everything succeeded. A rename
  that only changes case moves nothing. A new name that can't name a secret (one starting with `-`)
  is refused while the toolset owns secrets. The offline rename does the same
  ([Instance rename](instance-rename.md)).
- **Upgrade.** `start` first runs `move_tokens_into_the_store`. A bearer token kept as text in a
  row, or as a `{ secret = "<name>" }` reference to `secrets.toml`, is put at the toolset's path,
  and the row is rewritten to the reference. A reference whose secret `secrets.toml` lacks is left
  alone, and the toolset fails validation with the reason.

### Each user's sign-in

A stored toolset with `auth.oauth = { client_id, client_secret, scopes }` (each optional; a
`client_secret` needs a `client_id`) signs each user in with the OAuth authorization code grant and
PKCE, as the MCP authorization spec has it. Config loading parses it as `Auth::UserOAuth`; a remote
plugin's `oauth` stays client credentials (`Auth::OAuth`). `toolsets::oauth` does the work through
`rmcp`'s `auth` feature.

- **HTTP.** Every OAuth request (discovery, registration, token) goes through `OAuthHttp`, built for
  the MCP server's URL: `net::tls_client_builder` (bundled roots), a 30 s timeout, and 1 MiB bodies.
  Redirects are followed (up to 5) only where `rmcp` asks, which it does for dynamic client
  registration and never for a token request.
- **Addresses.** The URLs these requests go to come from the MCP server, so `oauth::address` keeps
  them off the network Giles runs in, with the rule `rmcp`'s own client has. Public addresses are
  allowed. A loopback or private address is allowed only when the MCP server's URL names one (an IP
  literal of that class, or `localhost`); what its host name resolves to never widens this.
  Link-local (cloud instance metadata), unspecified, broadcast, multicast, and reserved addresses
  are never allowed. The rule applies to IP-literal URLs, to every address a host name resolves to
  (a filtering DNS resolver), and to each redirect. Proxy hosts from the environment aren't
  filtered. An MCP server on a private network that is reached by a host name therefore can't send
  Giles to a private authorization server; give its URL as the IP address.
- **Tokens.** `UserTokens` is `rmcp`'s `CredentialStore` over the secret store. The secret at
  `users/<user>/toolsets/<name>/oauth-token` is JSON: `rmcp`'s `StoredCredentials`, plus the issuer
  and token endpoint of the authorization server at sign-in. It's written with the user as
  `updated_by`. A refresh holds a lock per path (`acquire_refresh_guard`), so two connections of one
  user don't both spend a rotating refresh token. A refresh token the server rejects
  (`invalid_grant`) deletes the stored tokens, unless another refresh replaced them meanwhile, so
  the user is shown as signed out.
- **Pinned endpoints.** Every connection discovers the authorization server again, and refuses to
  use the tokens unless the issuer and token endpoint are the ones stored with them. An MCP server
  that changes hands, or answers discovery differently, can't make Giles send the refresh tokens and
  the client secret to another token endpoint; the user is told to sign in again. A new sign-in
  still trusts what the server names at that moment.
- **Sign-in.** `ToolsetManager::begin_sign_in(name, user, redirect_uri)` finds the running toolset
  (`redirect_uri` makes the callback URL from the toolset's name as stored), discovers the
  authorization server (protected-resource metadata, then authorization server metadata), registers
  a client if `client_id` is unset, and returns the authorization URL (`code_challenge_method=S256`,
  `resource` = the server's URL, `state`). The started sign-in waits in memory under its `state` for
  `SIGN_IN_TTL` (10 minutes): at most 4 per user, dropping that user's oldest, so no user can push
  out another's, and 256 in all. `finish_sign_in(name, user, state, code, iss)` takes it back only
  for the user who started it and only on that toolset's callback. A sign-in that comes back to
  another toolset's callback is dropped: each toolset has its own callback, so a code from another
  toolset's authorization server (a mix-up) can't be finished, whether or not the server sends
  `iss`. It then exchanges the code, stores the tokens, and restarts the toolset in the host.
  `sign_out` deletes the user's tokens and restarts it too. `sign_ins(user)` lists the toolsets with
  `auth.oauth` and when the user's tokens were last stored. Neither half holds the manager's lock,
  since both wait on the network.
- **Connections.** `UserOAuthToolset::connect` tries the signed-in users in id order and keeps the
  first connection that works: its server version is the toolset's, and its end is the toolset's end
  for the supervisor. Nothing else comes from it. With no one signed in, the connection fails as
  `Unavailable` and the supervisor retries with its backoff until a sign-in restarts it. A user's
  connection is `McpToolset::connect_http_oauth`: the transport is `rmcp`'s `AuthClient` over an
  `AuthorizationManager` initialized from the user's tokens (`initialize_from_store`, which drops
  tokens of another issuer), reconfigured with the client secret if the tokens belong to the
  configured client. `AuthClient` reads the access token from the store on every request, refreshes
  it within 30 s of expiry or after a 401, and retries once.
- **Tools.** The toolset is per-user (`Toolset::per_user`). Its `list_tools` is empty, it has no
  `tool_changes` and no skills, and `user_tools(user)` lists the tools over the user's own
  connection, or none if they haven't signed in. The registry asks for them as each of the user's
  sessions starts ([Registry](registry.md#tool-index)), so no user's model sees tool names or
  descriptions from another user's account. A group session gets none.
- **Calls.** `call` goes over the requester's own connection: the first one, an open one made
  earlier, or a new one. A turn without a requester (a config job) and a requester who isn't signed
  in get an `InvalidRequest`, which the agent loop turns into an error tool result; the turn goes
  on. No call uses another user's token.

### One change

One async lock spans each change, as `Routes` does for routes. A change:

1. Looks the name up in the rows. `add` refuses a stored name (`Exists`). `update` and `remove`
   refuse a name that only `giles.toml` has (`Unsupported`) or that nothing has (`NotFound`);
   `update` also compares `expected_updated_at` with the row's (`Stale`).
2. Moves literal credentials out of the spec ([Credentials](#credentials)) and validates it with
   `validate_toolset` ([Configuration](config.md#validating-one-toolset)) against the running
   configuration, with its credentials read from the secret store. Before it, in this order, the
   manager refuses the name `new` (ignoring case), which is the address of the web form for a new
   toolset (an `Invalid` at the root), a name that a `giles.toml` toolset uses (the reason is
   ``the name is taken by `[toolset.<name>]` in giles.toml``, whatever else is wrong with the spec),
   a credential that is neither a value nor a reference to the toolset's own secret (an `Invalid` at
   its key), and a spec without `url` (an `Invalid` at `url`: a stdio server goes in `giles.toml`).
   `validate_toolset` then refuses the keys of a stdio server (`command`, `args`, `env`,
   `idle_stop`, `sandbox`, `unsandboxed`) next to `url`, each at its key. Nothing is stored when any
   of these fails.
3. Stores the literal credentials, then writes the row. The store checks the stale token too, so a
   write can't overwrite a change that isn't the one the caller read.
4. Changes the `LiveConfig` (`add_toolset` or `replace_toolset`), then the host (`add` or
   `replace`), so new sessions get the new tool list and running sessions keep their snapshot. If
   this step fails after the row is written (it can't unless the live configuration and the manager
   disagree), the host has unregistered the toolset, so the entry is taken out of the live
   configuration again (`withdraw`) and the toolset is failed with the reason: it shows as one
   failed stored toolset, not as a toolset of `giles.toml`, and can be saved or removed. The error
   is an `Invalid` at the root.

`remove` deletes the row, takes the toolset out of the live configuration, and stops it in the host,
which withdraws its tools. A remote toolset has no data directory, and its entry in the
[tool-list cache](#tool-list-cache) is never offered, so nothing else is cleaned up. Agents' `tools`
and `ask` patterns that name the toolset's tools are left alone: they match nothing until a toolset
of that name returns.

### Renaming

A toolset's name is its tool prefix and the start of the globs agents use in `tools` and `ask`, so
`rename(old, new)` is more than a change to the row
([Instance rename](instance-rename.md#renaming-while-giles-runs) has the full account, and the
offline `giles toolset rename` does the same for either kind of toolset while Giles is stopped).
`rename_preview(old, new)` makes the checks and returns a `RenamePreview { agents }`, the
`AgentGlobChange { agent, globs }` of every agent whose `tools` or `ask` globs would change, each
`GlobChange { key, from, to }` with the list it is in (`tools` or `ask`) and the glob before and
after. `rename` returns a `ToolsetRenamed { from, view, agents }`: the name the toolset had as
stored, the toolset under its new name, and the same list. Under the manager's lock, and the agent
manager's lock once the checks start (see
[Instance rename](instance-rename.md#renaming-while-giles-runs)), a rename:

1. Checks the new name and the agents. The name must be valid, not `new`, free among the stored
   toolsets (`Exists`) and the toolsets of `giles.toml` (`Invalid` at the root), as for a new
   toolset. The old name is exempt, so a rename that changes only the case of a stored toolset's
   name is allowed. A running toolset's spec is validated again under the new name, with its
   references and credentials moved to the new name's paths. Then each agent's `agent.toml` is read.
   A glob that matches the tools without starting with `<old>__` (`github*`) can't be rewritten and
   refuses the rename: `Refused { reason }` names each glob and its agent, and so does a file that
   isn't valid TOML or that the form can't edit. Nothing has changed at this point, and
   `rename_preview` stops here.
2. Stops the toolset in the host, which unregisters it: a session that lists its old tools gets
   `tool unavailable`.
3. Rewrites each agent's `agent.toml` with the agent edit machinery (`agents::edit`, a temporary
   file renamed over it), and
4. renames the row.
5. Renames the toolset in the `LiveConfig`, replaces the agents there, and starts it under the new
   name (`ToolsetHost::add`). A toolset that failed to start is renamed too, then started if it
   validates now, else it stays failed under the new name with the new reason (`view.failure`).

A stored toolset is remote: it has no data directory, and its tool-list cache entry is never
offered, so nothing on disk moves but the agents' files. A step that fails undoes the earlier ones:
the agents' files are put back, the row is restored exactly (`Store::toolset_restore`), and the
toolset is started again under its old name. The error is `Failed { step, error, undo_errors }`;
`undo_errors` lists what couldn't be put back. A stored toolset whose name a toolset of `giles.toml`
took at startup (it shows as failed) is renamed in the database only: the agents' globs under that
name are that toolset's.

### Startup

`start` takes every row in name order and runs the same checks as a change, then adds it to the live
configuration and the host. The host has started the toolsets of `giles.toml` first, so a name that
a `giles.toml` toolset also uses stays with that toolset and the stored one fails. A stored toolset
that fails isn't started: it is logged (`a stored toolset is not started`) and kept with its reason,
a missing secret, a spec that a stored toolset can't have, a spec that can't be read, or the name.
**Startup never fails on a stored toolset**; only the database can't be read.

The manager is also a `PluginControl`, which `serve` merges with the plugin host and the toolset
host. Its `plugins()` is one `Failed` `PluginRuntime` per stored toolset that isn't running, with
the reason as `last_error`. Its `restart(kind, name)` accepts a failed stored toolset (and answers
`false` for any other name, or any other kind) and runs `retry(name)` in the background: it reads
the toolset's credentials from the secret store again, validates the stored spec against the live
configuration as startup did, and starts the toolset, or leaves it failed with the new reason.
`retry` is public, and returns the `ToolsetView`. `ListPlugins` and `Status` list a runtime that the
configuration doesn't have as a toolset, after the configured instances, so `giles status` shows the
failed toolset and why. The fix is in the web UI, which needs Giles running: saving the toolset
again validates it and starts it (`update` on a failed toolset adds it), and removing it deletes the
row.

Giles doesn't wait for a stored toolset's first start before it reports that it started, as it does
for the toolsets of `giles.toml`; it starts in the background.

## Tool-list cache

`toolsets/cache.rs`, PLAN section 7.9: one JSON file per instance in `<root>/cache/toolsets/`
(written atomically, mode 0600), holding the format version, the key, and the bare tool list:

| Key part         | Stdio                                     | Remote         |
| ---------------- | ----------------------------------------- | -------------- |
| `source`         | `sha256:<hex>` of `program`               | the URL        |
| `config_hash`    | `ToolsetInstance::config_hash` (before secrets are resolved, [Configuration](config.md)) | the same |
| `server_version` | `serverInfo.version` from `initialize` (`McpToolset::server_version`) | the same |

Every start stores the fresh list under the full key, and each `list_changed` stores the new list
under the same key. The server version is only known once the server runs, so the lookup at boot
matches `source` and `config_hash`: a different binary (an upgrade) or an edited instance table is a
miss, and nothing is offered until the server answers. On a hit the cached tools are offered from
registration on, while the server starts, and if that start fails they stay offered until a start
succeeds. The version catches upgrades the binary hash can't see (an interpreted server whose
launcher script doesn't change): the start that sees a new version re-lists and replaces the entry.
Remote servers' lists are stored too, but never offered from the cache, since a down remote server's
tools must not be (PLAN section 7.6). A missing, unreadable, or foreign-format file is a miss; a
failed write is logged.

## Tests

- Unit: shebang parsing, install prefixes, the plan for a linked script run by `env`, an interpreter
  link into another prefix, a prefix containing the data root, the home directory (never granted,
  also through a link and with the data root elsewhere), and a program inside the data root; the
  spec built from a plan (credentials named, not written); the cache (hit only for the stored source
  and config hash, replaced by each store, 0600, damaged or foreign files ignored, the digest).
- Lifecycle (`toolsets/tests.rs`), with a fake connector and fake servers on paused time: boot
  starts and registers every toolset and `stop` drops every connection; a cache hit is offered
  before the server answers, then refreshed with the reported version; a changed binary or config
  misses; idle stop waits for calls in flight, keeps the tools, resets the restart backoff, and the
  next call relaunches; a remote server never idles; crash restarts at 1 s, then 2 s, and after ten
  healthy minutes at 1 s again, with calls failing with `retry_after` meanwhile; an unreachable
  remote server leaves the rest running, retries at 1, 2, and 4 s, and its tools come and go with
  it; rejected credentials aren't retried; a stdio server whose start fails for good withdraws its
  cached tools; `list_changed` reaches new snapshots and the cache, not running sessions; a `skills`
  directory is served by bare name and indexed for the agent with the prefix, its skill's files
  listed for `load_skill`.
- `crates/giles/tests/serve.rs`: a stdio toolset that exits and an unreachable remote one are logged
  and retried, with their tools registered (nothing pending) and `giles` running and stopping
  cleanly. With stored toolsets, all remote, one valid and two that can't start (a bearer token from
  the environment, a name that `giles.toml` uses): `giles` runs, the valid one is started and
  supervised, `giles status` lists the others as failed with their reasons, and the log names them.
- `crates/giles-core/tests/toolsets.rs` (`harness = false`): the test binary is both the trampoline
  and the server, found by name on a `PATH` through a link. It reports its environment, working
  directory, and a TCP connect to a local listener on stderr. Sandboxed (Seatbelt on macOS, Landlock
  where the kernel has it; elsewhere the launch is refused with the host check's message): exactly
  the scrubbed variables plus the `env` names, the credential passed, the data directory as working
  directory, the network denied, and with a `tcp:<port>` grant connected; the spec file is 0600 and
  holds the grants and the credential's name but not its value. An attachment passed as
  `{"$media": "<id>"}` reaches the server as a path in its `TMPDIR` that it can read inside the
  sandbox, and the copy is gone after the call. Unsandboxed: the same environment, network open, the
  same media hand-over, and a copy a crash left behind removed at the next start (the server's own
  files stay). Remote: listing tools over streamable HTTP with the bearer token, and a wrong token
  refused as `InvalidRequest`.
- Runtime changes (`toolsets/tests.rs`): adding a toolset registers it, offers its cached tools
  while it starts, and gives new snapshots its tools but not running sessions; replacing it drops
  the old connection (once the call running on it is dropped), ends that call as unavailable, misses
  the cache, offers the new list, and the old connection can't announce a list any more; removing it
  withdraws its tools, ends its calls, drops it from the admin report, and the name can be added
  again; a stopped host starts nothing. The registry's tests cover registering a toolset added to
  the live configuration and unregistering one, and the dispatcher's cover a call from a session
  that lists a removed toolset (`tool unavailable`) and the next batch using an edited toolset's
  `deadline`.
- The manager (`toolsets/manager_tests.rs`, with the fake connector of `tests.rs`, on a real
  database and data root): add, update, and remove reach the database, the live configuration, the
  registry, and the host (an edit restarts the toolset and drops the old connection; a stale update
  and an invalid one change nothing); an invalid spec is refused with its key and nothing is stored;
  a spec without `url`, with a key of a stdio server, or with a bearer token that is neither the
  token nor a reference to the toolset's own secret is refused at that key; a token is stored in the
  secret store with only the reference in the row, kept by an edit that references it, replaced by
  one that gives a new value, moved by a rename, and deleted with the auth or the toolset; startup
  moves a token out of `secrets.toml`; startup adds the valid stored toolset beside a `giles.toml`
  toolset and reports each failure (missing secret, a name taken by a toolset of `giles.toml` with
  the exact reason, a stdio spec, a damaged spec) as failed, and saving or removing a failed toolset
  works and leaves the toolset that kept the name running; toolsets of `giles.toml` can't be
  changed, and a stored name is unique ignoring case, though a provider or a channel may share it.
  The admin tests cover a `Failed` runtime that the configuration doesn't have in `ListPlugins` and
  `Status` (also when a `giles.toml` toolset has the name, which keeps the host's report), and
  restarting it. Renaming: a running toolset offers its tools under the new prefix, and the agents'
  files and the live configuration say the new name (and the preview lists the same globs and
  changes nothing); a name that is taken (by a stored toolset or by a toolset of `giles.toml`),
  reserved, invalid, or the same is refused, and so are globs that match by the old name and an
  agent file that can't be edited, with the globs listed and nothing changed, while data left under
  the new name is not; a failed agent write is undone (the agents, the row, and the running toolset
  are as before); a failed toolset is renamed and started once it validates, and one that lost its
  name to `giles.toml` leaves that toolset's globs alone; the case of a name changes. The rename
  tests (`rename/tests.rs`) cover the offline rename of a stored toolset: the row and the agents'
  globs; the refusals; the case of a name; a failure undone with the row put back exactly; and a run
  that stopped after the row finished by running it again.
- `crates/giles-core/tests/toolset_oauth.rs`, against a fake authorization server and an MCP server
  whose tools depend on the account: a user signs in, and their tokens are stored, used, refreshed,
  and deleted. With two users signed in, each is offered only the tools their own account lists, and
  no one else gets any. The dispatcher's tests cover calling a per-user toolset's tool, which the
  index doesn't list.
