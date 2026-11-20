# Docker environment

The design of `doozers-environment-docker`, the first environment plugin (issue #25, built in
issue #90). It runs each workspace as a container plus a named volume, through the Docker Engine
API, and serves `doozers.environment.v1` on the plugin SDK ([Plugin SDK](plugin-sdk.md)).
User-facing setup and settings are in [Docker environment](../user/docker-environment.md).

The crate is a library with a thin binary. `DockerEnvironment` implements
`doozers_types::Environment` directly, so the SDK serves it with no adapter. `main` calls
`EnvironmentPlugin::run`, which gives the plugin both launched mode (`socket`) and remote mode
(`serve`), and parses the `config` of the instance with `Config` (`deny_unknown_fields`). Its
settings come from `[environment.<name>.config]` when launched, and from the `[config]` table of the
`serve --config` file when remote.

The Engine API client is `bollard`, over the unix socket only (`pipe` feature, no TLS stack). It is
the one place the engine is named: `socket`, else the `unix://` path in `DOCKER_HOST`, else
`/var/run/docker.sock`. A launched plugin gets the sandbox's cleaned-up environment, so only `serve`
ever sees `DOCKER_HOST`. Docker, Podman's compatible API, Docker Desktop, OrbStack, and Colima all
answer the calls the plugin makes. The integration tests run on rootless Podman.

## State lives in labels

The plugin keeps nothing of its own, not even in its data directory. A restart, or a new plugin
process on the same engine, finds every workspace again from labels:

| Label | On | Meaning |
| --- | --- | --- |
| `doozers.instance` | volume, container | The `[environment.<name>]` instance, so two instances on one engine never see each other's workspaces |
| `doozers.workspace` | volume, container | The workspace id the core chose |
| `doozers.image` | volume, container | The image as requested, normalized (`docker.io/library/ubuntu:24.04`) |
| `doozers.image-digest` | volume, container | What the container is created from: the repository digest, or the image ID for an image with none (a local build) |
| `doozers.image-id` | volume, container | The image ID at creation, which image removal uses |
| `doozers.pulled` | volume, container | `true` if this plugin pulled the image |
| `doozers.created` | volume, container | Creation time, RFC 3339 |

The volume is the source of truth, because it outlives the container: `list_workspaces` lists the
instance's volumes and pairs each with its container, if there is one. A volume without a container
is a stopped workspace that `start_workspace` can recreate. A container without a volume is never
listed as a workspace.

The volume and container are both named `doozers-<instance>.<id>`. Ids contain no `.`, so the last
`.` separates the id and two instances can't produce the same name. Everything else is found by
label, never by name, and a result is checked against the labels again after the engine's filter.

Per-workspace calls hold an in-memory lock on the id (`start_workspace` takes it only when the
container isn't already running). It keeps two concurrent calls from both recreating a container,
and holds no state that matters after a restart.

## Creating a workspace

`create_workspace` takes `{ "image": "..." }` and nothing else (`deny_unknown_fields`, and the
schema says `additionalProperties: false`). It runs these steps and removes whatever it made if one
fails:

1. Parse the image and check the allowlist ([Images](#images)). A refusal lists the patterns.
2. Refuse an id that is in use with `InvalidRequest`, which is how the `Environment` trait reports
   what the protocol calls `ALREADY_EXISTS`.
3. Find the image on the engine, or pull it with the registry's credentials, then record its pinned
   name and ID.
4. Create the volume with the labels.
5. Create the container: `Init: true`, user `0`, working directory `/workspace`, the volume bound at
   `/workspace`, `HOME=/workspace/.home` and the configured `env`, the configured memory, CPU, and
   process limits, and the configured network. The model sets nothing else: there are no mounts,
   capabilities, devices, or privileged mode, and nothing is read from the options.
6. Copy the helper in with an archive upload, start the container, and run
   `mkdir -p /workspace/.home`. The `mkdir` is also the first use of `/bin/sh`, so an image without
   one fails here with `InvalidRequest`.

The container runs as root. On a rootless engine that is an unprivileged user on the host, and it
lets the model install packages and always own the volume, whatever user the image sets. The
entrypoint is the helper's `idle` subcommand, so the container stays up on any image, including one
whose own command exits at once. `Init: true` puts the engine's init process in front of it to reap
orphans.

## Start, stop, delete, list

`start_workspace` handles four cases:

- A running container is `Running`, after one list call and no lock.
- A stopped container is started, or resumed if paused: `Started`, with a detail that processes have
  ended and files and packages are intact.
- No container but a volume: the container is recreated from the pinned image. If the image is gone
  from the engine, it is pulled again by digest. An image with no repository digest can't be pulled
  again, and the error says so. `Recreated` has a detail that files under `/workspace` are intact
  and anything installed elsewhere is gone.
- Neither is `NotFound`.

`stop_workspace` stops the container with a five second grace period and succeeds if it already is.
The helper's `idle` process has no signal handlers, so SIGTERM ends it at once.

`delete_workspace` removes the container (with its anonymous volumes), then the volume, then
[removes the image if it can](#removing-images). Each step ignores a missing resource, so a delete
that failed halfway can be repeated.

`list_workspaces` reports state from the container, the volume's size from the engine's disk usage
report, and the free space where volumes live. The Engine API has no call for free space, so the
plugin runs the helper's `df /workspace` in a running workspace and reports `None` when none is
running.

The disk usage report (`GET /system/df`) has two shapes. From API 1.52 (Docker 29) the volumes are
in `VolumeUsage.Items`, and only when the request sets `verbose`. Older engines list them in a
top-level `Volumes` array, which bollard's model has no field for. So `disk_usage.rs` requests
`/v<negotiated>/system/df?verbose=1` itself, with hyper over the engine socket, and reads either
shape from the JSON. A failed request is logged, and every size is then `None`.

Each workspace also carries `details` for [the workspaces page](web-channel.md#workspaces-page), in
this order: **Image** (the requested reference), **Image digest** (the pinned one, when there is
one), **Container** (the name, and the first 12 characters of the engine's id, or a note that the
container is recreated on the next use), **Volume** (its name), and **Limits** (the memory, CPUs,
and processes configured now, or `none`). The limits are the plugin's settings, which new and
recreated containers get, not read back from the container.

## Images

The allowlist and the reference parser are pure functions in `image.rs`.

A reference normalizes the way Docker's does:

- The registry defaults to `docker.io`, and `index.docker.io` and its aliases fold into it.
- A single-component Docker Hub name is under `library/`.
- The first component is a registry only if it contains `.` or `:` or is `localhost`.
- The tag defaults to `latest`, unless there is a digest.

A pattern uses the same syntax and normalization. A `*` is accepted only as the whole tag, and a
pattern can't pin a digest. A reference pinned by digest (`name@sha256:...`) matches a pattern whose
tag is `*` and no other, because a digest can't be compared with a tag, even if the reference also
names one. The built-in list is `ubuntu`, `debian`, `alpine`, `python`, `node`, `golang`, `rust`,
`ruby`, and `eclipse-temurin`, each with `*`. `default_images = false` drops it.

The workspace pins the image when it is created. The pinned name is the repository digest the engine
lists for the requested repository (Docker lists Hub images without the `docker.io/library/`
defaults and Podman with them, so both sides are normalized before comparing), or the image ID. A
recreated container starts from that, so a moving tag such as `latest` can't change the software
under the agent in the middle of a conversation.

### Removing images

An image is removed after a delete only if all of these hold:

- The workspace's `doozers.pulled` is `true`. A workspace created from an image that an earlier
  workspace of the same instance pulled inherits `true`, so the last one out removes it.
- No remaining volume of the instance records the same image ID.
- The engine allows it. Removal is by image ID without `force`, so the engine refuses an image that
  a container (of anything) uses or that has other names, and the plugin leaves it.

An image that was already on the engine is never removed, and neither is one pulled by another
instance. A failed create removes the image that attempt pulled by the same rule.

## The helper

`doozers-workspace-helper` (crate `crates/doozers-workspace-helper`) is a small static Linux binary
that the plugin copies to `/.doozers/bin/doozers-workspace-helper` in every container. Its name
doesn't start with `doozers-environment-`, which would make plugin discovery treat it as a plugin.
It has no async runtime. It exists because the container can't be assumed to have anything but
`/bin/sh`, and because the Engine API can't kill an exec.

| Subcommand | Purpose |
| --- | --- |
| `idle` | The container's main process |
| `run --id ID -- CMD...` | The process-group wrapper |
| `kill --id ID` | Kill the group of `run --id ID` |
| `find`, `grep` | Search with `globset`, `ignore`, and `regex`; JSON lines out, ending in `{"truncated":bool}` |
| `read`, `write` | Whole-file access; `read` prints `{"size":N}` and then up to `--max` bytes |
| `df` | Free bytes where a path lives |
| `ssh-agent [--socket PATH]` | Serve `SSH_AUTH_SOCK` and a second socket for `known-hosts`, and carry their messages over standard input and output as [frames](#the-ssh-agent-relay) |
| `known-hosts [--socket PATH] HOST PORT TYPE KEY` | `ssh`'s `KnownHostsCommand`: ask the core, through the second socket, which host keys it trusts, and print them as `known_hosts` lines |

`find` and `grep` walk with `ignore` configured to skip `.git` and honor `.gitignore` files whether
or not a `.git` exists, include dotfiles, and sort the paths as strings so the order doesn't depend
on directory layout. `grep` skips files with a NUL byte in the first 8 KiB. Failures print a message
on standard error and exit 1, or 66 for a missing path, and the plugin turns those into
`InvalidRequest` and `NotFound`. `write` reads all of standard input before it opens the file, so a
broken transfer doesn't truncate it, and it opens the existing file in place, which keeps its
permissions.

### Finding and shipping the helper

The helper is built for the engine's architecture, which can differ from the plugin's (a plugin on
macOS driving a Linux VM). At connect time the plugin reads the engine's `info.Architecture`, maps
`amd64` and `x86_64` to `x86_64` and `arm64` and `aarch64` to `aarch64`, and loads
`<helper_dir>/doozers-workspace-helper-<arch>`, where `helper_dir` defaults to the directory of the
plugin's own executable. A missing file fails the plugin's configure step, with a message that names
the path and the `cargo build --target <arch>-unknown-linux-musl` command that makes it.

The linker for the musl targets is `rust-lld` (`.cargo/config.toml`), and both targets are in
`rust-toolchain.toml`, so the cross build needs no C toolchain. The
[container image](container-image.md) builds the helper for its own architecture and installs it
next to the plugin. The archive upload that copies it into a container also creates `/.doozers/run`
with mode 1777, so a command that runs as another user can still record its group.

## Running commands

Every command runs as one exec of
`/.doozers/bin/doozers-workspace-helper run --id <uuid> -- /bin/sh -c <command>`, in `/workspace`,
with no TTY and standard input closed. The id is a fresh UUID, not the engine's exec id, because the
plugin needs it before the exec exists.

`run` starts the command in a new process group and writes the group id to `/.doozers/run/<id>`. It
gives the command's output pipes to itself and copies them to its own standard output and standard
error, which the engine multiplexes back to the plugin. It exits with the command's status, or 128 +
N when signal N ended it, and removes its record. It doesn't wait for background processes that
still hold the output pipes, because it stops reading once the command has exited and the pipes are
empty: `sleep 300 &` in a command doesn't hold the call open. Those processes keep running, which is
how a model starts a server.

### Cancelling

The Engine API has no call that kills an exec, so cancellation is a second exec, `kill --id <uuid>`,
which sends SIGKILL to the group recorded for that id. Anything that stayed in the group dies, and
`run` reports 137. A process that moved itself to another group or session with `setsid` escapes,
and so does one that was already running before the command, such as a daemon.

Two things trigger a kill:

- The timeout. The plugin runs `kill`, marks the exit `timed_out`, and keeps draining output for up
  to ten seconds. The exit code is whatever the engine recorded, normally 137.
- Dropping the stream, or the future that creates it. A guard that is armed before the first request
  goes out spawns the kill when it drops, unless the exit event was already produced, so cancelling
  at any point in the setup still kills the command.

`kill` can run before `run` has recorded the group: the cancellation arrives while the exec is still
starting. `run` writes its record first and then looks for a marker file `<id>.kill`, and `kill`
looks for the record and, if there is none, writes the marker and looks again. Each side writes
before it reads, so at least one sees the other. If `kill` sees the record the second time it
removes its marker, and if `run` sees the marker it kills its own group at once. A `kill` for a
command that already finished leaves a marker nothing reads, a few bytes in the container's writable
layer, which is why the plugin only kills a command whose exit it hasn't produced.

### Output limit and exit status

The plugin forwards output pieces as they arrive. It counts the bytes of standard output and
standard error together, sends up to `output_limit`, and reports the rest as `dropped_bytes` in the
exit event, which is always the last event. The exit code comes from inspecting the exec after the
output ends. The engine can take a moment to record it, so the plugin polls for up to five seconds.
A zero timeout is `InvalidRequest`.

## Files

`read_file`, `write_file`, `find`, and `grep` are helper calls under the same wrapper with a 60
second timeout, so a runaway search is killed like a command. File content goes through standard
input and output, not the Engine API's archive calls, because the helper handles symlinks, modes,
and missing parent directories the same way for every image and the archive API doesn't. A path that
starts with `-` gets a `./` prefix so the helper never reads it as a flag. Relative paths need no
handling, because every exec starts in `/workspace`.

## The ssh-agent relay

The plugin declares the `ssh_relay` capability, and each workspace has an ssh-agent socket. The
container environment sets `SSH_AUTH_SOCK=/.doozers/run/ssh-agent.sock` at creation, and every exec
gets it too, so workspaces created before the relay existed have it as well. The plugin doesn't let
`[env]` set it.

`relay(id, replies)` needs a running container (`NotFound` if the workspace doesn't exist,
`InvalidRequest` if it is stopped). A workspace created before the relay existed has a helper
without the `ssh-agent` subcommand, and starting a container doesn't copy the helper again. So
before the first relay of a container in a plugin process, the plugin uploads its own helper under a
temporary name in `/.doozers/bin` and renames it over `/.doozers/bin/doozers-workspace-helper`. A
rename doesn't hit "text file busy" the way overwriting would, because the container's `idle`
process is running the old file, and commands that are running keep the old file open. The plugin
remembers the container id in memory, so each relay after that skips the upload, and a plugin
restart does it once more.

The plugin then starts one exec of `/.doozers/bin/doozers-workspace-helper ssh-agent`, without the
`run` wrapper, with standard input, output, and error attached. The helper listens on the socket
with mode 0666, because everything in the container may use the agent anyway and a command can run
as another user. It removes a stale socket file first. One thread reads each client connection's
requests and another writes its replies from a queue of 8, one thread accepts connections, and the
main thread reads replies from standard input and queues them. A client that doesn't read its
replies fills its queue and is closed, so it can't hold up the replies of other clients. When
standard input ends the helper removes its socket and exits.

The same process listens on a second socket, `/.doozers/run/known-hosts.sock` (mode 0666, stale file
removed first), which the `known-hosts` subcommand uses. Each connection to it is one lookup of the
host keys `ssh` trusts, and the helper carries it to the plugin as a kind 4 frame and back as a kind
5 frame. [SSH](ssh.md#known-hosts) says what the core answers.

The plugin sends the helper's frames on as `RelayRequest`s and writes the core's replies to the
helper as frames. Dropping the stream the plugin returns, or the core ending its replies, closes the
helper's standard input, which ends the exec. The stream ends when the exec does, for example when
the workspace stops. Lines the helper writes to standard error are logged at `debug`.

Both directions use one frame format:

```text
u32 BE length of the rest | u8 kind | u64 BE connection | payload
```

| Kind | Direction | Meaning |
| --- | --- | --- |
| 1 | helper to plugin | A request: the payload is one agent message without its own length prefix |
| 2 | helper to plugin | The connection ended; no payload |
| 3 | plugin to helper | A reply: the payload is one agent message for the connection |
| 4 | helper to plugin | A known-hosts lookup: `connection` names the lookup and the payload is the request below |
| 5 | plugin to helper | The answer to lookup `connection`: the payload is the answer below |

The length counts the kind, the connection id, and the payload. An agent message is at most 256 KiB
(OpenSSH's limit), and a client that sends a longer one is disconnected. A frame of an unknown kind
is skipped by both sides. The helper numbers connections from 1 and never reuses a number, and
numbers lookups in a separate series. The helper and the plugin each have their own encoder and
decoder, because the helper is a static binary with no dependencies, and each has tests for the
format.

The payload of a lookup and its answer are the `known-hosts` command's request and answer on the
socket, which the helper doesn't look inside:

```text
request: u32 BE port | string host | string key type | string key
answer:  u32 BE count | count * string key
string:  u32 BE length | bytes
```

The key type and the key are empty strings when `ssh` only asks for the stored keys (it passes the
literal `NONE` for `%t` and `%K`). The keys of an answer are SSH public key blobs. The plugin turns
a kind 4 frame into a `KnownHostsRequest` and the core's `KnownHostsReply` into a kind 5 frame. A
frame is at most 2 MiB, and a request the plugin can't decode is answered with no key.

The helper holds at most 64 lookups waiting for the plugin and closes one that gets no answer in 60
seconds, which makes the command fail. A client of the socket has 10 seconds to send its request.
The command exits 1 with a message on standard error and prints nothing when the socket is missing,
the relay ends, or the answer isn't valid, so `ssh` refuses the connection. When the relay isn't
reachable, the message says that the Doozers relay isn't reachable at
`/.doozers/run/known-hosts.sock` and that the helper is refusing the connection. `ssh` then prints
`KnownHostsCommand ... failed, status 1` and `KnownHostsCommand failed`, and gives up before it
checks host keys.

## SSH configuration

`ssh` in a workspace has to ask the core which host keys to trust. The plugin writes
`/etc/ssh/ssh_config.d/doozers.conf` into the container, whose writable layer holds it, so the file
is written again whenever the container could have lost it:

```text
KnownHostsCommand /.doozers/bin/doozers-workspace-helper known-hosts %H %p %t %K
UserKnownHostsFile /dev/null
GlobalKnownHostsFile /dev/null
StrictHostKeyChecking yes
```

- **When.** When a container is created (`create_container`, which creation and recreation both
  use), at start when the container was started, and when the relay opens, which covers a workspace
  that was running before the plugin wrote the file. A failure when the relay opens is logged and
  the relay goes on.
- **The `Include` line.** `ssh` reads `ssh_config.d` only if `/etc/ssh/ssh_config` includes it. The
  `openssh-client` packages of Debian, Ubuntu, Alpine, and Fedora do (checked for Alpine 3.20). If
  the file exists and has no `Include` of that directory, the plugin puts
  `Include /etc/ssh/ssh_config.d/*.conf` at its top, so it applies to every host. The plugin never
  creates `ssh_config`.
- **Options.** `UserKnownHostsFile` and `GlobalKnownHostsFile` are `/dev/null`, so a file in the
  workspace can't add trust, and `StrictHostKeyChecking yes` makes `ssh` refuse a host that the
  command returns no key for, without asking anyone.
- **OpenSSH 8.5.** `KnownHostsCommand` is new in 8.5. An older `ssh` rejects the file, so it can't
  connect at all.

The file is a default for the model's commands. Anyone in the workspace can override it with `-o`
options, or root can edit it, but that only changes what that `ssh` trusts. The core records a new
host only after its own scan, whatever the workspace sends.

## Host key scans

`scan_host_key(id, host, port, key_type)` fetches a server's host key as `ssh-keyscan` would, with
the SDK's `scan_host_key` and a 10 second timeout, from the machine the plugin runs on. It first
checks that the workspace exists and is running (`NotFound` if it doesn't exist, `InvalidRequest` if
it is stopped). A failed scan is `Unavailable` and says what failed, and a key type the scan doesn't
support is `InvalidRequest`.

The scan deliberately isn't made from inside the workspace. A workspace's root can rewrite
`/etc/hosts` or `/etc/resolv.conf`, so a scan through them would confirm whatever fake key the
workspace was offered for `github.com`, and the core would record it for every workspace of the
instance. From the plugin's network the workspace can't influence the scan.

A host that only the workspace's container network reaches, such as another container or a private
server, can't be scanned from the plugin's machine. Its first connection is refused with
`Host key verification failed` and nothing is recorded, until an admin pins its key on the Known SSH
hosts page ([SSH](ssh.md#admin-page-and-pinning)).

## Tests

The unit tests cover the reference parser, the allowlist, the configuration, the helper archive, and
the helper's output parsing. `crates/doozers-workspace-helper/tests/cli.rs` runs the helper binary
on the host. The integration tests in `plugins/doozers-environment-docker/tests/` run against a real
Docker API socket: `docker.rs` calls `DockerEnvironment` directly, and `serve.rs` runs the binary
with `serve --config` and drives it over gRPC. `relay.rs` opens the relay on `DockerEnvironment`
with the test standing in for the core, installs `openssh-client` in an Alpine workspace (it skips,
saying why, if that can't reach the network), and runs `ssh-add -L` against an answer the test
builds. It also swaps the container's helper for a stand-in without `ssh-agent`, to show that the
relay replaces it first. `ssh.rs` answers the relay with the core's own agent
(`doozers_core::ssh::Agent`, so the plugin has `doozers-core` as a dev-dependency) over keys in a
real secret store. It runs `ssh-keygen -Y sign` and `-Y verify` through the socket for Ed25519,
ECDSA, and RSA keys, checks that no private key text is in the container's files or configuration,
and logs in with `ssh` to an `sshd` in a second container on the engine's default network, which
also shows a forwarded agent getting no keys. `known_hosts.rs` runs `ssh` in workspaces against the
core's own `KnownHosts` over a real store. It covers these cases:

- a first use that is recorded and then used by a second workspace
- a changed host key refused with `REMOTE HOST IDENTIFICATION HAS CHANGED`, and trusted again after
  the host is deleted
- a pinned key, and a wrong pin
- a key that differs from the plugin's scan, which isn't recorded
- failing closed with no relay (`KnownHostsCommand failed`)
- `ssh_config.d` inclusion on Debian, Ubuntu, Alpine, and Fedora

It also tests the scan against an `sshd` port the test publishes, next to the SDK's own `sshd`
tests. A step that needs the network (the image, installing `openssh-client` or `sshd`) skips,
printing why, when it fails, unless `DOOZERS_REQUIRE_DOCKER=1` is set: the harness has pulled its
image by then, so a failure is real. They skip, printing why, when no socket answers
(`DOOZERS_REQUIRE_DOCKER=1` makes that a failure, as in [CI](ci.md)). The helper comes from
`DOOZERS_HELPER_DIR` or is cross-built for the engine's architecture.
