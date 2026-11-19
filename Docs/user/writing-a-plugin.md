# Writing a plugin

This page shows how to write a channel plugin in Rust with the `doozers-plugin-sdk` crate.

Channels other than the built-in web chat are plugins. A channel plugin is a binary named
`doozers-channel-<name>`, found in `<DOOZERS_HOME>/plugins/` or on `PATH`. Doozers starts one
process for each configured instance.

Model providers are built in for now. Toolsets are ordinary MCP servers and need no SDK.

## What Doozers does for you

Doozers starts the plugin in a sandbox. The only directory it can write to is the instance's data
directory, `<DOOZERS_HOME>/data/channel/<instance>/`.

Doozers sends the plugin the instance's `config` table with secrets already filled in. A plugin
never reads `doozers.toml` or `secrets.toml`, and never listens on a socket.

The SDK handles the connection to Doozers. You write a type that implements the `Channel` trait from
`doozers-types`. It says what the channel can do, produces inbound events, takes acks, and sends
messages.

## A minimal channel

`Cargo.toml`:

```toml
[package]
name = "doozers-channel-example"
version = "0.1.0"
edition = "2024"

[dependencies]
futures = "0.3"
doozers-plugin-sdk = "0.1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

`src/main.rs`:

```rust
use std::process::ExitCode;

use futures::stream::{self, BoxStream, StreamExt as _};
use doozers_plugin_sdk::doozers_types::{
    Channel, ChannelEvent, ChannelInfo, EventId, MessageId, OutboundMessage, OutputMode, Result,
};
use doozers_plugin_sdk::{ChannelPlugin, Configure, async_trait};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server: String,
}

struct Example {
    info: ChannelInfo,
}

#[async_trait]
impl Channel for Example {
    fn info(&self) -> &ChannelInfo {
        &self.info
    }

    async fn events(&self) -> Result<BoxStream<'static, Result<ChannelEvent>>> {
        Ok(stream::pending().boxed()) // connect and yield inbound messages here
    }

    async fn ack(&self, _event: &EventId) -> Result<()> {
        Ok(())
    }

    async fn send(&self, msg: OutboundMessage) -> Result<MessageId> {
        // render msg.markdown for the service and deliver it
        Ok(MessageId::new("1")?)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    ChannelPlugin::new("example", env!("CARGO_PKG_VERSION"))
        .output(OutputMode::Blocks)
        .run(|ctx: Configure| async move {
            let config: Config = ctx.parse_config()?;
            Ok(Example {
                info: ChannelInfo {
                    identity_namespace: format!("example:{}", config.server),
                    output: OutputMode::Blocks,
                    can_initiate: false,
                },
            })
        })
        .await
}
```

Install the binary where Doozers finds it and configure an instance:

```toml
[channel.home]
component = "example"
config = { server = "chat.example.com" }
```

`run` gives the binary two subcommands. Doozers launches it with `socket`; run by hand, that only
says that it's a Doozers plugin and exits. An operator can also run it as a
[remote plugin](remote-plugins.md) with `serve`.

## The pieces

`ChannelPlugin::new(name, version)` describes the plugin. `name` is the `<name>` in
`doozers-channel-<name>`. Its builder methods are:

- `output`: `Blocks` for chat services without message edits, `Deltas` for live streaming. For now,
  plugin channels get `blocks` output either way, and only the built-in web channel streams.
- `can_initiate`: whether the channel can message an identity that hasn't written first. Scheduled
  jobs and login codes need it.
- `requested_grants`: sandbox grants to suggest to the operator. They're shown in `doozers status`
  and never applied by themselves.

Call `run(configure)` first thing in `main` and return its exit code. `configure` runs when Doozers
sends the instance config.

For a bad config, return `Error::InvalidRequest`. Doozers shows the message and doesn't start the
instance. `ctx.parse_config()` does this for you, naming the offending key.

The identity namespace your channel reports must be the plugin's name, or the name, a colon, and
more. For example, `irc` or `irc:libera.chat`, but not `ircx`. Each `:`-separated part must be
non-empty, without spaces. Instances in the same namespace share identities.

Keep your state, such as session files and cursors, in `ctx.data_dir()`. It's the instance's own
directory, kept across restarts and upgrades. The `doozers-sdk/` subdirectory belongs to the SDK.

## Inbound events

Give each event an id that is unique within the instance. Where the service allows, make it the same
after a restart by using the service's message id instead of a counter. Doozers drops repeats by id,
so a message never reaches a conversation twice.

You don't need to store events yourself. The SDK writes each event to the data directory before
sending it to Doozers, and sends it again until Doozers acks it, even after your plugin crashed.

The SDK stores an event before it asks your stream for the next one. Once your stream is polled
again, you may forget the previous event. A source that can replay, such as an IMAP mailbox, can
instead keep a cursor and advance it in `ack`.

Report the connection's state with `ChannelEvent::Status`:

- `Connected`
- `Error`
- `NeedsAuth`, with a QR code, pair code, or URL that `doozers status` and the admin pages show to
  the operator

## Attachments

To receive an attachment, store its bytes with `ctx.blobs().put(bytes, media_type, name)` or
`put_reader` before emitting the event. Put the returned `MediaRef` in the message's `attachments`.

Only put blobs you emit. One that's never sent is deleted at the plugin's next start.

In `send`, read the outbound message's attachments with `blobs.read(&media)`, `open`, or `path`.
They're only valid until `send` returns.

## Sending

`send` gets the reply as CommonMark. The SDK's `render` module converts it for the service:

- `render::html`
- `render::plain_text`
- `render::irc`, split into lines that fit
- `render::whatsapp`
- `render::discord`, split into messages that fit

If a recipient can't be reached right now, such as an IRC account that isn't online, return
`Error::Unavailable`. Doozers retries later.

## TLS

For outgoing TLS connections, use the SDK's `tls` module, which is on by default. Its `rustls`
client settings trust the Mozilla root certificates built into the binary, so connections work the
same inside the sandbox on every host.

## Lifecycle

When Doozers stops the plugin, the SDK lets open calls finish for a few seconds and returns from
`run`. It also returns when Doozers itself goes away, so a plugin never outlives the daemon.

A plugin that is killed loses nothing. Events not yet acknowledged are already on disk.

## Logging

Log to stderr, for example with `tracing-subscriber`. Doozers logs each line under the instance's
name and discards anything written to stdout. A line that starts with a timestamp and a level, as
`tracing-subscriber` writes them, is logged at that level. Any other line is logged at `info`.

## Running a plugin remotely

The same channel can run on another machine. You start it yourself, and Doozers connects to it over
the network as a [remote plugin](configuration.md#remote-plugins).

A plugin built with `run` already does this: `doozers-channel-example serve` takes its listen
address, data directory, TLS files, and token from flags or a file, as
[Running a plugin on another machine](remote-plugins.md) describes. The plugin's own settings still
come from the instance's `config` in `doozers.toml`.

For your own command line, call `serve_remote` instead of `run`. The rest of `src/main.rs` stays as
above, and `tokio` needs its `net` feature:

```rust
use doozers_plugin_sdk::{RemoteAuth, RemoteServer, tls};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let token = std::env::var("EXAMPLE_TOKEN").map_err(std::io::Error::other)?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:7443").await?;
    let server = RemoteServer::new(listener, "/var/lib/doozers-example", RemoteAuth::Bearer(token))
        .tls(tls::server_config(
            &std::fs::read("/etc/doozers-example/fullchain.pem")?,
            &std::fs::read("/etc/doozers-example/key.pem")?,
        )?);
    ChannelPlugin::new("example", env!("CARGO_PKG_VERSION"))
        .output(OutputMode::Blocks)
        .serve_remote(server, |ctx: Configure| async move {
            let config: Config = ctx.parse_config()?;
            Ok(Example {
                info: ChannelInfo {
                    identity_namespace: format!("example:{}", config.server),
                    output: OutputMode::Blocks,
                    can_initiate: false,
                },
            })
        })
        .await
}
```

The directory you pass is the plugin's data directory (`ctx.data_dir()`). It's created if it doesn't
exist.

Choose how the plugin checks Doozers' calls:

- `RemoteAuth::Bearer(token)` accepts only calls carrying the token from the instance's
  `auth = { bearer = ... }`.
- With `auth = { oauth = ... }`, Doozers gets access tokens from your OAuth server. Check them with
  `RemoteAuth::verify(|token| ...)`, by signature or introspection. It runs on every call, so cache
  slow checks.
- `RemoteAuth::None` accepts anyone who can reach the port.

`.tls(...)` takes your certificate chain and key in PEM. Doozers checks the certificate against the
public Mozilla roots and the host name in `address`, so use a certificate from a public CA, such as
Let's Encrypt. Without TLS, Doozers only connects to an address on its own machine, unless the
instance sets `insecure = true`.

Doozers connects at its startup and again after a lost connection. It calls `configure` only the
first time, and the channel you built stays. Restart the plugin to change its config. Events not yet
acknowledged wait in the data directory for the next connection.

The plugin runs until it gets `SIGINT` or `SIGTERM`, or the future given to `shutdown_on` completes.
Doozers never stops it.
