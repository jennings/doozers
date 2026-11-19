//! `doozers-channel-discord`: the Doozers Discord channel plugin. Doozers launches it (`socket`);
//! an operator can run it as a remote plugin (`serve`). See `Docs/technical/discord.md`.

use std::io;
use std::process::ExitCode;

use doozers_channel_discord::channel::{self, SessionSlot};
use doozers_plugin_sdk::ChannelPlugin;
use doozers_plugin_sdk::doozers_types::OutputMode;
use tracing_subscriber::EnvFilter;

/// The log filter when `DOOZERS_LOG` isn't set. The libraries' own logs are for their authors: only
/// problems show unless asked for.
const DEFAULT_LOG: &str = "warn,doozers_channel_discord=info,doozers_plugin_sdk=info";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_env("DOOZERS_LOG").unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG)),
        )
        .init();
    // The SDK owns the channel, so the session is reached through a slot `configure` fills: after
    // `run` returns, the Gateway is closed (the bot goes offline at once) before exiting.
    let slot = SessionSlot::default();
    let configure_slot = slot.clone();
    let code = ChannelPlugin::new("discord", env!("CARGO_PKG_VERSION"))
        .output(OutputMode::Blocks)
        .can_initiate(true)
        .run(move |ctx| {
            let slot = configure_slot.clone();
            async move { channel::configure(ctx, &slot).await }
        })
        .await;
    slot.shutdown(channel::shutdown_wait()).await;
    code
}
