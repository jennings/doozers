//! `doozers-channel-irc`: the Doozers IRC channel plugin. Doozers launches it (`socket`); an
//! operator can run it as a remote plugin (`serve`).

use std::io;
use std::process::ExitCode;

use doozers_plugin_sdk::ChannelPlugin;
use doozers_plugin_sdk::doozers_types::OutputMode;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_env("DOOZERS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    ChannelPlugin::new("irc", env!("CARGO_PKG_VERSION"))
        .output(OutputMode::Blocks)
        .can_initiate(true)
        .run(doozers_channel_irc::configure)
        .await
}
