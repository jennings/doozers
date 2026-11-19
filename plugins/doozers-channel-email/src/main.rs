//! `doozers-channel-email`: the Doozers email channel. Receives mail with IMAP IDLE, sends with
//! SMTP, and trusts a sender only as far as the receiving server's `Authentication-Results` vouch
//! for them. Doozers launches it (`socket`); an operator can run it as a remote plugin (`serve`).
//! See `Docs/user/email.md` and `Docs/technical/email.md`.

mod address;
mod auth_results;
mod channel;
mod config;
mod imap;
mod inbound;
mod media;
mod net;
mod outbound;
mod smtp;
mod state;
#[cfg(test)]
mod testing;

use std::io;
use std::process::ExitCode;

use doozers_plugin_sdk::ChannelPlugin;
use doozers_plugin_sdk::doozers_types::OutputMode;
use tracing_subscriber::EnvFilter;

use crate::channel::EmailChannel;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_env("DOOZERS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    ChannelPlugin::new("email", env!("CARGO_PKG_VERSION"))
        .output(OutputMode::Blocks)
        .can_initiate(true)
        .run(EmailChannel::configure)
        .await
}
