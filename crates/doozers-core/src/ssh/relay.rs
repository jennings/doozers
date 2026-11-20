//! The relay tasks (issue #137): for each workspace on an environment that can relay, one task
//! that holds the environment's [`Environment::relay`] stream open and answers each client's agent
//! requests with an [`Agent`].
//!
//! [`Relays`] keeps at most one task per workspace id. [`Relays::ensure`] starts one if there is
//! none, if the last one ended (the plugin or the container restarted), or when told the workspace
//! was just started or recreated, which makes whatever the old task held stale. [`Relays::end`]
//! stops it. The task's per-connection state goes with the task, so it is dropped when the relay
//! ends and, one connection at a time, when the environment reports a client closed.
//!
//! A relay is opened for every workspace on a capable environment, whatever its key user: a
//! workspace without keys gets an agent that offers none.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use doozers_types::{
    AgentReply, Environment, RelayReply, RelayRequest, Result as EnvResult, UserId, WorkspaceId,
};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::SshKeys;
use super::agent::Agent;
use crate::sessions::Clock;

/// How long [`Relays::ensure`] waits for the environment to open the relay. A workspace is usable
/// without one, so a slow environment doesn't hold up the call that opened it for longer.
pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How many replies wait to be sent back to the environment.
const REPLY_QUEUE: usize = 16;

/// What the relay of one workspace is doing. The async lock is held while a relay is being
/// opened, so two calls never open two.
type Slot = Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>;

/// The relay tasks of every workspace. Dropping it ends them all.
pub(crate) struct Relays {
    keys: SshKeys,
    clock: Arc<dyn Clock>,
    slots: Mutex<HashMap<WorkspaceId, Slot>>,
}

impl Relays {
    /// Relays that answer from `keys` and stamp key use with `clock`.
    pub(crate) fn new(keys: SshKeys, clock: Arc<dyn Clock>) -> Self {
        Self {
            keys,
            clock,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, id: &WorkspaceId) -> Slot {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id.clone())
            .or_default()
            .clone()
    }

    /// Makes sure the relay of workspace `id` is running on `client`, whose workspace gets the
    /// keys of `user`. Starts one if none runs, or the last ended, or `restart` says the workspace
    /// was started or recreated since. A relay that can't be opened is logged and left for the
    /// next call: the workspace is usable without it.
    pub(crate) async fn ensure(
        &self,
        client: &Arc<dyn Environment>,
        id: &WorkspaceId,
        user: Option<&UserId>,
        restart: bool,
    ) {
        let slot = self.slot(id);
        let mut running = slot.lock().await;
        if let Some(task) = running.take() {
            if !restart && !task.is_finished() {
                *running = Some(task);
                return;
            }
            task.abort();
        }

        let (replies, outgoing) = mpsc::channel(REPLY_QUEUE);
        let opened = tokio::time::timeout(OPEN_TIMEOUT, client.relay(id, replies_stream(outgoing)))
            .await
            .unwrap_or_else(|_| {
                Err(doozers_types::Error::unavailable(
                    "the environment didn't open the relay in time",
                ))
            });
        let requests = match opened {
            Ok(requests) => requests,
            Err(error) => {
                warn!(workspace = %id, %error, "cannot open the SSH agent relay; it is tried again on the workspace's next use");
                return;
            }
        };
        let agent = Agent::new(
            self.keys.clone(),
            self.clock.clone(),
            id.clone(),
            user.cloned(),
        );
        debug!(workspace = %id, "opened the SSH agent relay");
        *running = Some(tokio::spawn(serve(agent, requests, replies)));
    }

    /// Ends the relay of workspace `id`, if one runs. The environment sees its streams end.
    pub(crate) async fn end(&self, id: &WorkspaceId) {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned();
        let Some(slot) = slot else { return };
        if let Some(task) = slot.lock().await.take() {
            task.abort();
            debug!(workspace = %id, "ended the SSH agent relay");
        }
        // Forget the slot unless a call that found it earlier is about to use it.
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if Arc::strong_count(&slot) == 2 {
            slots.remove(id);
        }
    }

    /// Whether workspace `id` has a relay that hasn't ended.
    #[cfg(test)]
    pub(crate) async fn running(&self, id: &WorkspaceId) -> bool {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned();
        match slot {
            Some(slot) => slot
                .lock()
                .await
                .as_ref()
                .is_some_and(|task| !task.is_finished()),
            None => false,
        }
    }
}

impl Drop for Relays {
    fn drop(&mut self) {
        let slots = std::mem::take(self.slots.get_mut().unwrap_or_else(PoisonError::into_inner));
        for slot in slots.into_values() {
            if let Ok(mut running) = slot.try_lock()
                && let Some(task) = running.take()
            {
                task.abort();
            }
        }
    }
}

/// `outgoing` as the stream the environment reads the core's replies from.
fn replies_stream(outgoing: mpsc::Receiver<RelayReply>) -> BoxStream<'static, RelayReply> {
    futures::stream::unfold(outgoing, |mut outgoing| async move {
        outgoing.recv().await.map(|reply| (reply, outgoing))
    })
    .boxed()
}

/// Answers `requests` until they end or the environment stops reading replies.
async fn serve(
    mut agent: Agent,
    mut requests: BoxStream<'static, EnvResult<RelayRequest>>,
    replies: mpsc::Sender<RelayReply>,
) {
    while let Some(request) = requests.next().await {
        match request {
            Ok(RelayRequest::Agent(request)) => {
                let message = agent.handle(request.connection, &request.message).await;
                let reply = RelayReply::Agent(AgentReply {
                    connection: request.connection,
                    message,
                });
                if replies.send(reply).await.is_err() {
                    break;
                }
            }
            Ok(RelayRequest::AgentClosed(closed)) => agent.close(closed.connection),
            Ok(_) => {}
            Err(error) => {
                debug!(%error, "the SSH agent relay failed");
                break;
            }
        }
    }
}
