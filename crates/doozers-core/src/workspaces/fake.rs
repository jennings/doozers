//! An in-process [`Environment`] and a manual clock for tests of the workspace service and of
//! the code that calls it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use doozers_types::{
    Environment, EnvironmentInfo, Error, ExecEvent, ExecRequest, FindRequest, FindResult,
    GrepMatch, GrepRequest, GrepResult, ReadFile, RelayReply, RelayRequest, Result, StartOutcome,
    Timestamp, Workspace, WorkspaceDetail, WorkspaceId, WorkspaceList,
    WorkspaceState as PluginState,
};
use futures::StreamExt as _;
use futures::stream::{self, BoxStream};
use serde_json::{Value, json};

use crate::sessions::Clock;

/// The time tests start at.
pub(crate) const START: &str = "2026-11-10T12:00:00Z";

/// A clock that moves only when told to.
pub(crate) struct TestClock(Mutex<Timestamp>);

impl TestClock {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(START.parse().unwrap())))
    }

    pub(crate) fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.checked_add(by).unwrap();
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One workspace the fake holds.
#[derive(Debug, Clone)]
pub(crate) struct Held {
    pub(crate) running: bool,
    pub(crate) created_at: Timestamp,
    pub(crate) options: Value,
}

#[derive(Default)]
struct State {
    workspaces: BTreeMap<WorkspaceId, Held>,
    /// Every call that changed something, as `<call> <id>`.
    log: Vec<String>,
    /// The next `create_workspace` fails with this, after leaving `partial` behind if set.
    create_error: Option<Error>,
    partial: bool,
    /// `delete_workspace` and `list_workspaces` fail while set.
    delete_fails: bool,
    list_fails: bool,
    /// What `list_workspaces` reports for free space and for each workspace's disk use.
    free_bytes: Option<u64>,
    disk_used: Option<u64>,
    /// The details of every workspace; the default is one `Box: fake` row.
    details: Option<Vec<WorkspaceDetail>>,
    /// The next `start_workspace` of a stopped workspace says it recreated it.
    recreate: bool,
    /// What `exec` does; `Exec::Refuse` until a test sets it.
    exec: Exec,
    /// Every `exec` request, in order.
    execs: Vec<ExecRequest>,
    /// Files by workspace and path as the caller wrote it (the fake doesn't resolve paths).
    files: BTreeMap<(WorkspaceId, String), Vec<u8>>,
    /// The `max_bytes` of every `read_file`.
    reads: Vec<u64>,
    /// How many times `relay` was called, and the latest relay of each workspace.
    relay_calls: usize,
    relays: BTreeMap<WorkspaceId, FakeRelay>,
    /// `relay` fails while set.
    relay_fails: bool,
    /// What `scan_host_key` returns for a host and port; a host not set here is unreachable.
    scan_results: BTreeMap<(String, u16), Scan>,
    /// Every `scan_host_key` call: workspace, host, port, key type.
    scans: Vec<(WorkspaceId, String, u16, String)>,
}

/// What a fake `scan_host_key` does for one host and port.
#[derive(Clone)]
pub(crate) enum Scan {
    /// Returns this key.
    Key(Vec<u8>),
    /// Waits for the notification, then returns this key.
    Gated(Arc<tokio::sync::Notify>, Vec<u8>),
}

/// The fake's end of a relay the core opened.
struct FakeRelay {
    /// Requests for the core. Dropping this ends the relay as a plugin would.
    requests: futures::channel::mpsc::UnboundedSender<Result<RelayRequest>>,
    /// What the core replied.
    replies: Arc<tokio::sync::Mutex<futures::channel::mpsc::UnboundedReceiver<RelayReply>>>,
    /// Set when the core drops the request stream: it ended the relay.
    closed: Arc<AtomicBool>,
}

/// What a fake `exec` does.
#[derive(Clone, Default)]
pub(crate) enum Exec {
    /// Fails the call as not supported.
    #[default]
    Refuse,
    /// Yields these events.
    Events(Vec<ExecEvent>),
    /// Yields one piece of stdout, `started`, and then never ends. Dropping the stream sets the
    /// flag.
    Hang(Arc<AtomicBool>),
}

/// An environment that keeps its workspaces in memory.
pub(crate) struct Fake {
    state: Mutex<State>,
    clock: Arc<TestClock>,
    /// How many relay request streams the core has dropped.
    relays_dropped: Arc<AtomicUsize>,
}

impl Fake {
    pub(crate) fn new(clock: Arc<TestClock>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            clock,
            relays_dropped: Arc::default(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Puts a workspace there as if made outside Doozers, `age` ago.
    pub(crate) fn insert(&self, id: &str, age: Duration, running: bool) {
        let created_at = self.clock.now().checked_sub(age).unwrap();
        self.state().workspaces.insert(
            WorkspaceId::new(id).unwrap(),
            Held {
                running,
                created_at,
                options: json!({}),
            },
        );
    }

    pub(crate) fn remove(&self, id: &WorkspaceId) {
        self.state().workspaces.remove(id);
    }

    pub(crate) fn held(&self) -> BTreeMap<WorkspaceId, Held> {
        self.state().workspaces.clone()
    }

    pub(crate) fn has(&self, id: &WorkspaceId) -> bool {
        self.state().workspaces.contains_key(id)
    }

    pub(crate) fn running(&self, id: &WorkspaceId) -> Option<bool> {
        self.state().workspaces.get(id).map(|held| held.running)
    }

    /// The changing calls so far, e.g. `stop ws-1`.
    pub(crate) fn log(&self) -> Vec<String> {
        self.state().log.clone()
    }

    pub(crate) fn fail_next_create(&self, error: Error, leave_partial: bool) {
        let mut state = self.state();
        state.create_error = Some(error);
        state.partial = leave_partial;
    }

    pub(crate) fn fail_deletes(&self, fails: bool) {
        self.state().delete_fails = fails;
    }

    pub(crate) fn fail_lists(&self, fails: bool) {
        self.state().list_fails = fails;
    }

    /// What listing reports: free space, and the disk each workspace uses.
    pub(crate) fn report_space(&self, free_bytes: Option<u64>, disk_used: Option<u64>) {
        let mut state = self.state();
        state.free_bytes = free_bytes;
        state.disk_used = disk_used;
    }

    /// The details every listed workspace has.
    pub(crate) fn set_details(&self, details: Vec<WorkspaceDetail>) {
        self.state().details = Some(details);
    }

    pub(crate) fn recreate_next_start(&self) {
        self.state().recreate = true;
    }

    /// Makes every `exec` yield `events`.
    pub(crate) fn script_exec(&self, events: Vec<ExecEvent>) {
        self.state().exec = Exec::Events(events);
    }

    /// Makes every `exec` hang after one piece of output. The returned flag is set when the
    /// command's stream is dropped, as it is when the core cancels the command.
    pub(crate) fn hang_exec(&self) -> Arc<AtomicBool> {
        let dropped = Arc::new(AtomicBool::new(false));
        self.state().exec = Exec::Hang(dropped.clone());
        dropped
    }

    /// Every `exec` request so far.
    pub(crate) fn execs(&self) -> Vec<ExecRequest> {
        self.state().execs.clone()
    }

    /// Puts a file in a workspace.
    pub(crate) fn put_file(&self, id: &WorkspaceId, path: &str, content: &[u8]) {
        self.state()
            .files
            .insert((id.clone(), path.to_owned()), content.to_vec());
    }

    /// A file of a workspace.
    pub(crate) fn file(&self, id: &WorkspaceId, path: &str) -> Option<Vec<u8>> {
        self.state()
            .files
            .get(&(id.clone(), path.to_owned()))
            .cloned()
    }

    /// The `max_bytes` of every `read_file` so far.
    pub(crate) fn reads(&self) -> Vec<u64> {
        self.state().reads.clone()
    }

    /// How many times the core opened a relay.
    pub(crate) fn relay_calls(&self) -> usize {
        self.state().relay_calls
    }

    /// How many relay request streams the core has dropped, ending those relays.
    pub(crate) fn relays_dropped(&self) -> usize {
        self.relays_dropped.load(Ordering::SeqCst)
    }

    /// Makes `relay` fail (as an environment that can't start its helper) while `fails` is set.
    pub(crate) fn fail_relays(&self, fails: bool) {
        self.state().relay_fails = fails;
    }

    /// Whether the latest relay of `id` is open: opened, not ended by either side.
    pub(crate) fn relay_is_open(&self, id: &WorkspaceId) -> bool {
        self.state().relays.get(id).is_some_and(|relay| {
            !relay.closed.load(Ordering::SeqCst) && !relay.requests.is_closed()
        })
    }

    /// Makes `scan_host_key` of `host` and `port` do `scan`.
    pub(crate) fn scan_returns(&self, host: &str, port: u16, scan: Scan) {
        self.state()
            .scan_results
            .insert((host.to_owned(), port), scan);
    }

    /// Every `scan_host_key` call so far: workspace, host, port, key type.
    pub(crate) fn scans(&self) -> Vec<(WorkspaceId, String, u16, String)> {
        self.state().scans.clone()
    }

    /// Sends the core a request on the latest relay of `id`.
    pub(crate) fn relay_send(&self, id: &WorkspaceId, request: RelayRequest) {
        let state = self.state();
        let relay = state.relays.get(id).expect("no relay was opened");
        relay.requests.unbounded_send(Ok(request)).unwrap();
    }

    /// The next reply the core sent on the latest relay of `id`; `None` if the relay ended first.
    pub(crate) async fn relay_reply(&self, id: &WorkspaceId) -> Option<RelayReply> {
        let replies = self
            .state()
            .relays
            .get(id)
            .expect("no relay was opened")
            .replies
            .clone();
        let mut replies = replies.lock().await;
        tokio::time::timeout(Duration::from_secs(10), replies.next())
            .await
            .expect("the core never replied")
    }

    /// Ends the latest relay of `id` from the plugin's side.
    pub(crate) fn relay_end(&self, id: &WorkspaceId) {
        if let Some(relay) = self.state().relays.get(id) {
            relay.requests.close_channel();
        }
    }

    /// Waits until the latest relay of `id` is `open`.
    pub(crate) async fn relay_settled(&self, id: &WorkspaceId, open: bool) {
        for _ in 0..500 {
            if self.state().relays.contains_key(id) && self.relay_is_open(id) == open {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "the relay of {id} never became {}",
            if open { "open" } else { "closed" }
        );
    }

    fn workspace(id: &WorkspaceId, held: &Held) -> Workspace {
        Workspace {
            id: id.clone(),
            description: "fake box".to_owned(),
            working_directory: "/work".to_owned(),
            persistence: "files persist".to_owned(),
            created_at: held.created_at,
            state: if held.running {
                PluginState::Running
            } else {
                PluginState::Stopped
            },
            disk_used_bytes: None,
            details: vec![WorkspaceDetail::new("Box", "fake")],
        }
    }
}

fn unused<T>() -> Result<T> {
    Err(Error::other("not used by these tests"))
}

#[async_trait]
impl Environment for Fake {
    async fn info(&self) -> Result<EnvironmentInfo> {
        Ok(EnvironmentInfo {
            options_schema: json!({"type": "object"}),
        })
    }

    async fn create_workspace(&self, id: &WorkspaceId, options: Value) -> Result<Workspace> {
        let mut state = self.state();
        let held = Held {
            running: true,
            created_at: self.clock.now(),
            options,
        };
        if let Some(error) = state.create_error.take() {
            if state.partial {
                state.workspaces.insert(id.clone(), held);
            }
            return Err(error);
        }
        let workspace = Self::workspace(id, &held);
        state.workspaces.insert(id.clone(), held);
        state.log.push(format!("create {id}"));
        Ok(workspace)
    }

    async fn delete_workspace(&self, id: &WorkspaceId) -> Result<()> {
        let mut state = self.state();
        if state.delete_fails {
            return Err(Error::unavailable("the engine is down"));
        }
        state.workspaces.remove(id);
        state.log.push(format!("delete {id}"));
        Ok(())
    }

    async fn start_workspace(&self, id: &WorkspaceId) -> Result<StartOutcome> {
        let mut state = self.state();
        let recreate = std::mem::take(&mut state.recreate);
        let Some(held) = state.workspaces.get_mut(id) else {
            return Err(Error::NotFound(format!("workspace {id}")));
        };
        if held.running {
            return Ok(StartOutcome::Running);
        }
        held.running = true;
        state.log.push(format!("start {id}"));
        Ok(if recreate {
            StartOutcome::Recreated {
                detail: "Installed packages are gone.".to_owned(),
            }
        } else {
            StartOutcome::Started {
                detail: String::new(),
            }
        })
    }

    async fn stop_workspace(&self, id: &WorkspaceId) -> Result<()> {
        let mut state = self.state();
        if let Some(held) = state.workspaces.get_mut(id) {
            held.running = false;
        }
        state.log.push(format!("stop {id}"));
        Ok(())
    }

    async fn list_workspaces(&self) -> Result<WorkspaceList> {
        let state = self.state();
        if state.list_fails {
            return Err(Error::unavailable("the engine is down"));
        }
        Ok(WorkspaceList {
            workspaces: state
                .workspaces
                .iter()
                .map(|(id, held)| {
                    let mut workspace = Self::workspace(id, held);
                    workspace.disk_used_bytes = state.disk_used;
                    if let Some(details) = &state.details {
                        workspace.details.clone_from(details);
                    }
                    workspace
                })
                .collect(),
            free_bytes: state.free_bytes,
        })
    }

    async fn exec(
        &self,
        id: &WorkspaceId,
        request: ExecRequest,
    ) -> Result<BoxStream<'static, Result<ExecEvent>>> {
        let mut state = self.state();
        if !state.workspaces.contains_key(id) {
            return Err(Error::NotFound(format!("workspace {id}")));
        }
        state.execs.push(request);
        match state.exec.clone() {
            Exec::Refuse => unused(),
            Exec::Events(events) => Ok(stream::iter(events.into_iter().map(Ok)).boxed()),
            Exec::Hang(dropped) => {
                let guard = DropFlag(dropped);
                Ok(stream::iter([Ok(ExecEvent::Stdout(b"started\n".to_vec()))])
                    .chain(stream::pending().inspect(move |_: &Result<ExecEvent>| {
                        let _ = &guard;
                    }))
                    .boxed())
            }
        }
    }

    async fn relay(
        &self,
        id: &WorkspaceId,
        replies: BoxStream<'static, RelayReply>,
    ) -> Result<BoxStream<'static, Result<RelayRequest>>> {
        let mut state = self.state();
        state.relay_calls += 1;
        if state.relay_fails {
            return Err(Error::unavailable("the helper can't start"));
        }
        match state.workspaces.get(id) {
            None => return Err(Error::NotFound(format!("workspace {id}"))),
            Some(held) if !held.running => {
                return Err(Error::InvalidRequest(format!("workspace {id} is stopped")));
            }
            Some(_) => {}
        }
        let (requests, incoming) = futures::channel::mpsc::unbounded();
        let (reply_tx, reply_rx) = futures::channel::mpsc::unbounded();
        let closed = Arc::new(AtomicBool::new(false));
        state.relays.insert(
            id.clone(),
            FakeRelay {
                requests,
                replies: Arc::new(tokio::sync::Mutex::new(reply_rx)),
                closed: closed.clone(),
            },
        );
        tokio::spawn(async move {
            let mut replies = replies;
            while let Some(reply) = replies.next().await {
                if reply_tx.unbounded_send(reply).is_err() {
                    break;
                }
            }
        });
        let guard = DropFlag(closed);
        let dropped = DropCount(self.relays_dropped.clone());
        Ok(incoming
            .inspect(move |_| {
                let _ = (&guard, &dropped);
            })
            .boxed())
    }

    async fn scan_host_key(
        &self,
        id: &WorkspaceId,
        host: &str,
        port: u16,
        key_type: &str,
    ) -> Result<Vec<u8>> {
        let scan = {
            let mut state = self.state();
            state
                .scans
                .push((id.clone(), host.to_owned(), port, key_type.to_owned()));
            state.scan_results.get(&(host.to_owned(), port)).cloned()
        };
        match scan {
            Some(Scan::Key(key)) => Ok(key),
            Some(Scan::Gated(gate, key)) => {
                gate.notified().await;
                Ok(key)
            }
            None => Err(Error::unavailable(format!("no route to {host}"))),
        }
    }

    async fn read_file(&self, id: &WorkspaceId, path: &str, max_bytes: u64) -> Result<ReadFile> {
        let mut state = self.state();
        state.reads.push(max_bytes);
        let content = state
            .files
            .get(&(id.clone(), path.to_owned()))
            .ok_or_else(|| Error::NotFound(format!("no such file: {path}")))?;
        let kept = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        Ok(ReadFile {
            content: content[..content.len().min(kept)].to_vec(),
            size: content.len() as u64,
        })
    }

    async fn write_file(&self, id: &WorkspaceId, path: &str, content: Vec<u8>) -> Result<()> {
        let mut state = self.state();
        if !state.workspaces.contains_key(id) {
            return Err(Error::NotFound(format!("workspace {id}")));
        }
        state.files.insert((id.clone(), path.to_owned()), content);
        Ok(())
    }

    async fn find(&self, id: &WorkspaceId, request: FindRequest) -> Result<FindResult> {
        let state = self.state();
        let needle = request.pattern.trim_matches('*');
        let mut paths: Vec<String> = state
            .files
            .keys()
            .filter(|(owner, path)| owner == id && path.contains(needle))
            .map(|(_, path)| path.clone())
            .collect();
        let limit = usize::try_from(request.limit).unwrap_or(usize::MAX);
        let truncated = paths.len() > limit;
        paths.truncate(limit);
        Ok(FindResult { paths, truncated })
    }

    async fn grep(&self, id: &WorkspaceId, request: GrepRequest) -> Result<GrepResult> {
        let state = self.state();
        let mut matches = Vec::new();
        for ((owner, path), content) in &state.files {
            if owner != id {
                continue;
            }
            for (n, line) in String::from_utf8_lossy(content).lines().enumerate() {
                if line.contains(&request.pattern) {
                    matches.push(GrepMatch {
                        path: path.clone(),
                        line: n as u64 + 1,
                        text: line.to_owned(),
                    });
                }
            }
        }
        let limit = usize::try_from(request.limit).unwrap_or(usize::MAX);
        let truncated = matches.len() > limit;
        matches.truncate(limit);
        Ok(GrepResult { matches, truncated })
    }
}

/// Counts itself when dropped.
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Sets its flag when dropped.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
