//! Runs the built helper binary the way the Docker environment plugin does.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

fn helper(run_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_doozers-workspace-helper"));
    command.env("DOOZERS_RUN_DIR", run_dir);
    command
}

fn lines(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn tree(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (path, content) in files {
        let full = dir.path().join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }
    dir
}

fn find(dir: &Path, args: &[&str]) -> (Vec<String>, bool) {
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .arg("find")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    let mut values = lines(&out);
    let truncated = values.pop().unwrap()["truncated"].as_bool().unwrap();
    let paths = values
        .iter()
        .map(|v| v["path"].as_str().unwrap().to_owned())
        .collect();
    (paths, truncated)
}

#[test]
fn find_matches_a_glob_in_sorted_order() {
    let dir = tree(&[
        ("src/b.rs", ""),
        ("src/a.rs", ""),
        ("src/sub/c.rs", ""),
        ("src-extra/d.rs", ""),
        ("top.rs", ""),
        ("notes.txt", ""),
    ]);
    let (paths, truncated) = find(dir.path(), &["--pattern", "**/*.rs", "--limit", "100"]);
    assert_eq!(
        paths,
        [
            "src-extra/d.rs",
            "src/a.rs",
            "src/b.rs",
            "src/sub/c.rs",
            "top.rs"
        ]
    );
    assert!(!truncated);
}

#[test]
fn find_star_stays_within_a_directory() {
    let dir = tree(&[("a.rs", ""), ("src/b.rs", "")]);
    let (paths, _) = find(dir.path(), &["--pattern", "*.rs", "--limit", "10"]);
    assert_eq!(paths, ["a.rs"]);
}

#[test]
fn find_reports_paths_relative_to_the_searched_directory() {
    let dir = tree(&[("src/a.rs", ""), ("other/b.rs", "")]);
    let (paths, _) = find(
        dir.path(),
        &["--pattern", "**/*.rs", "--path", "src", "--limit", "10"],
    );
    assert_eq!(paths, ["a.rs"]);
}

#[test]
fn find_truncates_at_the_limit() {
    let dir = tree(&[("a", ""), ("b", ""), ("c", "")]);
    let (paths, truncated) = find(dir.path(), &["--pattern", "*", "--limit", "2"]);
    assert_eq!(paths, ["a", "b"]);
    assert!(truncated);
    let (paths, truncated) = find(dir.path(), &["--pattern", "*", "--limit", "3"]);
    assert_eq!(paths.len(), 3);
    assert!(!truncated);
}

#[test]
fn find_skips_git_and_gitignored_files_but_not_dotfiles() {
    // No `.git` directory: .gitignore applies anyway.
    let dir = tree(&[
        (".gitignore", "target/\n*.log\n"),
        (".git/config", ""),
        (".env", ""),
        ("target/out.bin", ""),
        ("run.log", ""),
        ("src/keep.rs", ""),
        ("src/.gitignore", "secret.rs\n"),
        ("src/secret.rs", ""),
    ]);
    let (paths, _) = find(dir.path(), &["--pattern", "**", "--limit", "100"]);
    assert_eq!(
        paths,
        [".env", ".gitignore", "src/.gitignore", "src/keep.rs"]
    );
}

#[test]
fn find_fails_on_a_missing_directory_and_a_bad_glob() {
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args([
            "find",
            "--pattern",
            "*",
            "--path",
            "/nonexistent-dir",
            "--limit",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    let out = helper(run_dir.path())
        .args(["find", "--pattern", "[", "--limit", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid glob"));
}

fn grep(dir: &Path, args: &[&str]) -> (Vec<(String, u64, String)>, bool) {
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .arg("grep")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    let mut values = lines(&out);
    let truncated = values.pop().unwrap()["truncated"].as_bool().unwrap();
    let matches = values
        .iter()
        .map(|v| {
            (
                v["path"].as_str().unwrap().to_owned(),
                v["line"].as_u64().unwrap(),
                v["text"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    (matches, truncated)
}

#[test]
fn grep_reports_lines_in_path_then_line_order() {
    let dir = tree(&[
        ("b.txt", "one\nneedle two\nthree\n"),
        ("a/x.txt", "needle first\r\nlast needle"),
        ("c.txt", "nothing\n"),
    ]);
    let (matches, truncated) = grep(dir.path(), &["--pattern", "needle", "--limit", "10"]);
    assert_eq!(
        matches,
        [
            ("a/x.txt".to_owned(), 1, "needle first".to_owned()),
            ("a/x.txt".to_owned(), 2, "last needle".to_owned()),
            ("b.txt".to_owned(), 2, "needle two".to_owned()),
        ]
    );
    assert!(!truncated);
}

#[test]
fn grep_filters_by_glob_and_case() {
    let dir = tree(&[
        ("a.rs", "Needle\n"),
        ("b.txt", "Needle\n"),
        ("src/c.rs", "needle\n"),
    ]);
    let (matches, _) = grep(
        dir.path(),
        &[
            "--pattern",
            "needle",
            "--glob",
            "**/*.rs",
            "--ignore-case",
            "--limit",
            "10",
        ],
    );
    let paths: Vec<_> = matches.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(paths, ["a.rs", "src/c.rs"]);
    let (matches, _) = grep(dir.path(), &["--pattern", "needle", "--limit", "10"]);
    assert_eq!(matches.len(), 1);
}

#[test]
fn grep_skips_binary_files_and_ignored_files() {
    let dir = tree(&[
        (".gitignore", "ignored.txt\n"),
        ("ignored.txt", "needle\n"),
        (".git/HEAD", "needle\n"),
        ("text.txt", "needle\n"),
    ]);
    fs::write(dir.path().join("blob.bin"), b"needle\0more").unwrap();
    let (matches, _) = grep(dir.path(), &["--pattern", "needle", "--limit", "10"]);
    let paths: Vec<_> = matches.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(paths, ["text.txt"]);
}

#[test]
fn grep_truncates_at_the_limit() {
    let dir = tree(&[("a.txt", "x\nx\nx\n")]);
    let (matches, truncated) = grep(dir.path(), &["--pattern", "x", "--limit", "2"]);
    assert_eq!(matches.len(), 2);
    assert!(truncated);
    let (matches, truncated) = grep(dir.path(), &["--pattern", "x", "--limit", "3"]);
    assert_eq!(matches.len(), 3);
    assert!(!truncated);
}

#[test]
fn grep_searches_a_single_file_under_its_own_name() {
    let dir = tree(&[("sub/a.txt", "needle\n"), ("b.txt", "needle\n")]);
    let (matches, _) = grep(
        dir.path(),
        &[
            "--pattern",
            "needle",
            "--path",
            "sub/a.txt",
            "--limit",
            "10",
        ],
    );
    assert_eq!(matches, [("a.txt".to_owned(), 1, "needle".to_owned())]);
}

#[test]
fn grep_rejects_a_bad_regex() {
    let dir = tree(&[("a.txt", "x\n")]);
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args(["grep", "--pattern", "(", "--limit", "1"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid regular expression"));
}

#[test]
fn read_prints_the_size_then_up_to_max_bytes() {
    let dir = tree(&[("f.txt", "0123456789")]);
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args(["read", "--max", "4", "f.txt"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"{\"size\":10}\n0123");
    let out = helper(run_dir.path())
        .args(["read", "f.txt"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"{\"size\":10}\n0123456789");
}

#[test]
fn read_fails_for_a_missing_file_and_a_directory() {
    let dir = tree(&[("d/f", "")]);
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args(["read", "missing"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    let out = helper(run_dir.path())
        .args(["read", "d"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is a directory"));
}

fn write(dir: &Path, path: &str, content: &[u8]) {
    let run_dir = TempDir::new().unwrap();
    let mut child = helper(run_dir.path())
        .args(["write", path])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(content).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn write_creates_parents_and_keeps_an_existing_files_mode() {
    let dir = tree(&[("script.sh", "old old old")]);
    let script = dir.path().join("script.sh");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    write(dir.path(), "script.sh", b"new");
    assert_eq!(fs::read(&script).unwrap(), b"new");
    assert_eq!(
        fs::metadata(&script).unwrap().permissions().mode() & 0o777,
        0o755
    );

    write(dir.path(), "deep/er/file.txt", b"\x00binary\xff");
    assert_eq!(
        fs::read(dir.path().join("deep/er/file.txt")).unwrap(),
        b"\x00binary\xff"
    );
}

fn run_command(run_dir: &Path, script: &str) -> Command {
    let mut command = helper(run_dir);
    command.args(["run", "--id", "test-1", "--", "/bin/sh", "-c", script]);
    command
}

#[test]
fn run_forwards_output_and_the_exit_status() {
    let run_dir = TempDir::new().unwrap();
    let out = run_command(run_dir.path(), "echo out; echo err >&2; exit 3")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
}

#[test]
fn run_reports_a_signal_as_128_plus_n() {
    let run_dir = TempDir::new().unwrap();
    let out = run_command(run_dir.path(), "kill -9 $$").output().unwrap();
    assert_eq!(out.status.code(), Some(137));
}

#[test]
fn run_reports_a_missing_program_as_127() {
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args(["run", "--id", "x", "--", "/nonexistent/program"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn run_does_not_wait_for_background_processes_holding_its_output() {
    let run_dir = TempDir::new().unwrap();
    let started = Instant::now();
    let out = run_command(run_dir.path(), "sleep 20 & echo done")
        .output()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"done\n");
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn run_records_its_group_and_removes_the_record_when_done() {
    let run_dir = TempDir::new().unwrap();
    let record = run_dir.path().join("test-1");
    let mut child = run_command(run_dir.path(), "sleep 0.5").spawn().unwrap();
    wait_for(&record);
    assert!(child.wait().unwrap().success());
    assert!(!record.exists());
}

#[test]
fn kill_ends_the_command_and_its_descendants() {
    let run_dir = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let pid_file = work.path().join("child.pid");
    let script = format!("sleep 60 & echo $! > {}; wait", pid_file.display());
    let mut child = run_command(run_dir.path(), &script).spawn().unwrap();
    wait_for(&pid_file);
    // Give the shell time to write the pid completely.
    std::thread::sleep(Duration::from_millis(100));
    let descendant = fs::read_to_string(&pid_file).unwrap().trim().to_owned();

    let killed = helper(run_dir.path())
        .args(["kill", "--id", "test-1"])
        .status()
        .unwrap();
    assert!(killed.success());
    assert_eq!(child.wait().unwrap().code(), Some(137));
    // The descendant is gone (`kill -0` fails for a process that doesn't exist).
    let alive = Command::new("kill")
        .args(["-0", &descendant])
        .status()
        .unwrap();
    assert!(!alive.success());
}

#[test]
fn kill_before_run_starts_makes_run_kill_the_command_at_once() {
    let run_dir = TempDir::new().unwrap();
    let killed = helper(run_dir.path())
        .args(["kill", "--id", "test-1"])
        .status()
        .unwrap();
    assert!(killed.success());
    let started = Instant::now();
    let out = run_command(run_dir.path(), "sleep 30").output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(out.status.code(), Some(137));
}

#[test]
fn kill_rejects_an_id_that_is_not_a_file_name() {
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args(["kill", "--id", "../etc"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn df_reports_free_bytes() {
    let dir = TempDir::new().unwrap();
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .arg("df")
        .arg(dir.path())
        .output()
        .unwrap();
    let values = lines(&out);
    assert!(values[0]["free_bytes"].as_u64().unwrap() > 0);
    let out = helper(run_dir.path())
        .args(["df", "/nonexistent-dir"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
}

/// The plugin's end of `ssh-agent`: the helper's stdio, speaking frames.
struct Relay {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    socket: PathBuf,
    lookup_socket: PathBuf,
    // Keeps the socket's directory (a short path: socket paths are limited to about 100 bytes).
    _dir: TempDir,
}

const REQUEST: u8 = 1;
const CLOSED: u8 = 2;
const REPLY: u8 = 3;
const LOOKUP: u8 = 4;
const LOOKUP_REPLY: u8 = 5;

impl Relay {
    fn start() -> Self {
        Self::start_in(TempDir::new().unwrap(), |_| {})
    }

    fn start_in(dir: TempDir, prepare: impl FnOnce(&Path)) -> Self {
        let socket = dir.path().join("a.sock");
        let lookup_socket = dir.path().join("k.sock");
        prepare(&socket);
        let run_dir = TempDir::new().unwrap();
        let mut child = helper(run_dir.path())
            .arg("ssh-agent")
            .arg("--socket")
            .arg(&socket)
            .arg("--known-hosts-socket")
            .arg(&lookup_socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        // The socket path exists before `listen` replaces a stale file, so wait for a connection.
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline, "the helper never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut relay = Self {
            child,
            stdin,
            stdout,
            socket,
            lookup_socket,
            _dir: dir,
        };
        // The probe connection above is connection 1; consume its closed frame.
        // (Another thread could race it, so the first frame is checked, not assumed.)
        let (kind, connection, _) = relay.read_frame();
        assert_eq!((kind, connection), (CLOSED, 1));
        relay
    }

    /// `known-hosts` as `ssh` runs it, against this relay.
    fn known_hosts(&self, args: &[&str]) -> Command {
        let mut command = helper(Path::new("/nonexistent"));
        command
            .arg("known-hosts")
            .arg("--socket")
            .arg(&self.lookup_socket)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }

    fn connect_lookup(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.lookup_socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
    }

    fn read_frame(&mut self) -> (u8, u64, Vec<u8>) {
        let mut length = [0u8; 4];
        self.stdout.read_exact(&mut length).unwrap();
        let mut rest = vec![0u8; u32::from_be_bytes(length) as usize];
        self.stdout.read_exact(&mut rest).unwrap();
        let connection = u64::from_be_bytes(rest[1..9].try_into().unwrap());
        (rest[0], connection, rest[9..].to_vec())
    }

    fn send_frame(&mut self, kind: u8, connection: u64, payload: &[u8]) {
        let mut frame = ((9 + payload.len()) as u32).to_be_bytes().to_vec();
        frame.push(kind);
        frame.extend(connection.to_be_bytes());
        frame.extend(payload);
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(&frame).unwrap();
        stdin.flush().unwrap();
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "the helper never exited");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn send_message(stream: &mut UnixStream, message: &[u8]) {
    stream
        .write_all(&(message.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(message).unwrap();
}

fn read_message(stream: &mut UnixStream) -> Vec<u8> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).unwrap();
    let mut message = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut message).unwrap();
    message
}

#[test]
fn ssh_agent_listens_on_a_socket_anyone_may_use() {
    let relay = Relay::start();
    let mode = fs::metadata(&relay.socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o666);
}

#[test]
fn ssh_agent_replaces_a_stale_socket_file() {
    let relay = Relay::start_in(TempDir::new().unwrap(), |socket| {
        fs::write(socket, "left over").unwrap();
    });
    drop(relay.connect());
}

#[test]
fn ssh_agent_multiplexes_clients_and_routes_replies_by_connection() {
    let mut relay = Relay::start();
    let (mut first, mut second) = (relay.connect(), relay.connect());
    send_message(&mut first, b"\x0bfirst");
    let (kind, first_id, payload) = relay.read_frame();
    assert_eq!((kind, payload.as_slice()), (REQUEST, &b"\x0bfirst"[..]));
    send_message(&mut second, b"\x0dsecond");
    let (kind, second_id, payload) = relay.read_frame();
    assert_eq!((kind, payload.as_slice()), (REQUEST, &b"\x0dsecond"[..]));
    assert_ne!(first_id, second_id);

    // Answer out of order: each reply reaches only its own client.
    relay.send_frame(REPLY, second_id, b"\x0eto-second");
    relay.send_frame(REPLY, first_id, b"\x0cto-first");
    assert_eq!(read_message(&mut second), b"\x0eto-second");
    assert_eq!(read_message(&mut first), b"\x0cto-first");

    // A client may send several requests on one connection.
    send_message(&mut first, b"\x0bagain");
    let (kind, id, payload) = relay.read_frame();
    assert_eq!(
        (kind, id, payload.as_slice()),
        (REQUEST, first_id, &b"\x0bagain"[..])
    );
}

#[test]
fn ssh_agent_reports_closed_connections_and_drops_late_replies() {
    let mut relay = Relay::start();
    let mut gone = relay.connect();
    let mut stays = relay.connect();
    send_message(&mut gone, b"\x0bhello");
    let (_, gone_id, _) = relay.read_frame();
    drop(gone);
    let (kind, id, payload) = relay.read_frame();
    assert_eq!((kind, id), (CLOSED, gone_id));
    assert!(payload.is_empty());

    // A reply for the closed connection, an unknown kind, and an unknown connection are all
    // ignored, and the relay still works.
    relay.send_frame(REPLY, gone_id, b"late");
    relay.send_frame(9, 1, b"future");
    relay.send_frame(REPLY, 9999, b"nobody");
    send_message(&mut stays, b"\x0bping");
    let (kind, stays_id, _) = relay.read_frame();
    assert_eq!(kind, REQUEST);
    relay.send_frame(REPLY, stays_id, b"\x0cpong");
    assert_eq!(read_message(&mut stays), b"\x0cpong");
}

#[test]
fn ssh_agent_disconnects_a_client_whose_message_is_too_long() {
    let mut relay = Relay::start();
    let mut client = relay.connect();
    let mut other = relay.connect();
    // 256 KiB is allowed; one byte more closes the client.
    send_message(&mut client, &vec![11u8; 256 * 1024]);
    let (kind, id, payload) = relay.read_frame();
    assert_eq!((kind, payload.len()), (REQUEST, 256 * 1024));
    client
        .write_all(&(256u32 * 1024 + 1).to_be_bytes())
        .unwrap();
    let (kind, closed_id, _) = relay.read_frame();
    assert_eq!((kind, closed_id), (CLOSED, id));
    let mut byte = [0u8; 1];
    assert_eq!(client.read(&mut byte).unwrap(), 0);

    // Other clients are unaffected.
    send_message(&mut other, b"\x0bok");
    let (kind, _, payload) = relay.read_frame();
    assert_eq!((kind, payload.as_slice()), (REQUEST, &b"\x0bok"[..]));
}

#[test]
fn ssh_agent_closes_a_client_that_never_reads_without_stalling_the_others() {
    let mut relay = Relay::start();
    let mut deaf = relay.connect();
    let mut other = relay.connect();
    send_message(&mut deaf, b"\x0bdeaf");
    let (kind, deaf_id, _) = relay.read_frame();
    assert_eq!(kind, REQUEST);
    send_message(&mut other, b"\x0bother");
    let (kind, other_id, _) = relay.read_frame();
    assert_eq!(kind, REQUEST);

    // The plugin answers the client that doesn't read with more than its socket and the helper's
    // queue hold, then answers the other one. The frames go out from another thread: if the helper
    // stalled behind the first client, a write here would block and hang the test.
    let mut stdin = relay.stdin.take().unwrap();
    let sender = std::thread::spawn(move || {
        let mut write = |kind: u8, connection: u64, payload: &[u8]| {
            let mut frame = ((9 + payload.len()) as u32).to_be_bytes().to_vec();
            frame.push(kind);
            frame.extend(connection.to_be_bytes());
            frame.extend(payload);
            stdin.write_all(&frame).is_ok() && stdin.flush().is_ok()
        };
        let big = vec![12u8; 200 * 1024];
        for _ in 0..64 {
            if !write(REPLY, deaf_id, &big) {
                return stdin;
            }
        }
        write(REPLY, other_id, b"\x0cfor-other");
        stdin
    });

    // The other client's reply arrives promptly (its read times out after 10 seconds, well under
    // the 30 seconds a stalled write to the first client would take to give up).
    assert_eq!(read_message(&mut other), b"\x0cfor-other");
    // And the client that never read is closed.
    let (kind, id, _) = relay.read_frame();
    assert_eq!((kind, id), (CLOSED, deaf_id));
    relay.stdin = Some(sender.join().unwrap());

    // The relay still works for the client that read.
    send_message(&mut other, b"\x0bagain");
    let (kind, id, _) = relay.read_frame();
    assert_eq!((kind, id), (REQUEST, other_id));
}

#[test]
fn ssh_agent_exits_and_removes_its_socket_when_stdin_ends() {
    let mut relay = Relay::start();
    let _client = relay.connect();
    relay.close_stdin();
    assert_eq!(relay.wait_for_exit().code(), Some(0));
    assert!(!relay.socket.exists());
}

#[test]
fn ssh_agent_refuses_a_stray_argument() {
    let run_dir = TempDir::new().unwrap();
    let out = helper(run_dir.path())
        .args(["ssh-agent", "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}

/// An SSH public key blob of `algorithm` with `data` standing in for the key.
fn blob(algorithm: &str, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, algorithm.as_bytes());
    put_string(&mut blob, data);
    blob
}

/// The answer payload of a lookup frame for `keys`.
fn lookup_answer(keys: &[Vec<u8>]) -> Vec<u8> {
    let mut answer = (keys.len() as u32).to_be_bytes().to_vec();
    for key in keys {
        put_string(&mut answer, key);
    }
    answer
}

/// The request payload `known-hosts` sends for these values.
fn lookup_request(port: u32, host: &str, key_type: &str, key: &[u8]) -> Vec<u8> {
    let mut request = port.to_be_bytes().to_vec();
    put_string(&mut request, host.as_bytes());
    put_string(&mut request, key_type.as_bytes());
    put_string(&mut request, key);
    request
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn ssh_agent_listens_on_a_known_hosts_socket_anyone_may_use() {
    let relay = Relay::start();
    let mode = fs::metadata(&relay.lookup_socket)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o666);
}

#[test]
fn ssh_agent_replaces_a_stale_known_hosts_socket_file() {
    let relay = Relay::start_in(TempDir::new().unwrap(), |socket| {
        fs::write(socket.with_file_name("k.sock"), "left over").unwrap();
    });
    drop(UnixStream::connect(&relay.lookup_socket).unwrap());
}

#[test]
fn known_hosts_without_a_key_asks_for_the_stored_keys_and_prints_them_under_the_given_host() {
    let mut relay = Relay::start();
    let child = relay
        .known_hosts(&["[127.0.0.1]:2222", "2222", "NONE", "NONE"])
        .spawn()
        .unwrap();
    let (kind, id, payload) = relay.read_frame();
    assert_eq!(kind, LOOKUP);
    assert_eq!(payload, lookup_request(2222, "[127.0.0.1]:2222", "", &[]));

    let ed25519 = blob("ssh-ed25519", b"one");
    let rsa = blob("ssh-rsa", b"two");
    relay.send_frame(
        LOOKUP_REPLY,
        id,
        &lookup_answer(&[ed25519.clone(), rsa.clone()]),
    );
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!(
            "[127.0.0.1]:2222 ssh-ed25519 {}\n[127.0.0.1]:2222 ssh-rsa {}\n",
            base64(&ed25519),
            base64(&rsa)
        )
    );
}

#[test]
fn known_hosts_sends_the_offered_key_decoded() {
    let mut relay = Relay::start();
    let offered = blob("ssh-ed25519", b"offered");
    let child = relay
        .known_hosts(&["github.com", "22", "ssh-ed25519", &base64(&offered)])
        .spawn()
        .unwrap();
    let (kind, id, payload) = relay.read_frame();
    assert_eq!(kind, LOOKUP);
    assert_eq!(
        payload,
        lookup_request(22, "github.com", "ssh-ed25519", &offered)
    );
    // No stored key and none to record: nothing is printed, and ssh refuses the host.
    relay.send_frame(LOOKUP_REPLY, id, &lookup_answer(&[]));
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn known_hosts_answers_go_to_the_lookup_they_belong_to() {
    let mut relay = Relay::start();
    let first = relay
        .known_hosts(&["a.example", "22", "NONE", "NONE"])
        .spawn()
        .unwrap();
    let (_, first_id, _) = relay.read_frame();
    let second = relay
        .known_hosts(&["b.example", "22", "NONE", "NONE"])
        .spawn()
        .unwrap();
    let (_, second_id, _) = relay.read_frame();
    assert_ne!(first_id, second_id);

    // Answered out of order, with a stray answer for nobody in between.
    relay.send_frame(LOOKUP_REPLY, 9999, &lookup_answer(&[]));
    relay.send_frame(
        LOOKUP_REPLY,
        second_id,
        &lookup_answer(&[blob("ssh-rsa", b"b")]),
    );
    relay.send_frame(
        LOOKUP_REPLY,
        first_id,
        &lookup_answer(&[blob("ssh-ed25519", b"a")]),
    );
    let first = String::from_utf8(first.wait_with_output().unwrap().stdout).unwrap();
    let second = String::from_utf8(second.wait_with_output().unwrap().stdout).unwrap();
    assert!(first.starts_with("a.example ssh-ed25519 "), "{first}");
    assert!(second.starts_with("b.example ssh-rsa "), "{second}");
}

#[test]
fn known_hosts_fails_closed_when_the_relay_is_not_there() {
    let dir = TempDir::new().unwrap();
    let out = helper(dir.path())
        .args(["known-hosts", "--socket"])
        .arg(dir.path().join("missing.sock"))
        .args(["github.com", "22", "NONE", "NONE"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing the connection"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn known_hosts_fails_closed_when_the_relay_ends_before_answering() {
    let mut relay = Relay::start();
    let child = relay
        .known_hosts(&["github.com", "22", "NONE", "NONE"])
        .spawn()
        .unwrap();
    let _ = relay.read_frame();
    relay.close_stdin();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn known_hosts_fails_on_an_answer_that_is_not_valid() {
    let mut relay = Relay::start();
    let child = relay
        .known_hosts(&["github.com", "22", "NONE", "NONE"])
        .spawn()
        .unwrap();
    let (_, id, _) = relay.read_frame();
    relay.send_frame(LOOKUP_REPLY, id, &[0, 0, 0, 1]);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn known_hosts_rejects_bad_arguments() {
    let relay = Relay::start();
    for args in [
        &["github.com", "22", "NONE"][..],
        &["github.com", "22", "NONE", "NONE", "extra"],
        &["github.com", "http", "NONE", "NONE"],
        &["github.com", "70000", "NONE", "NONE"],
        &["github.com", "22", "ssh-ed25519", "NONE"],
        &["github.com", "22", "NONE", "AAAA"],
        &["github.com", "22", "ssh-ed25519", "not base64!"],
    ] {
        let out = relay.known_hosts(args).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn the_helper_holds_a_bounded_number_of_lookups() {
    let mut relay = Relay::start();
    let request = lookup_request(22, "github.com", "", &[]);
    let send = |stream: &mut UnixStream| {
        stream
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&request).unwrap();
    };
    let mut waiting = Vec::new();
    for _ in 0..64 {
        let mut stream = relay.connect_lookup();
        send(&mut stream);
        let (kind, id, _) = relay.read_frame();
        assert_eq!(kind, LOOKUP);
        waiting.push((id, stream));
    }
    // The 65th is closed without being forwarded.
    let mut over = relay.connect_lookup();
    send(&mut over);
    let mut byte = [0u8; 1];
    assert_eq!(over.read(&mut byte).unwrap(), 0);

    // Answering one makes room.
    let (id, mut answered) = waiting.remove(0);
    relay.send_frame(LOOKUP_REPLY, id, &lookup_answer(&[]));
    assert_eq!(read_message(&mut answered), 0u32.to_be_bytes());
    let mut again = relay.connect_lookup();
    send(&mut again);
    let (kind, _, _) = relay.read_frame();
    assert_eq!(kind, LOOKUP);
}

#[test]
fn a_known_hosts_client_that_sends_too_much_or_nothing_is_closed() {
    let relay = Relay::start();
    let mut oversized = relay.connect_lookup();
    oversized
        .write_all(&(2 * 1024u32 * 1024 + 1).to_be_bytes())
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(oversized.read(&mut byte).unwrap(), 0);
    let mut empty = relay.connect_lookup();
    empty.write_all(&0u32.to_be_bytes()).unwrap();
    assert_eq!(empty.read(&mut byte).unwrap(), 0);
}

#[test]
fn ssh_agent_removes_both_sockets_when_stdin_ends() {
    let mut relay = Relay::start();
    relay.close_stdin();
    assert_eq!(relay.wait_for_exit().code(), Some(0));
    assert!(!relay.socket.exists());
    assert!(!relay.lookup_socket.exists());
}
