//! `doozers_plugin_sdk::ssh::scan_host_key` against a throwaway OpenSSH `sshd` on loopback, with
//! host keys of every supported type made by `ssh-keygen`. The tests skip, with a printed reason,
//! when `sshd` or `ssh-keygen` isn't installed; with `DOOZERS_REQUIRE_SSHD=1` they fail instead.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use doozers_plugin_sdk::ssh::{ScanError, scan_host_key};
use ssh_key::PublicKey;

const WAIT: Duration = Duration::from_secs(10);

/// The host key types a scan supports, with the `ssh-keygen` options that make one.
const KEYS: [(&str, &[&str]); 5] = [
    ("ssh-ed25519", &["-t", "ed25519"]),
    ("ecdsa-sha2-nistp256", &["-t", "ecdsa", "-b", "256"]),
    ("ecdsa-sha2-nistp384", &["-t", "ecdsa", "-b", "384"]),
    ("ecdsa-sha2-nistp521", &["-t", "ecdsa", "-b", "521"]),
    ("ssh-rsa", &["-t", "rsa", "-b", "2048"]),
];

/// Why the sshd tests can't run here, or `None` when they can.
fn missing_tool() -> Option<String> {
    let reason = if find_sshd().is_none() {
        "no sshd (looked in PATH, /usr/sbin, /usr/local/sbin, /opt/homebrew/sbin)"
    } else if find_in_path("ssh-keygen").is_none() {
        "no ssh-keygen in PATH"
    } else {
        return None;
    };
    assert!(
        std::env::var_os("DOOZERS_REQUIRE_SSHD").is_none_or(|v| v != "1"),
        "DOOZERS_REQUIRE_SSHD=1, but: {reason}"
    );
    Some(reason.to_owned())
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// `sshd` insists on being started with an absolute path, and isn't in the `PATH` of most
/// non-root users.
fn find_sshd() -> Option<PathBuf> {
    let fixed = [
        "/usr/sbin/sshd",
        "/usr/local/sbin/sshd",
        "/opt/homebrew/sbin/sshd",
    ]
    .map(PathBuf::from);
    find_in_path("sshd")
        .into_iter()
        .chain(fixed)
        .find(|candidate| candidate.is_file())
}

struct Sshd {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Sshd {
    fn key_file(&self, key_type: &str) -> PathBuf {
        self.dir.path().join(format!("host_{key_type}"))
    }

    /// The blob of the host key of `key_type`, from its `.pub` file.
    fn blob(&self, key_type: &str) -> Vec<u8> {
        let path = self.key_file(key_type).with_extension("pub");
        let line = fs::read_to_string(&path).expect("the public key file");
        PublicKey::from_openssh(&line)
            .expect("an OpenSSH public key")
            .to_bytes()
            .expect("the key encodes")
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
    listener.local_addr().expect("the address").port()
}

fn keygen(path: &Path, options: &[&str]) {
    let output = Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-C", "", "-f"])
        .arg(path)
        .args(options)
        .output()
        .expect("ssh-keygen starts");
    assert!(
        output.status.success(),
        "ssh-keygen: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Starts an `sshd` with host keys of `key_types`, as the current user, listening on loopback.
fn start_sshd(key_types: &[&str]) -> Sshd {
    let sshd = find_sshd().expect("sshd");
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut config = String::new();
    for key_type in key_types {
        let options = KEYS
            .iter()
            .find(|(name, _)| name == key_type)
            .expect("a known key type")
            .1;
        let path = dir.path().join(format!("host_{key_type}"));
        keygen(&path, options);
        config.push_str(&format!("HostKey {}\n", path.display()));
    }
    let port = free_port();
    config.push_str(&format!(
        "Port {port}\nListenAddress 127.0.0.1\nPidFile {}\nUsePAM no\n",
        dir.path().join("sshd.pid").display()
    ));
    let config_path = dir.path().join("sshd_config");
    fs::write(&config_path, config).expect("the config is written");
    let log = fs::File::create(dir.path().join("sshd.log")).expect("the log file");
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("sshd starts");
    let mut sshd = Sshd { child, port, dir };

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = sshd.child.try_wait().expect("sshd's status") {
            panic!("sshd exited early ({status}):\n{}", sshd.log());
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return sshd;
        }
        assert!(
            Instant::now() < deadline,
            "sshd didn't listen in time:\n{}",
            sshd.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn scan_returns_each_host_key_type_sshd_presents() {
    if let Some(reason) = missing_tool() {
        eprintln!("skipping: {reason}");
        return;
    }
    let all: Vec<&str> = KEYS.iter().map(|(name, _)| *name).collect();
    let sshd = start_sshd(&all);
    for key_type in all {
        let blob = scan_host_key("127.0.0.1", sshd.port, key_type, WAIT)
            .await
            .unwrap_or_else(|e| panic!("{key_type}: {e}\nsshd:\n{}", sshd.log()));
        assert_eq!(blob, sshd.blob(key_type), "{key_type}");
    }
}

#[tokio::test]
async fn scan_names_the_missing_algorithm_when_sshd_has_no_key_of_the_type() {
    if let Some(reason) = missing_tool() {
        eprintln!("skipping: {reason}");
        return;
    }
    let sshd = start_sshd(&["ssh-ed25519"]);
    let error = scan_host_key("127.0.0.1", sshd.port, "ssh-rsa", WAIT)
        .await
        .expect_err("sshd has no RSA key");
    assert!(matches!(error, ScanError::NoCommonAlgorithm(_)), "{error}");
    assert!(error.to_string().contains("ssh-ed25519"), "{error}");
    // The server is still fine afterwards.
    let blob = scan_host_key("127.0.0.1", sshd.port, "ssh-ed25519", WAIT)
        .await
        .expect("scan");
    assert_eq!(blob, sshd.blob("ssh-ed25519"));
}

#[tokio::test]
async fn scan_can_be_repeated_against_the_same_server() {
    if let Some(reason) = missing_tool() {
        eprintln!("skipping: {reason}");
        return;
    }
    let sshd = start_sshd(&["ecdsa-sha2-nistp256"]);
    let expected = sshd.blob("ecdsa-sha2-nistp256");
    for _ in 0..3 {
        let blob = scan_host_key("127.0.0.1", sshd.port, "ecdsa-sha2-nistp256", WAIT)
            .await
            .expect("scan");
        assert_eq!(blob, expected);
    }
}
