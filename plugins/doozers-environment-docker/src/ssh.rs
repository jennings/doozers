//! What `ssh` in a workspace needs besides the agent socket: the configuration that makes it ask
//! the core which host keys to trust (issue #138), and the scan of a host's key that lets the core
//! verify a first connection.
//!
//! The configuration is [`SSH_CONFIG`] in [`SSH_CONFIG_FILE`], written into the container's own
//! file system, so it is written again whenever a container is created, started, or recreated, and
//! whenever the relay opens (which covers workspaces that were running before the plugin learned
//! to write it). `ssh` reads `/etc/ssh/ssh_config.d/*.conf` only if `/etc/ssh/ssh_config` includes
//! them, which the `openssh-client` packages of Debian, Ubuntu, Alpine, and Fedora do. Where the
//! file exists without the `Include` line, the plugin adds it at the top, so it applies to every
//! host.
//!
//! The scan is [`doozers_plugin_sdk::ssh::scan_host_key`] from the machine the plugin runs on, as
//! `ssh-keyscan` would. It is deliberately not made from inside the workspace: a workspace's root
//! can rewrite `/etc/hosts` or `/etc/resolv.conf`, and a scan that went through them would confirm
//! whatever fake key the workspace was offered for `github.com`, and the core would then record it
//! for every workspace of the instance. A host only the workspace's network can reach isn't
//! scanned, so its first connection is refused until an admin pins its key.

use std::time::Duration;

use doozers_plugin_sdk::ssh::{ScanError, scan_host_key};
use tracing::debug;

use crate::DockerEnvironment;
use crate::error::{Error, ErrorExt as _, Result};
use crate::exec::Plain;

/// Where the configuration lives in a workspace.
pub const SSH_CONFIG_FILE: &str = "/etc/ssh/ssh_config.d/doozers.conf";

/// The configuration: trust the keys the core stores, and nothing else.
pub const SSH_CONFIG: &str = "\
KnownHostsCommand /.doozers/bin/doozers-workspace-helper known-hosts %H %p %t %K
UserKnownHostsFile /dev/null
GlobalKnownHostsFile /dev/null
StrictHostKeyChecking yes
";

/// How long a scan may take, connecting included.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// The shell script that writes the configuration and makes `ssh_config` include it.
fn config_script() -> String {
    format!(
        "set -e\n\
         mkdir -p /etc/ssh/ssh_config.d\n\
         cat > {SSH_CONFIG_FILE} <<'DOOZERS_SSH_CONFIG'\n\
         {SSH_CONFIG}DOOZERS_SSH_CONFIG\n\
         chmod 644 {SSH_CONFIG_FILE}\n\
         if [ -f /etc/ssh/ssh_config ] \\\n\
           && ! grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/ssh_config\\.d/' /etc/ssh/ssh_config\n\
         then\n\
           {{ echo 'Include /etc/ssh/ssh_config.d/*.conf'; cat /etc/ssh/ssh_config; }} \
             > /etc/ssh/ssh_config.doozers-new\n\
           cat /etc/ssh/ssh_config.doozers-new > /etc/ssh/ssh_config\n\
           rm -f /etc/ssh/ssh_config.doozers-new\n\
         fi\n"
    )
}

impl DockerEnvironment {
    /// Writes the `ssh` configuration into the running container `container`.
    pub(crate) async fn configure_ssh(&self, container: &str) -> Result<()> {
        let plain = self
            .exec_plain(
                container,
                vec!["/bin/sh".to_owned(), "-c".to_owned(), config_script()],
            )
            .await?;
        match plain {
            Plain { code: 0, .. } => Ok(()),
            Plain { code, stderr, .. } => Err(Error::other(format!(
                "writing the workspace's ssh configuration exited {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ))),
        }
    }

    /// Fetches the host key `host:port` presents for `key_type`, for workspace `id`. The workspace
    /// must exist and be running; the scan itself is made from the plugin's machine.
    pub(crate) async fn scan_for_workspace(
        &self,
        id: &str,
        host: &str,
        port: u16,
        key_type: &str,
    ) -> Result<Vec<u8>> {
        self.running_container(id).await?;
        scan_host_key(host, port, key_type, SCAN_TIMEOUT)
            .await
            .map_err(|error| {
                let error = match error {
                    ScanError::UnsupportedKeyType(_) => Error::invalid(error.to_string()),
                    _ => Error::unavailable(format!("scanning {host}:{port}: {error}")),
                };
                debug!(workspace = id, %error, "a host key scan failed");
                error
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::HELPER_PATH;

    #[test]
    fn the_configuration_asks_the_helper_and_trusts_nothing_else() {
        assert_eq!(
            SSH_CONFIG.lines().collect::<Vec<_>>(),
            [
                "KnownHostsCommand /.doozers/bin/doozers-workspace-helper known-hosts %H %p %t %K",
                "UserKnownHostsFile /dev/null",
                "GlobalKnownHostsFile /dev/null",
                "StrictHostKeyChecking yes",
            ]
        );
        assert!(SSH_CONFIG.contains(HELPER_PATH));
    }

    #[test]
    fn the_script_writes_the_file_from_a_quoted_here_document_and_includes_it_once() {
        let script = config_script();
        assert!(script.contains(&format!(
            "cat > {SSH_CONFIG_FILE} <<'DOOZERS_SSH_CONFIG'\n{SSH_CONFIG}DOOZERS_SSH_CONFIG\n"
        )));
        // The include goes first, and only if `ssh_config` has no include of the directory yet.
        assert!(script.contains("grep -Eqi"));
        assert!(
            script.contains("echo 'Include /etc/ssh/ssh_config.d/*.conf'; cat /etc/ssh/ssh_config")
        );
        // `sh -n` accepts it.
        let status = std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
