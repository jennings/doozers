//! SSH from a workspace, through the ssh-agent relay answered by the core's own agent
//! (`doozers_core::ssh::Agent`) over keys in a real secret store.
//!
//! `ssh-keygen -Y sign` signs through the agent socket with no network, once `openssh-client` is
//! installed in the workspace. The `sshd` test starts a second container on the same engine
//! network, running `sshd` with the key's public half in `authorized_keys`, and logs in to it: the
//! host's key is trusted on first use through the core's known hosts, as for every workspace
//! (`known_hosts.rs` tests that part on its own).
//!
//! The tests skip, saying why, when no Docker API socket answers or the engine can't reach the
//! network to install packages. `DOOZERS_REQUIRE_DOCKER=1` turns both into failures: the harness
//! has pulled its image by then, so the engine has a network.

mod support;

use doozers_core::ssh::KeyType;
use doozers_types::{Environment, UserId};
use support::ssh::{Core, Sshd, network_failed, wait_for_socket, workspace_with};
use support::{harness, wid};

#[tokio::test]
async fn ssh_keygen_signs_through_the_agent_and_no_private_key_is_in_the_workspace() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("ssh-sign", harness.config()).await;
    let Some(id) = workspace_with(&scope, "ssh-sign", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    let ed25519 = core.generate(KeyType::Ed25519, "laptop").await;
    let ecdsa = core.generate(KeyType::EcdsaP256, "ci").await;
    let rsa = core.generate(KeyType::Rsa3072, "legacy").await;
    // Another user's key is in the store too, and is never offered.
    let other = UserId::new("alice").unwrap();
    core.keys
        .generate(&other, KeyType::Ed25519, Some("alices"))
        .await
        .unwrap();
    core.serve(&scope, clock, &id, Some(core.owner.clone()))
        .await;
    wait_for_socket(&scope, &id).await;

    // The agent lists the user's keys, most recently used first.
    let listed = scope.run(&id, "ssh-add -L").await;
    assert_eq!(listed.code, 0, "{}{}", listed.stdout, listed.stderr);
    let comments: Vec<&str> = listed
        .stdout
        .lines()
        .map(|line| line.split(' ').nth(2).unwrap())
        .collect();
    assert_eq!(comments, ["legacy", "ci", "laptop"], "{}", listed.stdout);
    assert!(!listed.stdout.contains("alices"));

    // `ssh-keygen -Y sign` signs through the agent for each key type, and the signature checks out
    // against the public key.
    scope
        .env
        .write_file(&wid(&id), "/tmp/message", b"sign this\n".to_vec())
        .await
        .unwrap();
    for key in [&ed25519, &ecdsa, &rsa] {
        let public = key.authorized_key();
        scope
            .env
            .write_file(
                &wid(&id),
                "/tmp/key.pub",
                format!("{public}\n").into_bytes(),
            )
            .await
            .unwrap();
        scope
            .env
            .write_file(
                &wid(&id),
                "/tmp/allowed",
                format!("owner@doozers namespaces=\"file\" {}\n", key.public_key).into_bytes(),
            )
            .await
            .unwrap();
        let command = "rm -f /tmp/message.sig && \
                       ssh-keygen -Y sign -f /tmp/key.pub -n file /tmp/message && \
                       ssh-keygen -Y verify -f /tmp/allowed -I owner@doozers -n file \
                           -s /tmp/message.sig < /tmp/message";
        let ran = scope.run(&id, command).await;
        assert_eq!(
            ran.code, 0,
            "{} {}{}",
            key.type_label, ran.stdout, ran.stderr
        );
        assert!(
            ran.stdout.contains("Good \"file\" signature"),
            "{}",
            ran.stdout
        );
    }
    // Each signature stamped its key.
    for key in [&ed25519, &ecdsa, &rsa] {
        let used = core.keys.get(&core.owner, key.id).await.unwrap();
        assert!(used.last_used_at.is_some(), "{} was not used", key.label);
    }

    // Another user's key can't be signed with, though its public key is at hand.
    let alices = core.keys.list(&other).await.unwrap().remove(0);
    scope
        .env
        .write_file(
            &wid(&id),
            "/tmp/alice.pub",
            format!("{}\n", alices.authorized_key()).into_bytes(),
        )
        .await
        .unwrap();
    let refused = scope
        .run(
            &id,
            "ssh-keygen -Y sign -f /tmp/alice.pub -n file /tmp/message",
        )
        .await;
    assert_ne!(refused.code, 0, "{}{}", refused.stdout, refused.stderr);

    // No private key material is in the container: not in a file, its environment, or its
    // configuration.
    for key in [&ed25519, &ecdsa, &rsa] {
        let pem = core.private_key(key).await;
        let body = pem.lines().nth(1).expect("a PEM body line").to_owned();
        let found = scope
            .run(
                &id,
                &format!(
                    "grep -rlF -e '{body}' / --exclude-dir=proc --exclude-dir=sys \
                     --exclude-dir=dev 2>/dev/null; echo done"
                ),
            )
            .await;
        assert_eq!(
            found.stdout.trim(),
            "done",
            "key material in {}",
            found.stdout
        );
        let container = scope
            .docker
            .inspect_container(&format!("doozers-{}.{id}", scope.instance), None)
            .await
            .unwrap();
        let config = serde_json::to_string(&container).unwrap();
        assert!(
            !config.contains(&body),
            "key material in the container's configuration"
        );
    }
    let leaked = scope
        .run(&id, "grep -rl 'PRIVATE KEY' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null; echo done")
        .await;
    assert_eq!(leaked.stdout.trim(), "done", "{}", leaked.stdout);

    // A deleted key stops working at once, and the others go on.
    core.keys.delete(&core.owner, ecdsa.id).await.unwrap();
    let listed = scope.run(&id, "ssh-add -L").await;
    assert!(!listed.stdout.contains(" ci"), "{}", listed.stdout);
    assert!(listed.stdout.contains("laptop"), "{}", listed.stdout);
}

#[tokio::test]
async fn a_workspace_without_a_key_user_sees_an_agent_with_no_keys() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("ssh-none", harness.config()).await;
    let Some(id) = workspace_with(&scope, "ssh-none", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    core.generate(KeyType::Ed25519, "laptop").await;
    core.serve(&scope, clock, &id, None).await;
    wait_for_socket(&scope, &id).await;
    let listed = scope.run(&id, "ssh-add -L").await;
    assert_ne!(listed.code, 0);
    assert!(
        listed.stdout.contains("The agent has no identities"),
        "{}{}",
        listed.stdout,
        listed.stderr
    );
}

#[tokio::test]
async fn ssh_logs_in_to_an_sshd_container_with_a_key_that_never_enters_the_workspace() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("ssh-login", harness.config()).await;
    let Some(id) = workspace_with(&scope, "ssh-login", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    let key = core.generate(KeyType::Ed25519, "laptop").await;
    core.serve(&scope, clock, &id, Some(core.owner.clone()))
        .await;
    wait_for_socket(&scope, &id).await;

    let name = format!("doozers-sshd-{}", scope.instance);
    let sshd = match Sshd::start(harness.docker(), &name, &key.authorized_key()).await {
        Ok(sshd) => sshd,
        Err(reason) => {
            network_failed("starting an sshd container", &reason);
            return;
        }
    };
    let ssh = format!("ssh -o BatchMode=yes -p 2222 tester@{}", sshd.address);

    // The agent signs for the login.
    assert_eq!(
        core.keys
            .get(&core.owner, key.id)
            .await
            .unwrap()
            .last_used_at,
        None
    );
    let login = scope
        .run(&id, &format!("{ssh} 'echo logged in as $(id -un)'"))
        .await;
    assert_eq!(login.code, 0, "{}{}", login.stdout, login.stderr);
    assert_eq!(login.stdout.trim(), "logged in as tester");
    assert!(
        core.keys
            .get(&core.owner, key.id)
            .await
            .unwrap()
            .last_used_at
            .is_some()
    );

    // A forwarded agent is refused: the server sees no keys, and can't use any to go further.
    let forwarded = scope
        .run(
            &id,
            &format!(
                "{} -A 'ssh-add -L; echo exit $?' 2>&1",
                ssh.replace("-o BatchMode=yes", "")
            ),
        )
        .await;
    assert!(
        forwarded.stdout.contains("The agent has no identities"),
        "{}{}",
        forwarded.stdout,
        forwarded.stderr
    );
    assert!(
        !forwarded.stdout.contains("ssh-ed25519"),
        "{}",
        forwarded.stdout
    );
    let onward = scope
        .run(
            &id,
            &format!(
                "{ssh} -A \"ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -p 2222 \
                 tester@127.0.0.1 true\" 2>&1"
            ),
        )
        .await;
    assert_ne!(onward.code, 0, "{}{}", onward.stdout, onward.stderr);
    assert!(
        onward.stdout.contains("Permission denied"),
        "{}",
        onward.stdout
    );

    // Deleting the key ends the logins at once.
    core.keys.delete(&core.owner, key.id).await.unwrap();
    let denied = scope.run(&id, &format!("{ssh} true 2>&1")).await;
    assert_ne!(denied.code, 0);
    assert!(
        denied.stdout.contains("Permission denied"),
        "{}",
        denied.stdout
    );
    drop(sshd);
}
