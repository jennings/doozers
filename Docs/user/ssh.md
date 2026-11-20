# SSH keys and SSH in workspaces

This page shows how to give Doozers an SSH key, add its public key to GitHub, and use the key for
`ssh` and `git` in your agent's workspace.

Each user keeps their own SSH keys in Doozers, on the **SSH keys** page in the
[web interface](web.md#ssh-keys). Doozers keeps every private key encrypted and never shows it
again, not even one it generated. Only you can use your keys. The owner can see every user's key
details and delete a key, but can't use one.

## Generate a key

To make a new key:

1. Select **SSH keys** in the sidebar.
2. Under **Generate a key**, choose the **Type**. Ed25519 is the default and the best choice unless
   a server needs another type.
3. Enter a **Label** to tell your keys apart, or leave it empty to use `<you>@doozers`.
4. Select **Generate**.

You can generate these types:

- Ed25519
- RSA with 3072 or 4096 bits. RSA keys take a few seconds to generate.
- ECDSA on P-256, P-384, or P-521

## Upload a key

Upload a key you already use if it should work from Doozers too. Doozers keeps its own copy, so
deleting it in Doozers doesn't touch your original.

1. Under **Upload a key**, paste the private key into **Private key**, or choose its file under
   **Key file**.
2. If the key has a passphrase, enter it under **Passphrase**. Doozers decrypts the key once and
   keeps it without the passphrase, because nobody is there to type it later.
3. Enter a **Label**, or leave it empty to use the comment stored in the key.
4. Select **Upload**.

Doozers reads private keys in these formats, as PEM text:

- OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), the format `ssh-keygen` writes
- PKCS#1 RSA (`-----BEGIN RSA PRIVATE KEY-----`)
- SEC1 EC (`-----BEGIN EC PRIVATE KEY-----`)
- PKCS#8 (`-----BEGIN PRIVATE KEY-----` and `-----BEGIN ENCRYPTED PRIVATE KEY-----`)

Doozers doesn't accept PuTTY `.ppk` files, DSA keys, or security keys (`sk-ssh-ed25519@openssh.com`
and `sk-ecdsa-sha2-nistp256@openssh.com`). To use a PuTTY key, convert it first:

```sh
puttygen key.ppk -O private-openssh -o key
```

A key that is encrypted with another cipher can be converted with `ssh-keygen -p -f key`. You can't
upload a key you already have, but another user can upload the same key.

## Add the public key to GitHub

Each key on the page shows its **Public key**, ready to paste into a service that should accept it.
To add it to GitHub:

1. Select the copy button at the right end of the key's **Public key** field. If there's no button,
   select the text and copy it.
2. On GitHub, open **Settings**, then **SSH and GPG keys**, and select **New SSH key**.
3. Enter a **Title**, paste the public key into **Key**, and select **Add SSH key**.

GitHub lists the key's fingerprint, which starts with `SHA256:`. It matches the **Fingerprint** on
the page. For another server, add the same line to the `~/.ssh/authorized_keys` file of the account
you log in to.

## Rename or delete a key

Select **Rename** to change a key's label. The label is the comment at the end of the public key.
Renaming doesn't change the key, so a copy you registered earlier keeps working.

Select **Delete** and confirm to remove a key from Doozers. Doozers can't bring it back. Remove the
public key from GitHub and your servers too.

## See every user's keys

The owner sees every user's keys under **Admin**, then **SSH keys**: the owner of each key, its
label, type, fingerprint, and when it was created and last used. The owner can delete a key there,
such as one that belonged to a user who left.

## Use SSH in a workspace

A workspace can use your keys for `ssh` and for git remotes such as `git@github.com:you/repo.git`.
The private key never enters the workspace. Programs there ask Doozers to sign, and Doozers signs
with one of your keys. A key you add or delete works or stops working at once, without restarting
anything.

**While your agent works in your workspace, it can use all of your keys. It can sign in to every
server and service that accepts them. Use a key that has only the access your agent needs, such as a
key that you registered on one GitHub repository as a deploy key.**

Which keys a workspace gets depends on the conversation that created it:

- A conversation with you, such as a direct message or your web chat, gets your keys.
- An isolated job run gets the keys of the user who created the job. A job from `doozers.toml` has
  no creator, so its workspace gets none.
- A group conversation gets none, because the commands of several users can't be kept apart.

The workspace's image needs an OpenSSH client, which provides `ssh` and `ssh-add`. Debian, Ubuntu,
and Alpine images have it in the `openssh-client` package. Your agent can install it in the
workspace, or you can use an image that has it.

To check that SSH works, run these in the workspace:

```sh
ssh-add -L
ssh -T git@github.com
```

`ssh-add -L` lists the public keys the workspace gets, with the labels you gave them. `ssh -T`
greets you by your GitHub user name if one of those keys is registered at GitHub. If the first
command prints `The agent has no identities`, the workspace gets no keys. Your agent's
`environment_plugins` and `environment_create` results say which keys it gets and why it has none.

Doozers doesn't check the host keys of servers for you yet. On the first connection to a server,
pass `-o StrictHostKeyChecking=accept-new`, which trusts the server's key the first time and refuses
a changed key later:

```sh
ssh -o StrictHostKeyChecking=accept-new git@github.com
GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=accept-new" git clone git@github.com:you/repo.git
```

Doozers refuses to sign for a forwarded agent, so `ssh -A` gives the server you connect to no keys.
The **Workspaces** page shows whose keys each workspace gets under **SSH keys**.
