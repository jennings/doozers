# syntax=docker/dockerfile:1

# The Doozers container image (PLAN section 14.2): `doozers` and the first-party plugins on Debian
# bookworm. Build it with `docker build .`; nothing is built on the host first. See
# Docs/technical/container-image.md.

# Build stage: the official Rust image on Debian bookworm, the same glibc as the runtime stage.
FROM rust:1-bookworm AS build
WORKDIR /src

# The toolchain pinned in rust-toolchain.toml (`rustup toolchain install` with no argument reads
# it), in its own layer, so it's downloaded again only when the pin changes.
COPY rust-toolchain.toml ./
RUN rustup toolchain install && rustc --version

COPY . .

# The binaries the image ships: the daemon and every first-party plugin meant for real use (the echo
# channel plugin is test-only). Protobuf code generation uses the vendored `protoc`. `target/` is a
# cache mount, which isn't part of the layer, so the binaries are copied out to /out.
#
# The Docker environment plugin copies a static Linux helper into the workspace containers it
# creates, built for the architecture of the engine it talks to. In this image that is the image's
# own architecture (the plugin reaches an engine on another machine as a remote plugin), so the
# helper is built for it, as a musl binary that runs in any image, and installed next to the plugin
# as `doozers-workspace-helper-<arch>`.
RUN --mount=type=cache,id=doozers-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=doozers-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=doozers-target,target=/src/target,sharing=locked \
    set -eu; \
    bins="doozers doozers-channel-irc doozers-channel-email doozers-channel-whatsapp doozers-channel-discord doozers-environment-docker"; \
    arch="$(uname -m)"; \
    cargo build --release --locked $(for bin in $bins; do printf -- '-p %s ' "$bin"; done); \
    cargo build --release --locked -p doozers-workspace-helper --target "$arch-unknown-linux-musl"; \
    mkdir /out; \
    for bin in $bins; do cp "target/release/$bin" /out/; done; \
    cp "target/$arch-unknown-linux-musl/release/doozers-workspace-helper" "/out/doozers-workspace-helper-$arch"

# Runtime stage.
FROM debian:bookworm-slim

# `tini` runs as PID 1: it forwards signals to `doozers` and reaps orphaned plugin descendants,
# which would otherwise stay zombies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata tini \
    && rm -rf /var/lib/apt/lists/*

# A fixed, unprivileged uid and gid outside the range of system and login accounts, so a
# bind-mounted data root can be given to it.
RUN groupadd --gid 10001 doozers \
    && useradd --uid 10001 --gid doozers --home-dir /data --no-create-home --shell /usr/sbin/nologin \
        doozers \
    && install -d -m 0700 -o doozers -g doozers /data

# Plugin discovery finds the plugins on `$PATH` (PLAN section 7.3), so the data root stays pure data.
COPY --from=build /out/ /usr/local/bin/
# The repository is MIT OR Apache-2.0, except plugins/doozers-channel-whatsapp, which is
# AGPL-3.0-only (it links AGPL code): its license text and source offer ship with the binary.
COPY LICENSE-MIT LICENSE-APACHE /usr/share/doc/doozers/
COPY plugins/doozers-channel-whatsapp/LICENSE-AGPL-3.0 plugins/doozers-channel-whatsapp/THIRD-PARTY \
    /usr/share/doc/doozers/

LABEL org.opencontainers.image.title="Doozers" \
      org.opencontainers.image.description="A personal agent daemon with chat channel plugins." \
      org.opencontainers.image.source="https://github.com/jennings/doozers" \
      org.opencontainers.image.licenses="(MIT OR Apache-2.0) AND AGPL-3.0-only"

ENV DOOZERS_HOME=/data
VOLUME ["/data"]
USER doozers
WORKDIR /data
# `doozers.toml` must set `http_listen = "0.0.0.0:8080"` for this port to be reachable.
EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "doozers"]
CMD ["serve"]
