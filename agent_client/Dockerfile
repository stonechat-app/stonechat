# The agent (README.md): a headless device on its owner's identity.
#
# Built from the REPO ROOT, not agent_client/: it links ../core as a path crate,
# and core links ../pqcore. agent_client/Dockerfile.dockerignore trims the
# context to those three crates. Run it with agent_client/docker-compose.yml.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY pqcore ./pqcore
COPY core ./core
COPY agent_client ./agent_client
WORKDIR /src/agent_client
RUN cargo build --release --locked
# scratch has no mkdir. An empty directory owned by the agent's user, so the
# named volume first mounted over it takes that ownership.
RUN mkdir /state

# A static musl binary and nothing else: no shell, no libc, no package manager.
# TLS roots are compiled in (webpki-roots), so there is no CA bundle to ship.
FROM scratch
COPY --from=build /src/agent_client/target/release/stonechat-agent /stonechat-agent
COPY --from=build --chown=10001:10001 /state /state
# The state file is this agent's entire authority — device token, device keys,
# live ratchets — and nothing about holding it needs root.
USER 10001:10001
ENV STONECHAT_AGENT_STATE=/state/agent.json
ENTRYPOINT ["/stonechat-agent"]
CMD ["run"]
