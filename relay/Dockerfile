# Multi-stage: build a static musl binary, ship it alone (~10 MB image).
# In production a machine host wraps a PREBUILT binary, uploaded to it by the
# hub (RUST_PORT.md "Packaging") — this self-building Dockerfile is for dev/e2e
# where no CI artifact exists.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release && strip target/release/stonechat-relay

FROM scratch
COPY --from=build /src/target/release/stonechat-relay /stonechat-relay

ENV STONECHAT_DB=/data/mailbox.db
ENV STONECHAT_BLOBS=/data/blobs
ENV STONECHAT_TLS_DIR=/data

EXPOSE 8080
# The browser transport is QUIC, so UDP. Separate from the TLS listener on
# purpose: a host that blocks UDP loses browser sessions and nothing else.
EXPOSE 8443/udp
ENTRYPOINT ["/stonechat-relay"]
