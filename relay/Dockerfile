# Multi-stage: build a static musl binary, ship it alone (~10 MB image).
# In production the fleet ships a PREBUILT binary in the build context
# (RUST_PORT.md "Packaging") — this self-building Dockerfile is for dev/e2e
# where no CI artifact exists.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release && strip target/release/zeon-relay

FROM scratch
COPY --from=build /src/target/release/zeon-relay /zeon-relay

ENV ZEON_DB=/data/mailbox.db
ENV ZEON_BLOBS=/data/blobs
ENV ZEON_TLS_DIR=/data

EXPOSE 8080
ENTRYPOINT ["/zeon-relay"]
