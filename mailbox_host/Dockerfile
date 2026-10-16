# The mailbox host (README.md): hosts your own mailbox plus invited friends'
# on one server, one relay container each. Run it with docker-compose.yml.
#
# Nothing is compiled, here or on the host. Guest mailboxes run either the
# published relay image (ghcr.io/stonechat-app/relay), which main.py pulls on
# first use, or an image it wraps around a relay binary uploaded through
# POST /v1/relay — a two-line `FROM scratch` COPY, seconds, not a build of the
# crate.
FROM python:3.13-slim

# Mailboxes are SIBLING containers on the host's daemon, driven through the
# mounted /var/run/docker.sock — the CLI only, no daemon in here.
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
# Wrapping an uploaded relay binary in an image is a `docker build`, and current
# engines dropped the classic builder, so that needs buildx.
COPY --from=docker/buildx-bin:v0.37 /buildx /usr/libexec/docker/cli-plugins/docker-buildx

# main.py shells out to openssl to mint and fingerprint its pinned TLS cert.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/mailbox_host
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py ./

# The DB and the TLS keypair live together on a volume. The keypair matters
# most: its fingerprint is inside every invite you have sent, so losing it
# strands them all. Same host path the systemd unit uses.
ENV STONECHAT_MAILBOX_HOST_DB=/var/lib/stonechat/mailbox_host.db \
    STONECHAT_MAILBOX_HOST_TLS_DIR=/var/lib/stonechat \
    STONECHAT_MAILBOX_HOST_RELAY_DIR=/var/lib/stonechat

# Runs as root: whoever holds the Docker socket is root on the host anyway, and
# the socket's group id differs from server to server.
EXPOSE 8200
CMD ["python", "main.py"]
