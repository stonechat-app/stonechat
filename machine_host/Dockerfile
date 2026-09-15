# The machine host (README.md): hosts your own mailbox plus invited friends'
# on one box, one `stonechat-relay` container each.
#
# Built from the REPO ROOT, not machine_host/: the image carries relay/ as the
# build context for the mailbox image, which main.py builds on first provision
# if it is missing. machine_host/Dockerfile.dockerignore trims the context to
# those two directories. Run it with machine_host/docker-compose.yml.
FROM python:3.13-slim

# Mailboxes are SIBLING containers on the host's daemon, driven through the
# mounted /var/run/docker.sock — the CLI only, no daemon in here. The first
# provision does a `docker build` of the mailbox image, and current engines
# dropped the classic builder, so that needs buildx.
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker/buildx-bin:v0.37 /buildx /usr/libexec/docker/cli-plugins/docker-buildx

# main.py shells out to openssl to mint and fingerprint its pinned TLS cert.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# The repo's own layout, kept verbatim: main.py finds the mailbox build context
# as ../relay relative to itself, so no STONECHAT_MACHINE_HOST_RELAY_DIR needed.
# The CLI tars that directory up and sends it to the daemon, so it only has to
# exist in here, not on the host.
WORKDIR /srv

COPY machine_host/requirements.txt ./machine_host/requirements.txt
RUN pip install --no-cache-dir -r machine_host/requirements.txt

COPY relay ./relay
COPY machine_host/main.py ./machine_host/main.py

# The DB and the TLS keypair live together on a volume. The keypair matters
# most: its fingerprint is inside every invite you have sent, so losing it
# strands them all. Same host path the systemd unit uses.
ENV STONECHAT_MACHINE_HOST_DB=/var/lib/stonechat/machine_host.db \
    STONECHAT_MACHINE_HOST_TLS_DIR=/var/lib/stonechat

# Runs as root: whoever holds the Docker socket is root on the host anyway, and
# the socket's group id differs from box to box.
WORKDIR /srv/machine_host
EXPOSE 8200
CMD ["python", "main.py"]
