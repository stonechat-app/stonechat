# The hub: a FastAPI process, one SQLite file, and no mailboxes — those never
# run on the hub box (deploy/README.md "Topology rule").
#
# Built from the REPO ROOT, not hub/: the image also carries
# scripts/roll_relay.py so relay releases can be rolled with `compose exec`
# instead of a host venv. See docker-compose.yml next to this file.
FROM python:3.13-slim

# The fleet provider drives remote Docker daemons by shelling out to
# `docker -H ssh://…` (app/providers/fleet.py). That is the CLI only — no
# daemon here and no socket mount, because nothing is ever built or run on
# this box's own Docker.
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
# First ignite on a fresh fleet host does a `docker build` of the mailbox
# image. Current engines dropped the classic builder, so that needs buildx.
COPY --from=docker/buildx-bin:v0.37 /buildx /usr/libexec/docker/cli-plugins/docker-buildx

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

# The repo's own layout, kept verbatim: roll_relay.py reaches the hub package
# as ../hub relative to itself, so flattening this breaks it.
WORKDIR /srv

COPY hub/requirements.txt ./hub/requirements.txt
# The optional deps from requirements.txt. Layers are fixed at build time
# while STONECHAT_BILLING is read at runtime, so a billing-off hub built with
# the default simply carries an unused stripe — harmless, and it keeps one
# image able to serve both.
ARG WITH_BILLING=1
ARG WITH_GCP=0
RUN pip install --no-cache-dir -r hub/requirements.txt \
 && if [ "$WITH_BILLING" = "1" ]; then pip install --no-cache-dir "stripe>=11"; fi \
 && if [ "$WITH_GCP" = "1" ]; then pip install --no-cache-dir "google-cloud-compute>=1.19"; fi

COPY hub/app ./hub/app
COPY scripts/roll_relay.py ./scripts/roll_relay.py

# relay/ is deliberately absent, so the self-building fallback in
# providers/local.py cannot fire. A containerised hub always provisions from a
# prebuilt STONECHAT_RELAY_BINARY, bind-mounted in.
ENV STONECHAT_HUB_DB=/var/lib/stonechat/hub.db \
    STONECHAT_RELAY_BINARY=/opt/stonechat/stonechat-relay

WORKDIR /srv/hub
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
