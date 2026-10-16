# The hub: a FastAPI process, one SQLite file, and no mailboxes — those never
# run on the hub machine.
#
# Built from the REPO ROOT, not hub/: the image also carries
# scripts/roll_relay.py so relay releases can be rolled with `compose exec`
# instead of a host venv. See docker-compose.yml next to this file.
FROM python:3.13-slim

# No Docker CLI and no ssh client, deliberately. The hub reaches the boxes that
# hold mailboxes over one HTTPS API (app/providers/mailbox_host.py) instead of
# driving their daemons as it used to, so the image that holds the directory and
# every provider credential no longer carries the tools to run containers
# anywhere.

# The repo's own layout, kept verbatim: roll_relay.py reaches the hub package
# as ../hub relative to itself, so flattening this breaks it.
WORKDIR /srv

COPY hub/requirements.txt ./hub/requirements.txt
# The optional deps from requirements.txt.
ARG WITH_GCP=0
RUN pip install --no-cache-dir -r hub/requirements.txt \
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
# --no-access-log: the hub never writes a client's IP to its logs. Behind a
# proxy, the client's IP comes from X-Forwarded-For, trusted only from the
# addresses in FORWARDED_ALLOW_IPS (uvicorn reads it; default 127.0.0.1) —
# without that every request looks like the proxy, and the per-IP rate limits
# become one limit for everyone.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
