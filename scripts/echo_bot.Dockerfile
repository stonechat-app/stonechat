# The echo bot as a container (scripts/echo_bot.py), for running it next to
# the mailboxes it talks to rather than on a laptop. Built from four small
# contexts so nothing else in the repo is sent to the builder — and from
# copies without core/target and pqcore/target, which hold gigabytes of
# build output that named contexts would otherwise ship (no .dockerignore
# applies to them):
#
#   b=$(mktemp -d); rsync -a --exclude target core pqcore scripts "$b"/
#   mkdir "$b/hub" && rsync -a hub/app "$b/hub/"
#   docker buildx build --platform linux/amd64 -f scripts/echo_bot.Dockerfile \
#     --build-context core="$b/core" --build-context pqcore="$b/pqcore" \
#     --build-context hubapp="$b/hub/app" -t stonechat-echo-bot:latest \
#     --load "$b/scripts"
#
# Run with a state volume, so the identity and its sessions survive restarts:
#
#   docker run -d --name echo-bot --restart unless-stopped \
#     -v /var/lib/echo-bot:/state [-e STONECHAT_TEST_CODE=…] stonechat-echo-bot:latest
#
# STONECHAT_TEST_CODE is only needed on the first run, to get the shared tier.

FROM rust:1-bookworm AS corelib
# core/ refers to pqcore as ../pqcore, so keep them siblings.
COPY --from=pqcore . /src/pqcore
COPY --from=core . /src/core
RUN cd /src/core && cargo build --release --lib

FROM python:3.13-slim-bookworm
WORKDIR /bot
RUN pip install --no-cache-dir httpx pynacl websockets
# The protocol client lives in scripts/e2e.py and imports hub/app for the ID
# derivation; the bot itself is scripts/echo_bot.py.
COPY . scripts/
COPY --from=hubapp . hub/app/
COPY --from=corelib /src/core/target/release/libstonechat_core.so /bot/lib/
ENV STONECHAT_CORE_LIB=/bot/lib/libstonechat_core.so \
    STONECHAT_BOT_STATE=/state/echo_bot.pkl \
    PYTHONUNBUFFERED=1
CMD ["python", "-u", "scripts/echo_bot.py"]
