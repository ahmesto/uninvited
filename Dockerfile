# Uninvited in a container.
#
#   docker compose up        # from a clone: builds this image and starts the demo
#
# Out of the box it runs config.docker.yaml: every decoy, no outbound lookups, and one round of
# harmless test knocks at start so the dashboard has something to show. compose.yaml publishes the
# ports on the host's loopback only, so nothing is reachable from outside your machine.
# For a real sensor, mount your own config over /etc/uninvited/config.yaml: docs/RUNNING.md,
# "With Docker".
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin uninvited \
 && mkdir -p /data /etc/uninvited && chown uninvited:uninvited /data

WORKDIR /src
# The dependencies first, so a change to the code does not download them again.
COPY requirements.txt .
RUN pip install -r requirements.txt
# .dockerignore lets through only what the package is built from.
COPY . .
RUN pip install --no-deps . \
 && install -m 644 config.docker.yaml /etc/uninvited/config.yaml \
 && cd / && rm -rf /src

USER uninvited
WORKDIR /data
VOLUME /data
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/split', timeout=4).status == 200 else 1)"

CMD ["uninvited", "--config", "/etc/uninvited/config.yaml"]
