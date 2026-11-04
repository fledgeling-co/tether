FROM caddy:2.11-alpine@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5
RUN setcap -r /usr/bin/caddy \
    && mkdir -p /data/caddy /config/caddy && chown -R 65532:65532 /data /config
USER 65532:65532
