# syntax=docker/dockerfile:1.7
#
# Multi-arch (amd64 + arm64) container image for cyweb.
#
# This Dockerfile is consumed by `.github/workflows/release.yml` on every
# `v*` tag. The release workflow has *already* built the linux-amd64 and
# linux-arm64 binaries via the matrix `build` job, so this Dockerfile
# does NOT recompile from source — it just stages the right binary for
# the target platform on top of debian:bookworm-slim.
#
# The build context must contain both:
#   cyweb-linux-amd64
#   cyweb-linux-arm64
# The release workflow stages them from `actions/download-artifact@v4`
# before invoking `docker buildx build`.
#
# Final image carries the YAML payloads and signature rules at
# /opt/cyweb so users can run `cyweb scan ... --payloads /opt/cyweb/payloads`
# without mounting anything from the host.

# Trixie (Debian 13) ships glibc 2.40, which is required because the
# release matrix builds linux-amd64 on `ubuntu-latest` (Ubuntu 24.04 =
# glibc 2.39) and linux-arm64 on `ubuntu-24.04-arm` (also glibc 2.39).
# Bookworm (12) only has glibc 2.36, so the binary fails to load with:
#   /usr/local/bin/cyweb: /lib/x86_64-linux-gnu/libc.so.6:
#   version `GLIBC_2.39' not found
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
 && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
WORKDIR /opt/cyweb

COPY cyweb-linux-${TARGETARCH} /usr/local/bin/cyweb
RUN chmod +x /usr/local/bin/cyweb \
 && /usr/local/bin/cyweb version

COPY payloads /opt/cyweb/payloads
COPY rules    /opt/cyweb/rules

# Sprint v0.8.1 — image-baked converted templates. Populated at
# release time by the upstream-templates conversion step in
# release.yml (which runs `cyweb convert-templates` against the
# projectdiscovery/nuclei-templates community repo). Build context
# always includes a `templates-converted/` directory; even when
# empty, the COPY below is a no-op rather than a failure.
COPY templates-converted /opt/cyweb/templates

ENV CYWEB_PAYLOADS_DIR=/opt/cyweb/payloads \
    CYWEB_RULES_DIR=/opt/cyweb/rules \
    CYWEB_TEMPLATES_DIR=/opt/cyweb/templates

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/cyweb"]
CMD ["--help"]
