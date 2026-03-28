# Multi-stage build — scratch final image with pre-built static musl binary.
#
# The binary is NOT built here; CI builds stardust-amd64 / stardust-arm64 /
# stardust-riscv64 with zig cross-compilation and passes them in as build
# context.  Docker buildx automatically sets TARGETARCH to amd64, arm64, or
# riscv64 for each platform slice of the multi-arch manifest.
#
# Usage:
#   docker run --rm --network host \
#     -v /etc/stardust/config.yaml:/etc/stardust/config.yaml:ro \
#     -v stardust-state:/var/lib/stardust \
#     ghcr.io/ryannoblett/stardust
#
# DHCP requires --network host (broadcast on 255.255.255.255 does not work
# through Docker's default bridge NAT) and CAP_NET_BIND_SERVICE + CAP_NET_RAW
# (granted automatically when running as root, or add --cap-add explicitly).
#
# The config file must be mounted at /etc/stardust/config.yaml.  Set
# state_dir: "/var/lib/stardust" in the config to use the named volume.

# Use a real base only to create empty directories — scratch cannot mkdir.
# Pinned to linux/amd64 so this step always runs natively on the CI host.
FROM --platform=linux/amd64 alpine:3 AS dirs
RUN mkdir -p /etc/stardust /var/lib/stardust

FROM scratch
ARG TARGETARCH
LABEL org.opencontainers.image.title="stardust"
LABEL org.opencontainers.image.description="Lightweight DHCP server (RFC 2131/2132)"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/ryannoblett/stardust"

COPY --from=dirs /etc/stardust/  /etc/stardust/
COPY --from=dirs /var/lib/stardust/ /var/lib/stardust/
COPY stardust-${TARGETARCH} /usr/local/bin/stardust

# Mount config.yaml here (read-only):
#   -v /path/to/config.yaml:/etc/stardust/config.yaml:ro
VOLUME ["/var/lib/stardust"]
EXPOSE 67/udp

ENTRYPOINT ["/usr/local/bin/stardust", "-c", "/etc/stardust/config.yaml"]
