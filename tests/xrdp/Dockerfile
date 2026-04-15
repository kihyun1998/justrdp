# xrdp-based RDP server for JustRDP end-to-end CI.
#
# Produces a disposable container that:
#   - installs xrdp + xorgxrdp + a minimal XFCE desktop
#   - creates a test user `testuser` with password `testpass`
#   - launches xrdp in the foreground so Docker can track the PID
#   - listens on 3389/tcp for RDP connections
#
# Build:
#   docker build -t justrdp-xrdp -f tests/xrdp/Dockerfile tests/xrdp
#
# Run:
#   docker run --rm -p 3389:3389 --name justrdp-xrdp justrdp-xrdp
#
# Stop:
#   docker stop justrdp-xrdp
#
# CI uses this image from .github/workflows/e2e-xrdp.yml. The image is
# intentionally not published — every CI run rebuilds it so a
# contributor editing this file does not have to push a new tag.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install xrdp + a real X11 session. xorgxrdp provides the Xorg
# module that xrdp spawns per-session; without it xrdp falls back to
# VNC which some clients do not negotiate. xfce4 is the lightest
# full desktop we can get that pulls in a working session manager;
# xfce4-session is what xrdp actually invokes.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        xrdp \
        xorgxrdp \
        xfce4 \
        xfce4-session \
        dbus-x11 \
        sudo \
        procps \
        net-tools \
        iproute2 \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Test account. Password is baked in because this image only runs
# inside ephemeral CI containers with no inbound network exposure
# outside the runner — never publish this image.
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:testpass' | chpasswd && \
    adduser testuser sudo && \
    echo 'testuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# xrdp ships with a self-signed TLS key pair that requires being a
# member of the `ssl-cert` group to read. Add xrdp to that group so
# the daemon can read /etc/ssl/private/ssl-cert-snakeoil.key at
# startup.
RUN adduser xrdp ssl-cert

# Tell xrdp which session to start for testuser. startxfce4 is the
# canonical entry point for an XFCE session.
RUN echo 'startxfce4' > /home/testuser/.xsession && \
    chown testuser:testuser /home/testuser/.xsession

COPY start.sh /usr/local/bin/start-xrdp.sh
RUN chmod +x /usr/local/bin/start-xrdp.sh

EXPOSE 3389/tcp

# Healthcheck: xrdp is ready once it is listening on 3389. The CI
# workflow also polls for this before invoking connect_test.
HEALTHCHECK --interval=2s --timeout=2s --start-period=10s --retries=30 \
    CMD ss -ltn | grep -q ':3389 ' || exit 1

ENTRYPOINT ["/usr/local/bin/start-xrdp.sh"]
