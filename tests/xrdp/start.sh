#!/bin/bash
# xrdp entrypoint for the JustRDP E2E CI container.
#
# Runs the xrdp session manager in the background and the main xrdp
# daemon in the foreground so Docker sees a single tracked process.
# Logging goes to stdout/stderr so `docker logs` captures it.

set -euo pipefail

# The session manager (xrdp-sesman) brokers authentication and spawns
# per-user Xorg sessions. It must run before xrdp itself so the main
# daemon has somewhere to forward successful logins.
/usr/sbin/xrdp-sesman --nodaemon &
SESMAN_PID=$!

# Give sesman a moment to open its domain socket before xrdp tries
# to connect to it. 500ms is empirically enough on GitHub runners.
sleep 0.5

# Main xrdp daemon — foreground so `exec` semantics keep it as PID 1
# of the container. `--nodaemon` is critical; without it xrdp forks
# and Docker reaps an empty parent.
exec /usr/sbin/xrdp --nodaemon
