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

# Wait for sesman's authentication socket to exist before starting
# xrdp. A fixed sleep was racy on cold runners with high I/O
# contention: if sesman took longer than the sleep to open its
# socket, xrdp would come up first and refuse the first few login
# attempts, surfacing as an auth failure in the E2E client. Polling
# the actual socket file eliminates the race at the cost of one
# syscall per 100 ms until the file shows up.
SESMAN_SOCK=/var/run/xrdp/xrdp-sesman.socket
for i in $(seq 1 50); do
    if [ -S "$SESMAN_SOCK" ]; then
        break
    fi
    # Guard: if sesman died during startup we should bail rather
    # than spinning until the loop cap; its exit will not create
    # the socket and xrdp would come up orphaned.
    if ! kill -0 "$SESMAN_PID" 2>/dev/null; then
        echo "xrdp-sesman exited before opening $SESMAN_SOCK" >&2
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$SESMAN_SOCK" ]; then
    echo "xrdp-sesman did not open $SESMAN_SOCK within 5s" >&2
    exit 1
fi

# Main xrdp daemon — foreground so `exec` semantics keep it as PID 1
# of the container. `--nodaemon` is critical; without it xrdp forks
# and Docker reaps an empty parent.
exec /usr/sbin/xrdp --nodaemon
