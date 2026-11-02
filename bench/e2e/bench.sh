#!/bin/bash
# #556: one rdpbench session per call, by one client, in one mode.
#   bench.sh <justrdp|freerdp> <timing|cpu> <out-file>
# Needs JUSTRDP_TEST_PASSWORD (rdpbench's password) and JUSTRDP_BIN (the justrdp-tokio test
# binary, built in WSL with `cargo test --release -p justrdp-tokio --lib --no-run`).
set -u
client=$1 mode=$2 out=$3
host=192.168.136.136
user=rdpbench

# `launch=exec` makes the client replace the backgrounded subshell, so `$!` is the client's pid.
run_justrdp() {
    ${launch-} env JUSTRDP_NO_LOG_CAPTURE=1 JUSTRDP_TEST_USERNAME=$user \
        JUSTRDP_TEST_PASSWORD="$JUSTRDP_TEST_PASSWORD" \
        "$JUSTRDP_BIN" tests::end_to_end_baseline_session_on_the_real_vm --exact --ignored --nocapture
}

# `mask:1928` drops EGFX 10.1, 10.5, 10.6, 10.6 ERR and 10.7 (bits 3, 7-10 of FreeRDP 3.32.1's
# capList with no AV1), and `small-cache:off` clears the cache flag, so FreeRDP advertises what
# justrdp's default EgfxConfig does: 8, 8.1, 10, 10.2, 10.3 and 10.4, AVC_DISABLED on 10.x only.
run_freerdp() {
    ${launch-} xfreerdp3 /v:$host /u:$user "/p:$JUSTRDP_TEST_PASSWORD" /cert:ignore /size:1280x800 /bpp:32 \
        /network:lan /gfx:mask:1928,small-cache:off -sound -microphone +clipboard \
        -wallpaper -window-drag -menu-anims -decorations
}

# Per-second user+system CPU ticks and RSS of $1 until it exits.
sample() {
    local pid=$1 hz
    hz=$(getconf CLK_TCK)
    echo "hz $hz"
    while [ -d /proc/$pid ]; do
        local stat rss
        stat=$(cut -d' ' -f14,15 /proc/$pid/stat 2>/dev/null) || break
        rss=$(awk '/VmRSS/ {print $2}' /proc/$pid/status 2>/dev/null)
        echo "$(date +%s.%N) $stat $rss"
        sleep 1
    done
}

if [ "$mode" = timing ]; then
    if [ "$client" = freerdp ]; then
        export WLOG_FILTER="com.freerdp.core.rdp:DEBUG,com.freerdp.channels.rdpgfx.client:TRACE"
    fi
    "run_$client" > "$out" 2>&1
else
    launch=exec
    "run_$client" > "$out.log" 2>&1 &
    pid=$!
    sample $pid > "$out"
    wait $pid
fi
