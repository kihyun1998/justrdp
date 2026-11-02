#!/bin/bash
# #556: the whole campaign, timing runs then CPU runs, ten sessions per client, alternating
# clients so drift on the host lands on both. Writes <out>/<mode>-<client>-<nn>.txt.
#   campaign.sh <out>
set -u
here=$(dirname "$0") out=$1
mkdir -p "$out"
for mode in timing cpu; do
    for i in $(seq -w 1 10); do
        for client in justrdp freerdp; do
            echo "$(date +%T) $mode $client $i"
            bash "$here/bench.sh" "$client" "$mode" "$out/$mode-$client-$i.txt"
            # Let the previous logoff finish before the next logon.
            sleep 10
        done
    done
done
