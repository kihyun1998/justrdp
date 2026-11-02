"""#556: turn the campaign's run files into per-client medians and spreads."""
import glob
import json
import os
import re
import statistics
import sys

RUNS = sys.argv[1]
# Where the animation starts and the session ends, in seconds from the CPU sampler's start, read
# off the median per-second series this script prints.
HEAVY_FROM_S, HEAVY_TO_S = 47, 80
MILESTONES = ["nla", "mcs", "finalization", "active", "first_graphics"]


def ms_of(stamp):
    h, m, s, ms = map(int, stamp.split(":"))
    return ((h * 60 + m) * 60 + s) * 1000 + ms


def justrdp_timing(path):
    line = next(l for l in open(path, encoding="utf-8", errors="replace") if l.startswith("E2E "))
    d = json.loads(line[4:])
    st = d["stages"]
    return {
        "nla": st["nla-credssp"],
        "mcs": st["capability-exchange"],
        "finalization": st["activation"],
        "active": d["active_ms"],
        "first_graphics": d["first_graphics_ms"],
        "latency_p50_us": d["latency_p50_us"],
        "latency_p95_us": d["latency_p95_us"],
        "frames": d["frames"],
    }


def freerdp_timing(path):
    t = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\[(\d+:\d+:\d+:\d+)\]", line)
        if not m:
            continue
        at = ms_of(m.group(1))
        if "CONNECTION_STATE_INITIAL --> CONNECTION_STATE_NEGO" in line:
            t.setdefault("t0", at)
        elif "--> CONNECTION_STATE_NLA" in line:
            t.setdefault("nla", at)
        elif "--> CONNECTION_STATE_MCS_CREATE_REQUEST" in line:
            t.setdefault("mcs", at)
        elif "--> CONNECTION_STATE_FINALIZATION" in line:
            t.setdefault("finalization", at)
        elif "--> CONNECTION_STATE_ACTIVE" in line:
            t.setdefault("active", at)
        elif "RecvStartFramePdu" in line:
            t.setdefault("first_graphics", at)
    t0 = t.pop("t0")
    return {k: v - t0 for k, v in t.items()}


def cpu(path):
    lines = open(path).read().split("\n")
    hz = int(lines[0].split()[1])
    rows = [l.split() for l in lines[1:] if len(l.split()) == 4]
    t = [float(r[0]) for r in rows]
    ticks = [int(r[1]) + int(r[2]) for r in rows]
    rss = [int(r[3]) for r in rows]
    per_s = [
        100 * (ticks[i + 1] - ticks[i]) / hz / (t[i + 1] - t[i]) for i in range(len(rows) - 1)
    ]

    def cpu_s(start, end):
        inside = [k for x, k in zip(t, ticks) if start <= x - t[0] < end]
        return (inside[-1] - inside[0]) / hz if len(inside) > 1 else 0.0

    return {"t": [x - t[0] for x in t[1:]], "cpu": per_s, "rss_kb": rss[1:],
            "total_cpu_s": (ticks[-1] - ticks[0]) / hz, "peak_rss_kb": max(rss),
            "pre_heavy_cpu_s": cpu_s(0, HEAVY_FROM_S), "heavy_cpu_s": cpu_s(HEAVY_FROM_S, HEAVY_TO_S)}


def summary(values):
    values = sorted(values)
    return {"median": statistics.median(values), "min": values[0], "max": values[-1], "n": len(values)}


out = {}
for client, parse in [("justrdp", justrdp_timing), ("freerdp", freerdp_timing)]:
    runs = [parse(p) for p in sorted(glob.glob(os.path.join(RUNS, f"timing-{client}-*.txt")))]
    keys = MILESTONES + (["latency_p50_us", "latency_p95_us", "frames"] if client == "justrdp" else [])
    out[f"timing/{client}"] = {k: summary([r[k] for r in runs if k in r]) for k in keys if any(k in r for r in runs)}
    samples = [cpu(p) for p in sorted(glob.glob(os.path.join(RUNS, f"cpu-{client}-*.txt")))]
    if samples:
        out[f"cpu/{client}"] = {
            "total_cpu_s": summary([s["total_cpu_s"] for s in samples]),
            "pre_heavy_cpu_s": summary([s["pre_heavy_cpu_s"] for s in samples]),
            "heavy_cpu_s": summary([s["heavy_cpu_s"] for s in samples]),
            "peak_rss_mb": summary([s["peak_rss_kb"] / 1024 for s in samples]),
        }
        # Per-second series, as the median over runs, for picking the phase windows.
        n = min(len(s["cpu"]) for s in samples)
        out[f"cpu/{client}/series"] = [round(statistics.median(s["cpu"][i] for s in samples), 1) for i in range(n)]
print(json.dumps(out, indent=1))
