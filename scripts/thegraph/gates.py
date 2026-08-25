#!/usr/bin/env python3
"""thegraph `gate` runner (justrdp) -- 8 gates, 9 commands, each run BARE.

Build stamp: thegraph/SKILL.md md5:ea2d94a3591f092e76e5ff29dbdbc3ce (2026-08-24).
Graph: docs/agents/thegraph.md. Method: the `thegraph` skill.

Why this is a script rather than a list someone types: a gate must be able to
FAIL. `cargo test ... | tail -1 && commit` always commits, because a pipeline's
exit status is the last command's and `tail` always succeeds. A gate you cannot
fail is not a gate. So every command here is spawned as an argv list with no
shell, no pipe, and no redirection, and its raw exit code is what decides.

Never move a threshold to turn a build green. There are no thresholds here to
move -- if one appears, that is the bug.

Exit codes:
    0   every gate that ran exited 0
    1   at least one gate failed (the summary names which)
    2   a gate could not be launched (binary missing, etc.)

Usage:
    python scripts/thegraph/gates.py
    python scripts/thegraph/gates.py --list
    python scripts/thegraph/gates.py --only fmt clippy
    python scripts/thegraph/gates.py --skip i686
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time

# This console defaults to cp949, so printing any non-ASCII byte raises
# UnicodeEncodeError at the point of USE even though the decode succeeded --
# the ADR-0012 shape: a guarantee held at the parser is not held at the
# consumption site. Both halves have to be named.
for _stream in (sys.stdout, sys.stderr):
    try:
        # line_buffering: when this is piped or redirected, block buffering
        # makes our own lines land AFTER a child process's output, which
        # pushed the "NOT RUN" notice below the gate it warns about.
        _stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except (AttributeError, ValueError):  # not a reconfigurable text stream
        pass

PY = sys.executable

# (key, human name, [argv, ...], note)
# A gate with more than one argv runs them in order and fails on the first
# non-zero -- used only where the first command is a genuine prerequisite.
GATES: list[tuple[str, str, list[list[str]], str]] = [
    ("fmt", "cargo fmt --all --check", [["cargo", "fmt", "--all", "--check"]], ""),
    (
        "clippy",
        "cargo clippy --workspace --all-targets -- -D warnings",
        [["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]],
        "",
    ),
    ("test", "cargo test --workspace", [["cargo", "test", "--workspace"]], ""),
    (
        "fuzz-check",
        "cargo check --manifest-path fuzz/Cargo.toml",
        [["cargo", "check", "--manifest-path", "fuzz/Cargo.toml"]],
        "`fuzz` is OUT of the workspace (own [workspace]), so `cargo test "
        "--workspace` does not even build it. A public-API change needs this.",
    ),
    (
        "map-selftest",
        "check_map.py --selftest",
        [[PY, ".github/scripts/check_map.py", "--selftest"]],
        "the gate's own defect kinds, first -- it must fail on each of them.",
    ),
    (
        "map",
        "check_map.py",
        [[PY, ".github/scripts/check_map.py"]],
        "docs/map: links, #anchors, `## Code` symbols at the path their bullet "
        "names (#224), section sets, invariant<->territory reciprocity.",
    ),
    (
        "shield",
        "just-shield scan . --strict",
        [["just-shield", "scan", ".", "--strict"]],
        "ADR-0006 SHA-pinned actions; CI passes strict: true.",
    ),
    (
        "i686",
        "cargo test -p justrdp-codecs -p justrdp --target i686-pc-windows-msvc",
        [
            ["rustup", "target", "add", "i686-pc-windows-msvc"],
            [
                "cargo",
                "test",
                "-p",
                "justrdp-codecs",
                "-p",
                "justrdp",
                "--target",
                "i686-pc-windows-msvc",
            ],
        ],
        "the ONLY gate that can reach the dimension-overflow class -- on x86-64 a "
        "wrapping width*height*bpp is merely a large number. The `target add` is a "
        "prerequisite, not ceremony: a rustup target is per-toolchain, so "
        "ADR-0013's pin means one added under the old default is absent under the "
        "pinned one. Names BOTH crates: two of the five territories the invariant "
        "covers (EGFX surface allocation, the framebuffer) live in `justrdp`.",
    ),
]

BLIND_SPOTS = """
Blind spots these gates do NOT cover -- recorded so nothing reads as covered:
  - OS. CI is ubuntu-latest, this host is Windows MSVC. The local gates mirror CI
    only because the compiler is pinned (ADR-0013, #235); the residue that pin
    does not cover is a platform-conditional path.
  - The fuzz lane is NIGHTLY-only (fuzz.yml, #99), so a *new* fuzz target is not
    covered by the PR gate on the day it lands.
  - coverage.yml is deliberately not a gate: no threshold, post-merge/dispatch,
    and it excludes justrdp-tokio (its tests need the real VM).
  - justrdp-tokio's integration tests are #[ignore]d by design -- they need the VM
    at 192.168.136.136, so `cargo test --workspace` green says nothing about them.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="list the gates and exit")
    ap.add_argument("--only", nargs="+", metavar="KEY", help="run only these gates")
    ap.add_argument("--skip", nargs="+", metavar="KEY", default=[], help="skip these gates")
    args = ap.parse_args()

    if args.list:
        for key, name, _, note in GATES:
            print(f"{key:14} {name}")
            if note:
                print(f"{'':14}   {note}")
        print(BLIND_SPOTS)
        return 0

    selected = [g for g in GATES if (not args.only or g[0] in args.only) and g[0] not in args.skip]
    if args.skip or args.only:
        left_out = [g[0] for g in GATES if g not in selected]
        if left_out:
            print(f"NOT RUN (say so in the PR): {', '.join(left_out)}\n")

    results: list[tuple[str, str, int, float]] = []
    for key, name, argvs, _ in selected:
        print(f"\n===== {key}: {name}")
        started = time.time()
        code = 0
        for argv in argvs:
            if shutil.which(argv[0]) is None:
                print(f"  cannot launch: `{argv[0]}` is not on PATH")
                code = 127
                break
            # BARE: no shell, no pipe, no redirection. The exit code is the gate's.
            code = subprocess.run(argv).returncode
            if code != 0:
                break
        results.append((key, name, code, time.time() - started))

    print("\n===== summary")
    failed = [r for r in results if r[2] != 0]
    for key, name, code, secs in results:
        mark = "PASS" if code == 0 else f"FAIL({code})"
        print(f"  {mark:9} {key:14} {secs:6.1f}s  {name}")

    if any(r[2] == 127 for r in results):
        print("\nA gate could not be launched -- that is not a pass.")
        return 2
    if failed:
        print(f"\n{len(failed)} gate(s) failed. Guard on the `gate` back-edge: fix and re-run.")
        print("Bound: three consecutive failures with the SAME signature are a")
        print("design question -- route to the maintainer, not to a fourth fix.")
        return 1
    print("\nAll selected gates passed.")
    print(BLIND_SPOTS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
