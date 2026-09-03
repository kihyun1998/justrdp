#!/usr/bin/env python3
"""thegraph `verify` inbound guard (justrdp) — sacred paths x the diff.

Build stamp: thegraph is the whole skill DIRECTORY as of this stamp --
  SKILL.md          md5:2d6a25ea8bb45587bd1f78316ffdff87
  NODES.md          md5:6f3b044bece13d2e7ab24ddaf88b8944
  BUILD_CONTRACT.md md5:a4fc95f7e6d1605869a33e8c2bafb2c6
  DELEGATION.md     md5:bb6ef36e828ab465c4cbfc60fb04f5b5
  CREATION-LOG.md   md5:dbee47f193894a7bf7711239ebdc0a51   (2026-09-04)
Graph: docs/agents/thegraph.md. Method: the `thegraph` skill.

This is the guard's `code` decider. A hit makes the adversarial completeness pass
MANDATORY and it OVERRIDES judgement -- you do not reason your way out of it
because the diff looks small. Absent a hit the guard falls back to enumeration
risk, which is an `AI` judgement and not this script's business.

Exit codes:
    0   no sacred path in the diff  -- the guard did not fire
    10  a sacred path is in the diff -- the pass is mandatory (both lenses)
    2   the script could not answer (bad ref, not a git repo, or an EMPTY DIFF --
        `classify`'s open-decision route runs `verify` on the OPTIONS before any
        code exists, so "no sacred path in the diff" is not what is true there)

Usage:
    python scripts/thegraph/triggers.py                 # vs merge-base with master
    python scripts/thegraph/triggers.py --base HEAD~1
    python scripts/thegraph/triggers.py --staged
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys

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

# --- justrdp's sacred paths (docs/agents/thegraph.md, `verify`) ---------------
#
# Group 1's globs are CRATE-LEVEL AND DELIBERATELY OVER-BROAD. Over-triggering
# costs one lens run; every narrower derivation went blind on a real class --
# #241/#238, where the no-panic census's derivations were byte-scoped and
# path-scoped, so one could not see a parser in the core and neither could
# describe a consumption site at all. Both classes held live defects. Do not
# narrow these without a record that says why.

SACRED = [
    (
        "1. untrusted-input decoders, parsers, and consumption sites",
        [
            "crates/justrdp-pdu/src/*",
            "crates/justrdp-codecs/src/*",
            "crates/justrdp/src/*",
        ],
        "a wrong bound yields plausible pixels or a panic (DoS), not an error; "
        "see docs/map/invariant/untrusted-decode-never-panics.md",
    ),
    (
        "2. the TLS trust decision",
        [
            "crates/justrdp-tokio/src/trust.rs",
            "crates/justrdp/src/tls.rs",
        ],
        "silent by construction: a wrongly-accepted chain produces a perfectly "
        "working session (ADR-0005, #36)",
    ),
    (
        "3. the NLA credential path",
        [
            "crates/justrdp-tokio/src/lib.rs",
            "crates/justrdp/src/tls.rs",
            "crates/justrdp/src/connect.rs",
        ],
        "a wrong SPKI binding or token order can still complete a handshake "
        "(ADR-0004)",
    ),
]

# Group 3 has a second trigger that is not a path: an `sspi` version bump.
# ADR-0004 requires the real-VM suite for one.
MANIFESTS = ["Cargo.toml", "Cargo.lock", "crates/justrdp-tokio/Cargo.toml"]


def run(args: list[str]) -> str:
    # Explicit UTF-8: git emits it, and a cp949 console default turns a
    # non-ASCII path or diff line into a UnicodeDecodeError.
    proc = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        sys.stderr.write(f"triggers: `{' '.join(args)}` failed:\n{proc.stderr}")
        raise SystemExit(2)
    return proc.stdout


def changed_files(base: str | None, staged: bool) -> list[str]:
    if staged:
        out = run(["git", "diff", "--name-only", "--cached"])
    elif base:
        out = run(["git", "diff", "--name-only", f"{base}...HEAD"])
    else:
        merge_base = run(["git", "merge-base", "HEAD", "master"]).strip()
        out = run(["git", "diff", "--name-only", f"{merge_base}...HEAD"])
        if not out.strip():
            # Nothing committed on the branch yet -- fall back to the worktree,
            # so the guard answers during implementation and not only after.
            out = run(["git", "diff", "--name-only", "HEAD"])
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]


def matches(path: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(path, pat):
            return True
        # `crates/x/src/*` is meant as a whole-subtree glob, not one level.
        if pat.endswith("/*") and path.startswith(pat[:-1]):
            return True
    return False


def sspi_bump(files: list[str], base: str | None) -> bool:
    touched = [f for f in files if f in MANIFESTS]
    if not touched:
        return False
    ref = base or "HEAD"
    diff = subprocess.run(
        ["git", "diff", ref, "--", *touched],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).stdout
    return any(
        line.startswith(("+", "-")) and "sspi" in line and "=" in line
        for line in diff.splitlines()
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", help="compare against this ref instead of merge-base/master")
    ap.add_argument("--staged", action="store_true", help="use the staged diff")
    args = ap.parse_args()

    files = changed_files(args.base, args.staged)
    if not files:
        # Not `0`. An empty diff is `classify`'s open-decision route in its normal
        # state -- `verify` runs on the OPTIONS, before any code exists -- and
        # answering "no sacred path" there is a false negative, not a clean result.
        # Measured on #252: this returned 0, both lenses were in fact mandatory
        # (`crates/justrdp/src/**` is surface 1), and only the run's own judgement
        # caught it. A `code` decider resolved by judgement is invariant 4 pointing
        # at itself, so the script says it cannot answer and hands over what an
        # answer needs -- a judgement that read the list is not the same act as a
        # skip, and only one of the two leaves a trace.
        print(
            "triggers: the diff is empty -- the guard CANNOT ANSWER, which is not the\n"
            "          same as 'no sacred path'. `classify`'s open-decision route runs\n"
            "          `verify` on the OPTIONS before any code exists, so an empty diff\n"
            "          is that route's normal state rather than a clean one.\n"
            "          Resolve it by reading the list below against the change you are\n"
            "          ABOUT to make, and say which slot you substituted for. This is\n"
            "          NOT a `build_gaps` entry -- `2` is this script's designed answer\n"
            "          for this case, so filing a re-grill request here asks for a\n"
            "          rebuild over a question already answered, and every open-decision\n"
            "          run filed one (#268). Write a gap only if reading the list is\n"
            "          itself ambiguous: the paths are not yet knowable, or they sit\n"
            "          outside every group. Exit `2` from a NON-EMPTY diff is a real\n"
            "          'could not answer' and does carry one. Measured on #252: this\n"
            "          returned 0, both lenses were in fact mandatory, and only the\n"
            "          run's own judgement caught it."
        )
        for name, patterns, _why in SACRED:
            print(f"\n  {name}")
            for pattern in patterns:
                print(f"    - {pattern}")
        return 2

    hits: list[tuple[str, list[str], str]] = []
    for name, patterns, why in SACRED:
        hit = [f for f in files if matches(f, patterns)]
        if hit:
            hits.append((name, hit, why))

    if sspi_bump(files, args.base):
        hits.append(
            (
                "3. the NLA credential path -- an `sspi` version bump",
                MANIFESTS,
                "ADR-0004 requires the real-VM suite for a bump",
            )
        )

    print(f"triggers: {len(files)} changed file(s) examined.")
    if not hits:
        print("VERDICT: no sacred path in the diff -- the guard did not fire.")
        print("         The pass is now an enumeration-risk judgement (decider: AI).")
        return 0

    print("VERDICT: SACRED PATH HIT -- the adversarial completeness pass is")
    print("         MANDATORY, both lenses, and this overrides judgement.")
    for name, hit, why in hits:
        print(f"\n  {name}")
        print(f"    why: {why}")
        for f in sorted(set(hit))[:20]:
            print(f"    - {f}")
        if len(set(hit)) > 20:
            print(f"    ... and {len(set(hit)) - 20} more")
    return 10


if __name__ == "__main__":
    raise SystemExit(main())
