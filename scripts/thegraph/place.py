#!/usr/bin/env python3
"""thegraph `place` guard (justrdp) -- the tree rule x the diff.

Build stamp: thegraph is the whole skill DIRECTORY as of this stamp --
  SKILL.md          md5:2d6a25ea8bb45587bd1f78316ffdff87
  NODES.md          md5:6f3b044bece13d2e7ab24ddaf88b8944
  BUILD_CONTRACT.md md5:a4fc95f7e6d1605869a33e8c2bafb2c6
  DELEGATION.md     md5:bb6ef36e828ab465c4cbfc60fb04f5b5
  CREATION-LOG.md   md5:dbee47f193894a7bf7711239ebdc0a51   (2026-09-04)
Graph: docs/agents/thegraph.md. Method: the `thegraph` skill.

This is the `place` node's `code` decider, and it also runs again at `gate` on the
final diff. A directory boundary is where the seam is PHYSICALLY expressed, so a
file written to the wrong one breaks the seam while producing no error, no failing
test and no warning -- which is why this is a script and not a paragraph. Prose
alone would make the node a bar with no firing mechanism.

Three checks, in the order they can fail:

  1. OWNERSHIP -- every changed path is claimed by a row of the tree rule. An
     unclaimed path is the `decide` guard ("the change needs a new top-level
     area"), not a defect. `benches/` lands here on purpose: the bench-harness
     question is deliberately open in #250, so a bench directory is unowned until
     that is decided rather than silently permitted.
  2. MODULE ROOT -- `<area>.rs` + `<area>/`, the 2018 form, decided 2026-08-31
     because the evidence could not (the repo held one of each form and the
     confirmed peers disagree; quinn mixes both). One grandfathered outlier.
  3. DEPENDENCY BOUNDARY -- ADR-0001/ADR-0002 as a manifest assertion. This is the
     load-bearing half of the tree rule: the paths say where a file goes, and only
     this says whether the crate it went into is still allowed to hold it. Measured
     0 violators on 2026-08-31; this is what keeps that a fact rather than a memory.

Exit codes:
    0   every changed path is owned and no boundary is violated
    10  a boundary is VIOLATED (checks 2 or 3) -- fix before `implement`
    20  a changed path is UNOWNED (check 1) -- take the `decide` edge
    2   the script could not answer (bad ref, not a git repo, or an EMPTY DIFF --
        `classify`'s open-decision route reaches `place` with no code written, so
        "every path is owned" is not what is true there)

Usage:
    python scripts/thegraph/place.py                  # vs merge-base with master
    python scripts/thegraph/place.py --base HEAD~1
    python scripts/thegraph/place.py --staged
    python scripts/thegraph/place.py --deps-only      # check 3 alone, no diff
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys

# This console defaults to cp949, so printing any non-ASCII byte raises
# UnicodeEncodeError at the point of USE even though the decode succeeded --
# the ADR-0012 shape: a guarantee held at the parser is not held at the
# consumption site. Both halves have to be named.
for _stream in (sys.stdout, sys.stderr):
    try:
        # line_buffering: when this is piped or redirected, block buffering makes
        # our own lines land AFTER a child process's output.
        _stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except (AttributeError, ValueError):  # not a reconfigurable text stream
        pass

# --- check 1: the tree rule (docs/agents/thegraph.md, `place`) ----------------
#
# Each row is (glob, what that path owns). A changed path matching NO row is
# unowned -- which is an ANSWER (the `decide` edge), not a failure. Do not add a
# row here to silence an unowned path; add it to the graph first, or the script
# ratifies the drift it exists to catch.

OWNED: list[tuple[str, str]] = [
    ("crates/justrdp-pdu/src/*", "one file per [MS-*] protocol area; bytes<->types only"),
    ("crates/justrdp-codecs/src/*", "one codec per file; pixel math only"),
    ("crates/justrdp/src/*", "the sans-IO state machines and host-facing output types"),
    ("crates/justrdp-tokio/src/*", "the adapter -- the only home for tokio/rustls/sspi"),
    ("crates/*/tests/*", "differential-oracle and real-corpus tests only"),
    ("crates/*/proptest-regressions/*", "generated; never authored"),
    ("crates/*/Cargo.toml", "crate manifest"),
    ("crates/*/README.md", "crate readme"),
    ("Cargo.toml", "workspace manifest"),
    ("Cargo.lock", "workspace lockfile"),
    ("rust-toolchain.toml", "the compiler pin (ADR-0013)"),
    ("fuzz/fuzz_targets/*", "fuzz targets, out of the workspace"),
    ("fuzz/Cargo.toml", "the fuzz manifest, out of the workspace"),
    ("fuzz/Cargo.lock", "the fuzz lockfile, out of the workspace"),
    (".github/workflows/*", "CI gates"),
    (".github/scripts/*", "scripts that ARE CI gates"),
    ("scripts/thegraph/*", "scripts this graph runs locally, never in CI"),
    (".claude/agents/thegraph-*.md", "generated graph agents"),
    ("docs/adr/*.md", "decision records"),
    ("docs/agents/*.md", "agent contracts"),
    ("docs/map/*", "the wiring map"),
    ("docs/plan.md", "the build plan"),
    ("CLAUDE.md", "project instructions"),
    ("CONTEXT.md", "the domain model"),
    ("README.md", "repo readme"),
    ("LICENSE*", "licences"),
    (".gitignore", "version-control ignores"),
]

# --- check 2: module-root spelling -------------------------------------------
#
# `<area>.rs` beside `<area>/`, not `<area>/mod.rs`. One outlier predates the
# decision; its move is a separate change, because `plat` moves no file and a move
# made before the rule is written drifts straight back.
MOD_RS_GRANDFATHERED = {"crates/justrdp-codecs/src/rfx/mod.rs"}

# --- check 3: the dependency boundary (ADR-0001 / ADR-0002) ------------------
#
# `None` means "no external dependency at all". A name in `forbidden` may never
# appear in that crate's [dependencies]. justrdp-tokio is deliberately absent: it
# is the adapter, and holding these is its whole job.
ADAPTER_ONLY = ["tokio", "tokio-util", "rustls", "tokio-rustls",
                "rustls-platform-verifier", "sspi", "ring"]
DEP_RULE: dict[str, dict] = {
    "crates/justrdp-pdu/Cargo.toml": {
        "allowed": set(),
        "why": "justrdp-pdu is the zero-dependency wire crate (ADR-0002)",
    },
    "crates/justrdp-codecs/Cargo.toml": {
        "allowed": {"justrdp-pdu"},
        "why": "codecs own their pixel math and depend on the wire crate alone "
               "(ADR-0003); ironrdp-graphics is a DEV oracle, never a runtime dep",
    },
    "crates/justrdp/Cargo.toml": {
        "forbidden": ADAPTER_ONLY,
        "why": "the core is sans-IO and policy-agnostic -- it never reads a socket "
               "and never sees a TSRequest (ADR-0001)",
    },
}


def run(args: list[str]) -> str:
    # Explicit UTF-8: git emits it, and a cp949 console default turns a non-ASCII
    # path or diff line into a UnicodeDecodeError.
    proc = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        sys.stderr.write(f"place: `{' '.join(args)}` failed:\n{proc.stderr}")
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
            # Nothing committed on the branch yet -- fall back to the worktree, so
            # the guard answers DURING implementation and not only after, which is
            # the whole point of a node that runs before `implement`.
            out = run(["git", "diff", "--name-only", "HEAD"])
    return [ln.strip().replace("\\", "/") for ln in out.splitlines() if ln.strip()]


def matches(path: str, pattern: str) -> bool:
    if fnmatch.fnmatch(path, pattern):
        return True
    # `crates/x/src/*` is meant as a whole-subtree glob, not one level.
    if pattern.endswith("/*"):
        prefix = pattern[:-1]
        if "*" in prefix:  # e.g. crates/*/tests/* -- match segment by segment
            depth = prefix.count("/")
            head = "/".join(path.split("/")[:depth])
            return fnmatch.fnmatch(head + "/", prefix)
        return path.startswith(prefix)
    return False


def owner(path: str) -> str | None:
    for pattern, what in OWNED:
        if matches(path, pattern):
            return what
    return None


def read_deps(manifest: str) -> list[str]:
    """The crate names in a manifest's [dependencies] table.

    Deliberately not a TOML parse: the repo pins no TOML library and the map gate
    is toolchain-free by design, so this stays a stdlib script. It reads only the
    `[dependencies]` table -- `[dev-dependencies]` is where the oracle lives and
    is not what ADR-0002 constrains.
    """
    if not os.path.exists(manifest):
        return []
    names: list[str] = []
    in_deps = False
    with open(manifest, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("["):
                in_deps = line == "[dependencies]"
                continue
            if not in_deps or not line or line.startswith("#"):
                continue
            m = re.match(r'^([A-Za-z0-9_\-]+)\s*(?:\.|=)', line)
            if m:
                names.append(m.group(1))
    return names


def check_deps() -> list[str]:
    problems: list[str] = []
    for manifest, rule in DEP_RULE.items():
        deps = read_deps(manifest)
        if "allowed" in rule:
            extra = [d for d in deps if d not in rule["allowed"]]
            if extra:
                allowed = ", ".join(sorted(rule["allowed"])) or "(nothing)"
                problems.append(
                    f"{manifest}: depends on {', '.join(extra)}; allowed: {allowed}\n"
                    f"    {rule['why']}"
                )
        for bad in rule.get("forbidden", []):
            if bad in deps:
                problems.append(
                    f"{manifest}: depends on `{bad}`, which is ADAPTER-ONLY\n"
                    f"    {rule['why']}"
                )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="thegraph `place` guard for justrdp")
    ap.add_argument("--base", help="compare against this ref instead of merge-base/master")
    ap.add_argument("--staged", action="store_true", help="use the staged diff")
    ap.add_argument("--deps-only", action="store_true",
                    help="run the dependency-boundary check alone, with no diff")
    args = ap.parse_args()

    if args.deps_only:
        problems = check_deps()
        if problems:
            print("VERDICT: DEPENDENCY BOUNDARY VIOLATED (ADR-0001 / ADR-0002).")
            for p in problems:
                print(f"\n  - {p}")
            return 10
        print("place: dependency boundary intact across all three constrained crates.")
        return 0

    files = changed_files(args.base, args.staged)
    if not files:
        # Not `0`. `classify`'s open-decision route reaches `place` before any code
        # exists, so an empty diff is that route's NORMAL state -- answering "every
        # path is owned" there is a false negative, not a clean result. Same shape
        # as triggers.py's exit 2, and for the same reason: a `code` decider
        # resolved by judgement is invariant 4 pointing at itself, so the script
        # says it cannot answer and hands over what an answer needs.
        print(
            "place: the diff is empty -- the guard CANNOT ANSWER, which is not the\n"
            "       same as 'every path is owned'. Resolve it by reading the tree\n"
            "       rule in docs/agents/thegraph.md against the change you are ABOUT\n"
            "       to make, and say which slot you substituted for. This is NOT a\n"
            "       `build_gaps` entry. `place` runs BEFORE `implement`, so at the\n"
            "       position this guard is consulted the diff is empty BY\n"
            "       CONSTRUCTION -- prescribing a re-grill request here files a gap\n"
            "       on every run that reaches the node. The second call site is\n"
            "       `gate`, on the final diff, where an empty one means nothing was\n"
            "       changed, which is not drift either. So there is no position\n"
            "       where this is a gap. Same answer as triggers.py: one quantity,\n"
            "       one answer across the family."
        )
        return 2

    unowned = [f for f in files if owner(f) is None]
    bad_mod = [
        f for f in files
        if f.endswith("/mod.rs") and f.startswith("crates/")
        and f not in MOD_RS_GRANDFATHERED
    ]
    dep_problems = check_deps()

    print(f"place: {len(files)} changed file(s) examined.")

    if bad_mod or dep_problems:
        print("VERDICT: TREE RULE VIOLATED -- fix before `implement`.")
        for f in bad_mod:
            area = f[: -len("/mod.rs")]
            print(f"\n  - {f}\n    module root is `{area}.rs` beside `{area}/`, not "
                  f"`mod.rs` (the 2018 form, decided 2026-08-31)")
        for p in dep_problems:
            print(f"\n  - {p}")
        if unowned:
            print(f"\n  ...and {len(unowned)} unowned path(s); re-run after fixing.")
        return 10

    if unowned:
        print("VERDICT: UNOWNED PATH(S) -- take the `decide` edge. This is an ANSWER,")
        print("         not a defect: the tree rule does not claim these, so either")
        print("         the change needs a new top-level area or it is misplaced.")
        print("         Do NOT add a row to this script to silence it -- the graph")
        print("         is amended first, or the guard ratifies the drift it exists")
        print("         to catch.")
        for f in unowned:
            note = ""
            if f.startswith(("benches/", "bench/")) or "/benches/" in f:
                note = "  <- the bench-harness question is deliberately open in #250"
            elif f.startswith("examples/"):
                note = "  <- no `examples/` yet; `downstream` is absent (nothing published)"
            print(f"    - {f}{note}")
        return 20

    print("VERDICT: every changed path is owned, the module-root form holds, and the")
    print("         dependency boundary is intact. Placement is routine -- derive it,")
    print("         do not ask.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
