#!/usr/bin/env python3
"""thegraph slot-authority check (justrdp) -- every DERIVED slot vs the fact it names.

Build stamp: thegraph is the whole skill DIRECTORY as of this stamp --
  SKILL.md          md5:2d6a25ea8bb45587bd1f78316ffdff87
  NODES.md          md5:6f3b044bece13d2e7ab24ddaf88b8944
  BUILD_CONTRACT.md md5:a4fc95f7e6d1605869a33e8c2bafb2c6
  DELEGATION.md     md5:bb6ef36e828ab465c4cbfc60fb04f5b5
  CREATION-LOG.md   md5:dbee47f193894a7bf7711239ebdc0a51   (2026-09-04)
Graph: docs/agents/thegraph.md. Method: the `thegraph` skill.

WHY THIS EXISTS
---------------
Every slot in the graph doc is one of two classes, and the class decides what can
ever tell you it is wrong.

  DERIVED  a copy of a fact that lives somewhere else. Being a copy it is NEVER
           EMPTY: it fails by being silently wrong, and no node notices, because
           a node handed a value uses it.
  DECIDED  the maintainer's judgement, with no fact anywhere to check it against.

`build_gaps` -- the graph's own drift detector -- fires where a slot came up
EMPTY. It cannot see the derived class at all. Measured: three consecutive
updates arrived with an empty gap queue and every one of them found real drift,
all of it derived, all of it caught by a person diffing by hand.

So this script is the detector for the other class. It is a gate, which means a
drifted copy is a red build rather than something the next build discovers by
looking.

BOTH DIRECTIONS, ALWAYS
-----------------------
Every check runs both ways: the fact is in the doc, AND nothing in the fact is
missing from the doc. A one-way check passes happily over a record, a gate, an
agent or a sacred path the doc never learned about -- which is the shape of every
finding this script was written after.

A STAMP IS NOT A ROOT
---------------------
A revision written into a file labels it; nothing compares it to anything that
could have changed. So the stamp is a ROW HERE rather than a mechanism of its
own, and it hashes the skill DIRECTORY: a list of N files is blind to file N+1,
which is exactly how DELEGATION.md -- the file holding the `**Runs:**` form
grants.py enforces -- arrived unseen between two builds.

WHAT IS NOT CHECKED IS DECLARED
-------------------------------
An unassertable slot that announces itself is a known hole; one that says nothing
is indistinguishable from a checked one. UNASSERTABLE below is printed on every
run for that reason -- a slot cannot leave the map by going quiet.

Exit codes:
    0   every derived slot agrees with the fact it names
    1   at least one slot has drifted (the summary names which)
    2   the check could not answer (graph doc missing or unparseable)

Usage:
    python scripts/thegraph/authority.py
    python scripts/thegraph/authority.py --skill-dir ~/.claude/skills/thegraph
    python scripts/thegraph/authority.py --list
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.util
import os
import re
import sys

# This console defaults to cp949, so printing any non-ASCII byte raises
# UnicodeEncodeError at the point of USE even though the decode succeeded --
# the ADR-0012 shape, and the reason gates.py carries the identical block.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except (AttributeError, ValueError):  # not a reconfigurable text stream
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
DOC = os.path.join(ROOT, "docs", "agents", "thegraph.md")

DEFAULT_SKILL_DIR = os.path.expanduser(os.path.join("~", ".claude", "skills", "thegraph"))

# The slots this script CANNOT assert, and why. Printed every run. Each is a
# DECIDED slot -- judgement with no in-repo fact to compare against -- or a fact
# that lives outside this repository entirely.
UNASSERTABLE = [
    ("tie-breaker rows",
     "judgement about which authority wins; no in-repo fact to compare against"),
    ("deliberate-divergence rows",
     "judgement, and the other half of each row lives in FreeRDP/IronRDP source "
     "this repo does not vendor. The citations resolve; the call cannot be checked"),
    ("proof method per layer, and its tautological traps",
     "judgement about what convinces -- the traps are precisely what a passing "
     "check cannot see"),
    ("sacred-path list MEMBERSHIP",
     "the paths are asserted to EXIST below; whether the list is the RIGHT list "
     "is the maintainer's, and a surface nobody named is a surface nobody guards"),
    ("boundary rule and the consumer seams",
     "CLAUDE.md states them in prose; place.py measures the dependency half, the "
     "policy half is not mechanically checkable"),
    ("reference source classes 1-3 and 5",
     "outside the repository -- a spec section, another project's tree, a "
     "registry. Derived and unassertable; dated at measurement, never checked"),
    ("reference class 4, the real VM",
     "one WS2022 box at 192.168.136.136, reachable only when it is up. An "
     "observation, not a fact this repo holds"),
]


# --- reading the graph doc ---------------------------------------------------

def section(doc: str, pattern: str) -> str:
    """Text from a heading matching `pattern` up to the next heading of the same
    or a higher level. Returns "" when the heading is absent."""
    m = re.search(pattern, doc, re.MULTILINE)
    if not m:
        return ""
    level = len(m.group(0)) - len(m.group(0).lstrip("#"))
    tail = doc[m.end():]
    nxt = re.search(r"^#{1,%d} " % level, tail, re.MULTILINE)
    return tail[: nxt.start()] if nxt else tail


def backticked(text: str, prefix: str) -> set[str]:
    """Backticked tokens beginning with `prefix`, from TABLE ROWS only -- prose
    mentions of the same path are not the doc's copy of the slot."""
    out: set[str] = set()
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        for tok in re.findall(r"`([^`]+)`", line):
            if tok.startswith(prefix):
                out.add(tok)
    return out


def norm_glob(p: str) -> str:
    """`crates/x/src/**` and `crates/x/src/*` are one path list written two ways."""
    return re.sub(r"/\*+$", "/*", p.strip())


# --- importing the sibling scripts -------------------------------------------

def sibling(name: str):
    """Import a sibling artifact for its data. Each is argparse-in-main, so an
    import runs no work."""
    path = os.path.join(HERE, name + ".py")
    spec = importlib.util.spec_from_file_location("thegraph_" + name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- the checks --------------------------------------------------------------
#
# Each returns (status, headline, [detail, ...]).
#   "ok"     the copy agrees with the fact
#   "FAIL"   it has drifted
#   "skip"   the fact is not reachable from here (never a failure, always said)

def check_stamp(doc: str, skill_dir: str):
    rows = {}
    for m in re.finditer(
        r"^\|\s*`thegraph/([^`]+)`.*?\|\s*`([0-9a-f]{32})`\s*\|\s*([\d\s]+?)\s*\|",
        doc, re.MULTILINE,
    ):
        rows[m.group(1)] = (m.group(2), int(re.sub(r"\s", "", m.group(3))))
    if not rows:
        return "FAIL", "stamp", ["no stamp table found in the graph doc"]

    if not os.path.isdir(skill_dir):
        return "skip", "stamp", [
            "%s is not present -- the method lives outside this repo, so this row"
            % skill_dir,
            "cannot answer here. It is the one row that is host-local by nature.",
            "%d file(s) are stamped: %s" % (len(rows), ", ".join(sorted(rows))),
        ]

    on_disk = {}
    for path in sorted(glob.glob(os.path.join(skill_dir, "*.md"))):
        with open(path, "rb") as fh:
            blob = fh.read()
        on_disk[os.path.basename(path)] = (hashlib.md5(blob).hexdigest(), len(blob))

    detail = []
    for name in sorted(set(on_disk) - set(rows)):
        detail.append("UNSTAMPED  %s -- a file the stamp cannot see. A list of N is "
                      "blind to file N+1." % name)
    for name in sorted(set(rows) - set(on_disk)):
        detail.append("GONE       %s -- stamped, but no longer in the skill" % name)
    for name in sorted(set(rows) & set(on_disk)):
        if rows[name] != on_disk[name]:
            detail.append("MOVED      %s -- stamped %s/%d, now %s/%d"
                          % (name, rows[name][0][:8], rows[name][1],
                             on_disk[name][0][:8], on_disk[name][1]))
    if detail:
        detail.append("The method moved. WARN AND CONTINUE -- never rebuild on your "
                      "own; a rebuild writes agents and scripts, and those pass")
        detail.append("through the maintainer. Re-run /grill-the-graph to restamp.")
        return "FAIL", "stamp", detail
    return "ok", "stamp", ["%d file(s) in %s match" % (len(rows), skill_dir)]


def check_adr_roster(doc: str):
    on_disk = set()
    for path in glob.glob(os.path.join(ROOT, "docs", "adr", "0*.md")):
        on_disk.add(os.path.basename(path)[:4])

    sec = section(doc, r"^### `search`.*$")
    in_doc = set(re.findall(r"^\|\s*(\d{4})\s*\|", sec, re.MULTILINE))

    in_script = {num for num, _ in sibling("cluster").RECORDS}

    detail = []
    for label, other in (("the graph doc", in_doc), ("cluster.py", in_script)):
        for num in sorted(on_disk - other):
            detail.append("MISSING FROM %-13s ADR-%s exists as a file" % (label, num))
        for num in sorted(other - on_disk):
            detail.append("NO SUCH FILE  %-13s ADR-%s listed in %s"
                          % ("", num, label))
    if detail:
        detail.append("`search` checks this list before proposing an anchor, so a "
                      "record missing from it gets a second home.")
        return "FAIL", "adr-roster", detail
    return "ok", "adr-roster", [
        "%d record file(s) == %d doc row(s) == %d cluster.py row(s)"
        % (len(on_disk), len(in_doc), len(in_script))]


def check_gate_count(doc: str):
    gates = sibling("gates").GATES
    n_gates = len(gates)
    n_cmds = sum(len(argvs) for _, _, argvs, _ in gates)

    claims = []
    m = re.search(r"^### `gate` — (\d+) gates, (\d+) commands", doc, re.MULTILINE)
    if m:
        claims.append(("the `gate` section heading", int(m.group(1)), int(m.group(2))))
    m = re.search(r"^\|\s*`gate`\s*\|\s*1\s*\|\s*\*\*(\d+)\*\*\s*gates\s*/\s*"
                  r"\*\*(\d+)\*\*\s*commands", doc, re.MULTILINE)
    if m:
        claims.append(("the node roster row", int(m.group(1)), int(m.group(2))))
    if not claims:
        return "FAIL", "gate-count", [
            "neither the section heading nor the roster row states a gate count"]

    detail = []
    for where, g, c in claims:
        if (g, c) != (n_gates, n_cmds):
            detail.append("%s says %d gates / %d commands; gates.py yields %d / %d"
                          % (where, g, c, n_gates, n_cmds))
    if detail:
        detail.append("A count restated where its authority is elsewhere (#49). The "
                      "runnable roster is `gates.py --list`.")
        return "FAIL", "gate-count", detail
    return "ok", "gate-count", [
        "%d gate(s) / %d command(s), agreed by %d site(s)"
        % (n_gates, n_cmds, len(claims) + 1)]


def check_sacred(doc: str):
    in_script = set()
    for _, paths, _ in sibling("triggers").SACRED:
        in_script |= {norm_glob(p) for p in paths}

    sec = section(doc, r"^### `verify`.*$")
    in_doc = {norm_glob(p) for p in backticked(sec, "crates/")}

    detail = []
    for p in sorted(in_script - in_doc):
        detail.append("NOT IN THE DOC   %s -- triggers.py guards it, the doc's table "
                      "does not name it" % p)
    for p in sorted(in_doc - in_script):
        detail.append("NOT IN THE GUARD %s -- the doc calls it sacred, triggers.py "
                      "does not match it" % p)

    # The value is a judgement; the EXISTENCE is a fact, and it is the half a
    # rename empties in silence.
    for p in sorted(in_script):
        target = os.path.join(ROOT, p[:-2] if p.endswith("/*") else p)
        if not os.path.exists(target):
            detail.append("GONE             %s -- guarded, but nothing is there" % p)

    if detail:
        detail.append("A surface nobody named is a surface nobody guards, and a "
                      "renamed one empties the guard with every copy still agreeing.")
        return "FAIL", "sacred", detail
    return "ok", "sacred", ["%d path(s), all matched by both and all resolving"
                            % len(in_script)]


def check_artifacts(doc: str):
    sec = section(doc, r"^## Extraction plan.*$")
    doc_agents = {os.path.basename(p) for p in backticked(sec, ".claude/agents/")}
    doc_scripts = {os.path.basename(p) for p in backticked(sec, "scripts/thegraph/")}

    disk_agents = {os.path.basename(p) for p in
                   glob.glob(os.path.join(ROOT, ".claude", "agents", "thegraph-*.md"))}
    disk_scripts = {os.path.basename(p) for p in
                    glob.glob(os.path.join(ROOT, "scripts", "thegraph", "*.py"))}

    detail = []
    for label, on_disk, in_doc in (("agent", disk_agents, doc_agents),
                                   ("script", disk_scripts, doc_scripts)):
        for f in sorted(on_disk - in_doc):
            detail.append("UNLISTED %-6s %s -- generated, named by no row in the "
                          "extraction plan" % (label, f))
        for f in sorted(in_doc - on_disk):
            detail.append("MISSING  %-6s %s -- the plan names it, the tree has no "
                          "such file" % (label, f))
    if detail:
        detail.append("The extraction plan IS the artifact manifest; an artifact "
                      "outside it carries a stamp nobody restamps.")
        return "FAIL", "artifacts", detail
    return "ok", "artifacts", ["%d agent(s) + %d script(s), all listed"
                               % (len(disk_agents), len(disk_scripts))]


def check_tests_rule(doc: str):
    on_disk = glob.glob(os.path.join(ROOT, "crates", "*", "tests", "*.rs"))
    sec = section(doc, r"^### `place`.*$")
    m = re.search(r"measured \*\*(\d+)/(\d+)\*\*", sec)
    if not m:
        return "FAIL", "tests-rule", [
            "the `place` tree rule states no measured count for crates/*/tests/*.rs"]
    claimed, total = int(m.group(1)), int(m.group(2))
    if claimed != total:
        return "FAIL", "tests-rule", [
            "the doc records %d/%d -- the rule itself is reported broken" % (claimed, total)]
    if total != len(on_disk):
        return "FAIL", "tests-rule", [
            "the doc records %d/%d; the tree holds %d file(s) under crates/*/tests/"
            % (claimed, total, len(on_disk)),
            "The RULE is that all of them are differential or corpus tests; only the "
            "count moves, and it moved without the doc.",
        ]
    return "ok", "tests-rule", ["%d file(s) under crates/*/tests/" % total]


def check_mod_rs():
    """The module-root spelling rule: `<area>.rs` beside `<area>/`, one
    grandfathered outlier whose move is a separate change. A NEW mod.rs is the
    rule being broken, and nothing else in the repo would say so."""
    on_disk = set()
    for path in glob.glob(os.path.join(ROOT, "crates", "*", "src", "*", "mod.rs")):
        on_disk.add(os.path.relpath(path, ROOT).replace(os.sep, "/"))
    allowed = set(sibling("place").MOD_RS_GRANDFATHERED)

    detail = []
    for p in sorted(on_disk - allowed):
        detail.append("NEW OUTLIER %s -- the 2018 form is `<area>.rs` beside "
                      "`<area>/`" % p)
    for p in sorted(allowed - on_disk):
        detail.append("MOVED       %s -- grandfathered, and now gone. Drop it from "
                      "place.py and from the doc." % p)
    if detail:
        return "FAIL", "mod-rs", detail
    return "ok", "mod-rs", ["%d grandfathered outlier(s), no new one" % len(allowed)]


CHECKS = [
    ("stamp", "the skill directory, hashed per file", check_stamp),
    ("adr-roster", "docs/adr/*.md vs the doc vs cluster.py", check_adr_roster),
    ("gate-count", "gates.py vs both places the doc states it", check_gate_count),
    ("sacred", "triggers.py vs the doc, and every path resolves", check_sacred),
    ("artifacts", ".claude/agents + scripts/thegraph vs the plan", check_artifacts),
    ("tests-rule", "crates/*/tests/*.rs vs the place rule", check_tests_rule),
    ("mod-rs", "module-root spelling, grandfathered set", check_mod_rs),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--skill-dir", default=DEFAULT_SKILL_DIR,
                    help="the thegraph skill directory (default: %(default)s)")
    ap.add_argument("--list", action="store_true",
                    help="print the slot->authority map and the unassertable roster")
    args = ap.parse_args()

    if args.list:
        print("DERIVED slots, and the fact each is a copy of:\n")
        for key, what, _ in CHECKS:
            print("  %-12s %s" % (key, what))
        print("\nUNASSERTABLE -- declared, never checked:\n")
        for slot, why in UNASSERTABLE:
            print("  %s" % slot)
            print("      %s" % why)
        return 0

    if not os.path.isfile(DOC):
        print("authority: no graph doc at %s -- cannot answer" % DOC)
        return 2
    with open(DOC, encoding="utf-8") as fh:
        doc = fh.read()

    failures = 0
    for key, _, fn in CHECKS:
        if key == "stamp":
            status, name, detail = fn(doc, args.skill_dir)
        elif key == "mod-rs":
            status, name, detail = fn()
        else:
            status, name, detail = fn(doc)
        head = detail[0] if detail else ""
        print("%-4s %-11s %s" % (status, name, head))
        for line in detail[1:]:
            print("     %s" % line)
        if status == "FAIL":
            failures += 1

    print()
    print("unassertable (declared, not checked): %d" % len(UNASSERTABLE))
    for slot, _ in UNASSERTABLE:
        print("  - %s" % slot)

    print()
    if failures:
        print("slot rooting: %d of %d derived slot(s) have drifted from the fact "
              "they name." % (failures, len(CHECKS)))
        return 1
    print("slot rooting: %d derived slot(s), each agreeing with its authority in "
          "both directions." % len(CHECKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
