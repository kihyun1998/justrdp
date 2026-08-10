#!/usr/bin/env python3
"""Gate for `docs/map/` — the dependency graph (hub: docs/map/README.md).

A map is a link graph, so the checks that earn their keep are the ones that keep the
edges landing and the notes addressable. Run from the repository root:

    python3 .github/scripts/check_map.py [file ...]

With no arguments it checks **every `*.md` under `docs/map/`, recursively** — the
scope is written here rather than intended, because a gate whose scope has drifted
from the tree passes having inspected nothing, which is the one failure mode
indistinguishable from a clean run. Re-derive it against `ls docs/map/` if in doubt.

What it checks, and why each one is silent without it:

1. **Links and `#anchors` resolve.** A missing file 404s and is loud; a missing
   anchor **silently** falls back to the top of the target document, so a link that
   used to land on one row starts pointing at a whole file and the reader never
   learns they were misrouted. Anchors are also the volatile half — headings get
   rewritten by routine maintenance, breaking links in files nobody touched.
2. **Every symbol and path named under `## Code` exists.** The map deliberately
   carries symbol names, never line numbers (a line number is an ungated copy of
   something the compiler owns). This is what keeps that trade honest.
3. **The section set is complete per note kind.** Empty sections are load-bearing:
   `**None.**` under `## Governing decisions` *is* the finding, so a note may not
   drop the heading to hide the hole.
4. **Invariant ↔ territory reciprocity.** Every territory an invariant claims must
   claim it back. Not symmetry for its own sake: the reading protocol sends a reader
   to their territory's `## Cross-cutting invariants` as a checklist, so an invariant
   the territory omits is invisible at exactly the moment it is needed. A vault's
   backlink panel does not cover it — that is a different surface, absent on GitHub.

Code spans and fenced blocks are blanked before link extraction, because
documentation *about* links contains link-shaped text.
"""

import glob
import os
import re
import sys

ROOT = os.path.abspath(".")
MAP = os.path.join(ROOT, "docs", "map")

TERRITORY_SECTIONS = [
    "## What it is",
    "## Governing decisions",
    "## Design model",
    "## Code",
    "## Reference behaviour",
    "## Cross-cutting invariants",
    "## Blast radius",
    "## Known holes / open",
]
INVARIANT_SECTIONS = [
    "## The fact",
    "## Why it is cross-cutting",
    "## Territories it holds in",
    "## What a violation looks like",
    "## Discovery history",
    "## Where it will recur",
]

# Roots a `## Code` path may be written against. Notes address crates by name
# (`justrdp-pdu/src/x.rs`) because the `crates/` prefix adds no information; a bullet
# may also list bare filenames under a directory named earlier in the same bullet.
PATH_ROOTS = [ROOT, os.path.join(ROOT, "crates")]

SRC_GLOBS = ("crates/*/src/**/*.rs", "crates/*/tests/*.rs", "fuzz/fuzz_targets/*.rs")


def source_text():
    files = []
    for pat in SRC_GLOBS:
        files += glob.glob(pat, recursive=True)
    if not files:
        sys.exit("map gate: no source files matched — run me from the repository root")
    return "\n".join(open(f, encoding="utf-8", errors="replace").read() for f in files)


SRC_TEXT = source_text()


def rel(path):
    try:
        return os.path.relpath(path, ROOT).replace("\\", "/")
    except ValueError:  # different drive on Windows
        return path.replace("\\", "/")


def blank_code(text):
    """Blank fenced blocks and inline spans, preserving offsets (and line numbers)."""
    out = list(text)
    for m in re.finditer(r"```.*?```", text, re.S):
        for i in range(m.start(), m.end()):
            if out[i] != "\n":
                out[i] = " "
    for m in re.finditer(r"`[^`\n]*`", "".join(out)):
        for i in range(m.start(), m.end()):
            out[i] = " "
    return "".join(out)


def slug(heading):
    s = re.sub(r"[^\w\s-]", "", heading.strip().lower())
    return re.sub(r"\s+", "-", s).strip("-")


def anchors_of(path):
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return None
    return {slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.*?)\s*$", text, re.M)}


def section(text, heading):
    m = re.search(r"^" + re.escape(heading) + r"\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1) if m else ""


def bullets(text):
    """A bullet, not a line, is the unit of context — entries wrap."""
    out, cur = [], ""
    for line in text.splitlines():
        if line.lstrip().startswith("- "):
            if cur:
                out.append(cur)
            cur = line
        else:
            cur += " " + line
    if cur:
        out.append(cur)
    return out


def kind_of(path):
    r = rel(path)
    if "/invariant/" in r:
        return "invariant"
    if "/territory/" in r:
        return "territory"
    return "hub"


def check_sections(raw, kind, errs):
    want = {"territory": TERRITORY_SECTIONS, "invariant": INVARIANT_SECTIONS}.get(kind, [])
    for s in want:
        if not re.search(r"^" + re.escape(s) + r"\s*$", raw, re.M):
            errs.append(f"missing section: {s}")


def check_links(path, body, errs):
    for m in re.finditer(r"\[[^\]\n]+\]\(([^)\s]+)\)", body):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        file_part, _, anchor = target.partition("#")
        dest = os.path.normpath(os.path.join(os.path.dirname(path), file_part)) if file_part else path
        if file_part and not os.path.exists(dest):
            errs.append(f"broken link: {target}")
            continue
        if anchor:
            known = anchors_of(dest)
            if known is not None and slug(anchor) not in known:
                errs.append(f"broken anchor: {target}")


def check_code(raw, errs):
    for bullet in bullets(section(raw, "## Code")):
        dirs = re.findall(r"`([^`\n]*/)`", bullet)
        for tok in (t.strip() for t in re.findall(r"`([^`\n]+)`", bullet)):
            if tok.startswith("[MS-") or any(c in tok for c in '"|$'):
                continue  # spec citation or shell fragment
            if tok.split(" ")[0] in ("grep", "ls", "rg", "cargo", "python", "python3", "sed"):
                continue  # a derivation command, not a name
            if "/" in tok or tok.endswith((".rs", ".toml", ".yml")):
                p = tok.rstrip("/")
                roots = PATH_ROOTS + [os.path.join(r, d) for d in dirs for r in PATH_ROOTS]
                if not any(os.path.exists(os.path.join(r, p)) for r in roots):
                    errs.append(f"path under ## Code does not exist: {tok}")
                continue
            name = re.split(r"[^A-Za-z0-9_:]", tok)[0].split("::")[-1]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""):
                continue
            if not re.search(r"\b" + re.escape(name) + r"\b", SRC_TEXT):
                errs.append(f"symbol not found in tree: {name}  (from `{tok}`)")


def check_sentinel(raw, errs):
    """`**None.**` marks three different holes, so it must sit under a heading."""
    for m in re.finditer(r"^\*\*None\.\*\*", raw, re.M):
        if not re.findall(r"^## .*$", raw[: m.start()], re.M):
            errs.append("sentinel **None.** appears before any section heading")


def check_file(path):
    errs = []
    raw = open(path, encoding="utf-8").read()
    check_sections(raw, kind_of(path), errs)
    check_links(path, blank_code(raw), errs)
    check_code(raw, errs)
    check_sentinel(raw, errs)
    return errs


def check_reciprocity():
    """Every territory an invariant claims must claim it back, and vice versa."""
    claims, listed = {}, {}
    for p in sorted(glob.glob(os.path.join(MAP, "invariant", "*.md"))):
        body = section(open(p, encoding="utf-8").read(), "## Territories it holds in")
        claims[os.path.basename(p)] = set(re.findall(r"\(\.\./territory/([a-z0-9-]+\.md)\)", body))
    for p in sorted(glob.glob(os.path.join(MAP, "territory", "*.md"))):
        body = section(open(p, encoding="utf-8").read(), "## Cross-cutting invariants")
        listed[os.path.basename(p)] = set(re.findall(r"\(\.\./invariant/([a-z0-9-]+\.md)\)", body))
    errs = []
    for inv, terrs in claims.items():
        for t in terrs:
            if t not in listed:
                errs.append(f"{inv} claims a territory that does not exist: {t}")
            elif inv not in listed[t]:
                errs.append(f"one-way edge: invariant/{inv} claims {t}, which does not list it back")
    for terr, invs in listed.items():
        for i in invs:
            if i not in claims:
                errs.append(f"{terr} lists an invariant that does not exist: {i}")
            elif terr not in claims[i]:
                errs.append(f"one-way edge: territory/{terr} lists {i}, which does not claim it")
    return errs


def main():
    targets = sys.argv[1:] or sorted(glob.glob(os.path.join(MAP, "**", "*.md"), recursive=True))
    if not targets:
        sys.exit("map gate: no notes found under docs/map/ — has the scope drifted?")
    failing = 0
    for t in targets:
        errs = check_file(t)
        if errs:
            failing += 1
            print(f"FAIL {rel(t)}")
            for e in errs:
                print(f"     - {e}")
        else:
            print(f"ok   {rel(t)}")

    recip = check_reciprocity() if len(sys.argv) == 1 else []
    if recip:
        failing += 1
        print("FAIL reciprocity (invariant <-> territory)")
        for e in recip:
            print(f"     - {e}")
    else:
        print("ok   reciprocity (invariant <-> territory)")

    print(f"\n{len(targets)} note(s) checked, {failing} failing")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
