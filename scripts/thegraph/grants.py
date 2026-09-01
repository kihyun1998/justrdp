#!/usr/bin/env python3
"""thegraph invariant (1) check (justrdp) -- a generated agent's grant vs its brief.

Build stamp: thegraph is THREE files as of this stamp --
  SKILL.md          md5:f73cef09189056e3ed7713a81177becc
  NODES.md          md5:82d1538acc2c35dd2fbcb3cecded3f66
  BUILD_CONTRACT.md md5:a4fc95f7e6d1605869a33e8c2bafb2c6   (2026-09-02)
Graph: docs/agents/thegraph.md. Method: the `thegraph` skill.

WHY THIS IS A GATE AND NOT A PARAGRAPH
--------------------------------------
A delegated node is licensed on the grounds that it reads without adjudicating.
The license is the GRANT, not the claim: a write-capable tool in `tools:` IS the
node being able to write, whatever the prose above it says. And a grant wider
than its brief is invisible to every other gate in this repo -- it compiles, it
tests green, it lints clean. So invariant (1) is enforced here or nowhere.

This build shipped the defect once. All four agents carried `Bash`, one carried
`Edit`, and no brief asked for a command. One of them mutated a live working tree
while the refuting pass was reading that same tree; the refuter then reported a
failure it could not reproduce.

ASSERT THE DEFAULT, NEVER THE CLAIM
-----------------------------------
Read-only is the DEFAULT. This script never looks for the words "read-only" --
that check was written first and let through an agent whose description said
"proposes edits rather than making them": same claim, different words, no
violation. A check a rephrase can dodge is not a check.

The only thing that moves an agent off the default is an explicit declaration
line that NAMES the tool it licenses. A declaration naming no tool licenses
nothing -- "**Runs:** nothing much" was enough to pass the first form of this
rule, which is the claim-nobody-verifies standing in for the claim nobody
verified, one level in.

Exit codes:
    0   every generated agent's grant is licensed by its brief
    1   at least one violation (an unlicensed write-capable tool)
    2   the script could not answer (no agent directory, unreadable frontmatter)

Usage:
    python scripts/thegraph/grants.py
    python scripts/thegraph/grants.py --dir .claude/agents
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys

# Tools that can change state. The property is what matters, not the name: if a
# tool can write a file, run a command, or reach the network to mutate something,
# it belongs here. Adding a delegated node that needs one means adding a
# declaration to its brief, never deleting a row from this list.
WRITE_CAPABLE = {
    "Bash",
    "BashOutput",
    "Edit",
    "Write",
    "NotebookEdit",
    "KillShell",
    "Task",
    "Agent",
}

# The declaration form invariant (1) gives. It must name each tool it licenses,
# on its own line, so the grant and the claim can be COMPARED rather than merely
# both existing.
DECL = re.compile(r"^\s*\*\*Runs:\*\*\s*(.+)$", re.MULTILINE)

PATTERN = "thegraph-*.md"


def frontmatter_tools(text: str) -> list[str] | None:
    """Return the `tools:` list, or None if there is no frontmatter at all."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    for line in text[3:end].splitlines():
        if line.startswith("tools:"):
            return [t.strip() for t in line[len("tools:"):].split(",") if t.strip()]
    return []


def licensed(text: str) -> set[str]:
    """Tools named on a declaration line. Naming none licenses none."""
    out: set[str] = set()
    for body in DECL.findall(text):
        for tool in WRITE_CAPABLE:
            # The tool must be NAMED. Prose around it is fine; absence is not.
            if re.search(r"\b%s\b" % re.escape(tool), body):
                out.add(tool)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=".claude/agents",
                    help="directory holding the generated agents")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print("grants: no agent directory at %s -- cannot answer" % args.dir)
        return 2

    files = sorted(glob.glob(os.path.join(args.dir, PATTERN)))
    if not files:
        print("grants: no %s under %s -- cannot answer" % (PATTERN, args.dir))
        return 2

    violations = 0
    for path in files:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()

        tools = frontmatter_tools(text)
        if tools is None:
            print("FAIL %s" % path)
            print("     no YAML frontmatter -- the grant cannot be read")
            violations += 1
            continue

        granted = {t for t in tools if t in WRITE_CAPABLE}
        declared = licensed(text)
        unlicensed = sorted(granted - declared)

        name = os.path.basename(path)
        if unlicensed:
            print("FAIL %s" % name)
            print("     grants %s with no declaration naming %s."
                  % (", ".join(unlicensed),
                     "it" if len(unlicensed) == 1 else "them"))
            print("     Either drop the tool, or add a line to the brief:")
            print('         **Runs:** `%s`, for one thing only -- <the command>,'
                  % unlicensed[0])
            print("         because <why Read/Glob/Grep cannot reach it>.")
            violations += 1
        elif granted:
            print("ok   %s -- %s, declared" % (name, ", ".join(sorted(granted))))
        else:
            print("ok   %s -- read-only" % name)

    print()
    if violations:
        print("invariant (1): %d of %d agent(s) carry an unlicensed "
              "write-capable tool." % (violations, len(files)))
        return 1
    print("invariant (1): %d agent(s), every grant licensed by its brief."
          % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
