#!/usr/bin/env python3
"""thegraph `search` router (justrdp) -- route a candidate by the artifact it touches.

Build stamp: thegraph/SKILL.md md5:f75be113416e647c1d0df2b841f092e1 (2026-08-10).
Graph: docs/agents/thegraph.md. Method: the `thegraph` skill.

Search by the ARTIFACT -- the module, the wire field, the predicate, the config
key -- NEVER by the feature name: a related issue almost never shares your
vocabulary. The trigger is naming, not deciding: the moment you can say which
artifact a candidate touches, search. Ordering it after reproduction spends the
expensive step first, and the tracker may hold a better measurement than the one
you were about to take.

This script queries and prints. It files nothing -- nothing reaches the tracker
except through the candidate batch, which is the maintainer's node.

Usage:
    python scripts/thegraph/cluster.py progressive quant
    python scripts/thegraph/cluster.py --records
    python scripts/thegraph/cluster.py zgfx --subissues 158
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

# This console defaults to cp949, so printing a UTF-8 issue title (an em dash is
# enough) raises UnicodeEncodeError at the point of USE even though the decode
# succeeded -- the ADR-0012 shape: a guarantee held at the parser is not held at
# the consumption site. Both halves have to be named.
for _stream in (sys.stdout, sys.stderr):
    try:
        # line_buffering: when this is piped or redirected, block buffering
        # makes our own lines land AFTER a child process's output, which
        # pushed the "NOT RUN" notice below the gate it warns about.
        _stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except (AttributeError, ValueError):  # not a reconfigurable text stream
        pass

REPO = "kihyun1998/justrdp"

# Areas that ALREADY carry a decision record. Checked BEFORE proposing an anchor,
# so a cluster with a home never gets a second one. All Accepted; none Proposed --
# a *proposed* record does an anchor's job by construction and would pre-empt one.
RECORDS = [
    ("0001", "sans-IO state-machine core / crate split"),
    ("0002", "dependency boundary (+ codec-ownership amendment, #100)"),
    ("0003", "phased codecs & the differential oracle"),
    ("0004", "`sspi` contribute-and-bridge (#61)"),
    ("0005", "TLS trust policy (#36)"),
    ("0006", "supply-chain action pinning"),
    ("0007", "stage-boundary codec verification (+ assembly-layer amendment, #118)"),
    ("0008", "robustness testing -- fuzz & property (#97/#98/#99)"),
    ("0009", "tolerant negotiation posture (#101)"),
    ("0010", "`FrameUpdate` dirty-rect contract (#85)"),
    ("0011", "zero `ironrdp` as the terminal state; the oracle retires per codec (#194)"),
    ("0012", "consumption-site totality -- a parser's guarantee is not held at the point of use (#211/#233)"),
    ("0013", "pinned build inputs -- every pin names its bumper; the compiler pin (#235)"),
]

OUTCOMES = """
Four outs -- pick one and say which:
  owned-by #N     the issue already exists and owns this defect. Comment; do not
                  open a sibling. READ WHAT IT REJECTED: an issue is the durable
                  record of rejected alternatives, and a rejection resting on an
                  ADR binds your DIRECTION, not only your filing location.
  conflicts-with #N  an existing issue whose proposal your change would break.
                  Cross-link BOTH ways in the same act of filing, and say which
                  decision comes first.
  sibling-of #N   the first sign of a cluster. FIRST check --records above: if the
                  area already carries a record (accepted or proposed), the
                  throughline has a home -- file a conformance item under it and do
                  NOT open an anchor. Otherwise propose an anchor whose body is a
                  HYPOTHESIS (suspected root, what is explicitly not yet decided,
                  the exclusions). Its roster is the SUBTREE, never a list in the
                  body. An anchor opens at issue two, so the siblings that
                  motivated it are enrolled in the same batch that opens it.
  nothing         an ordinary single issue.
"""

SUBISSUE_HELP = """
Tracker parent/child: GitHub sub-issues ARE in use here (#158 carries 7).
Use the relation for new follow-ups and spines rather than another prose
convention. A `- [ ] #NNN` task list in the body does NOT create it.

Two API traps:
  - `sub_issue_id` is the issue's DATABASE id, not its number, and `gh api` needs
    -F (not -f). With -f it sends a string and the API answers 422.
  - Re-adding an existing child ALSO answers 422, with a message reading as if the
    child belonged to another parent. List the parent's sub_issues before
    believing it -- `.parent` is absent from the REST issue payload.

  gh api repos/{repo}/issues/<parent>/sub_issues --jq '.[].number'
  ID=$(gh api repos/{repo}/issues/<child> --jq .id)
  gh api --method POST repos/{repo}/issues/<parent>/sub_issues -F sub_issue_id=$ID
"""


def gh(args: list[str]) -> str:
    if shutil.which("gh") is None:
        sys.stderr.write("cluster: `gh` is not on PATH -- cannot query the tracker.\n")
        raise SystemExit(2)
    # encoding is explicit: `gh` emits UTF-8, and a Windows console default of
    # cp949 makes an em dash in an issue title a UnicodeDecodeError. Found by
    # running this path -- --records and --subissues never reach it, so the
    # green they gave was a green nobody had seen fail.
    proc = subprocess.run(
        ["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(2)
    return proc.stdout


def print_records() -> None:
    print("Areas that already carry a decision record (all Accepted; none Proposed):")
    for num, area in RECORDS:
        print(f"  ADR-{num}  {area}")
    print("\nA cluster with a home never gets a second one.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifacts", nargs="*", help="artifact terms: module, wire field, predicate, config key")
    ap.add_argument("--records", action="store_true", help="print the record-carrying areas and exit")
    ap.add_argument("--subissues", metavar="N", help="list issue N's sub-issues")
    ap.add_argument("--state", default="all", choices=["open", "closed", "all"])
    args = ap.parse_args()

    if args.records:
        print_records()
        return 0

    if args.subissues:
        out = gh(["api", f"repos/{REPO}/issues/{args.subissues}/sub_issues", "--jq", ".[].number"])
        kids = [line for line in out.split() if line]
        print(f"#{args.subissues} sub_issues ({len(kids)}): {', '.join('#' + k for k in kids) or 'none'}")
        return 0

    if not args.artifacts:
        ap.error("name at least one artifact term, or pass --records / --subissues")

    for term in args.artifacts:
        print(f"\n===== artifact: {term!r}")
        out = gh(
            [
                "issue", "list", "--repo", REPO, "--search", term, "--state", args.state,
                "--limit", "30", "--json", "number,title,state,labels",
                "--template",
                "{{range .}}  #{{.number}} [{{.state}}] {{.title}}\n{{end}}",
            ]
        )
        print(out.rstrip() or "  (no match -- but see the note below)")

    print(
        "\nA no-match is not proof of absence: search is an index, not evidence.\n"
        "If you find yourself re-deriving a neighbour's reasoning with no anchor in\n"
        "sight, THAT is the sibling signal -- and it becomes a candidate, not an\n"
        "issue you open."
    )
    print(OUTCOMES)
    print_records()
    print(SUBISSUE_HELP.replace("{repo}", REPO))
    print(
        "Filing goes through the candidate batch (`batch`, decider: human).\n"
        "Label every new issue triage + type on creation (docs/agents/triage-labels.md)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
