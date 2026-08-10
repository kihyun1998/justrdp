# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v` — `gh` does this automatically when run inside a clone.

## "What do I work on?" — three queries, no stored priority list

A priority list is a stored answer, and stored answers rot (this repo has measured that twice:
a closed issue tracking a live obligation, and one roster kept in two places). So the order is
**derived on the spot**:

```bash
gh issue list --label ready-for-agent          # 1. the work queue — start here
gh issue list --label needs-triage             # 2. empty queue? these need a decision from the maintainer
gh issue list --label epic                     # 3. neither? the backlog, ordered by docs/plan.md §9's MVP cut
```

**`ready-for-agent` *is* the queue.** It means "fully specified **and** startable now" — not
"specified eventually". Keep it small; a blocked item does not carry it, however well written
it is (see [triage-labels.md](triage-labels.md) for why a blocked slice with this label is a
false statement). If the queue is empty, that is a real answer: the next move is a decision,
not code.

## Crate labels — what can run in parallel

Every open issue carries one or more `crate:*` labels. They exist for one question: **can these
two be worked at the same time without colliding?** Two issues with disjoint crate sets can;
overlapping ones cannot.

```bash
gh issue list --label "crate:justrdp-codecs"   # everything touching the codecs crate
# and, to see the queue with its blast surface:
gh issue list --label ready-for-agent --json number,title,labels \
  --jq '.[] | "#\(.number) [\([.labels[].name] | map(select(startswith("crate:"))) | join(" "))] \(.title)"'
```

The mapping is **derived from the boundary rule** (ADR-0001/0002), not chosen per issue:

| Work | Crates |
|---|---|
| RDP-native wire types | `crate:justrdp-pdu` |
| Connect/session state, dispatch, framebuffer | `crate:justrdp` |
| Graphics codecs and the differential oracle | `crate:justrdp-codecs` |
| Sockets, TLS, `sspi`/NLA, and the real-VM tests | `crate:justrdp-tokio` |

A redirection or session feature is therefore almost always `pdu` + `justrdp` (wire types plus
dispatch) and **never** `tokio` — the adapter holds no protocol. An issue whose labels contradict
that is either mislabelled or is telling you the boundary is about to be crossed. The labels on
backlog `epic`s are a first pass derived from their Scope sections; correct them when the epic is
actually grilled.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.
