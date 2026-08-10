# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the right-hand column to match whatever vocabulary you actually use.

## Epics and their slices carry no triage label — the tree carries the state

A triage label answers *"what does this need from a person right now?"*. Two kinds of issue
answer that structurally instead, and labelling them anyway is what destroys the label:

- **An `epic`** is by definition "large subsystem tracked for later grill + slice". The
  `epic` label already says it is not actionable yet, so a triage label on top adds nothing.
- **A slice under an epic** states its own `Depends on:` and sits in the epic's
  dependency-ordered checklist. Its state is its **position in the parent/child tree**, not a
  label — so only the *next actionable* slice takes `ready-for-agent`, and the blocked ones
  take no triage label at all.

Everything else keeps a triage label from the table above, applied on creation together with a
type label.

**Why this is written down (measured 2026-08-10).** Before this rule, `needs-triage` was on
**28 of 31** open issues — 20 of them untouched backlog epics filed in one sitting. At that
density the label cannot answer its own question: the two issues that genuinely needed a
decision were indistinguishable from the twenty that were exactly where they belonged.
Applying the rule left `needs-triage` on 2 issues, and both were real.

Corollary, learned the same day: **`ready-for-agent` on a blocked slice is a false statement.**
The label means an AFK agent can pick it up now. Labelling all six slices of an epic that way
invites someone to start slice 4 while slice 3 is unwritten.
