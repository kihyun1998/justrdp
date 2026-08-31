---
name: thegraph-sweep
description: Sweep every justrdp surface that describes a behavior after it moves — CONTEXT.md/ADRs, docs/plan.md, docs/map, Cargo.toml dependency comments, rustdoc, and now-false rationale. Use for thegraph's `sweep` node.
tools: Bash, Grep, Read, Glob, Edit
---

# thegraph `sweep` — surface sweeper (justrdp)

**Build stamp**: `thegraph/SKILL.md` `md5:7c624aedc9521627fc1985d2eae61b0d`
(2026-08-31). The graph is [`docs/agents/thegraph.md`](../../docs/agents/thegraph.md);
the method is the `thegraph` skill.

No substantive change ends at the code. Every surface that *describes* the
behaviour drifts the moment the behaviour moves, and **nothing compiles the drift
away**. Report per surface: touched, or checked-and-clean. One instance per
surface.

| # | Surface | What to do |
|---|---|---|
| 1 | **`CONTEXT.md` glossary + `docs/adr/`** | A **write** surface, not only a read one. If the change altered what a domain term *means*, update the glossary in the same change. If it **falsified a record's premise**, amend *that record* — a status note, a superseded-by line, an inline Amendment (ADR-0002 and ADR-0007 are the models; they carry amendments rather than being rewritten). An ADR's `Consequences` must be **currently true** |
| 2 | **`docs/plan.md`** | Keep the slice's entry (§2–§23) honest. Add to **§0** any trap the real VM just proved, so it is not re-discovered a third time |
| 3 | **[`docs/map/`](../../docs/map/README.md)** | Two obligations. ① **Coverage** — is the touched territory present, is its `## Blast radius` still right? (May lag.) ② **Promotion** — *is the fact this fix revealed also true outside this territory?* Answer by grep in this repo's terms: **does it hold at any site that sizes a buffer from server-declared dimensions, parses an untrusted length, or forwards pixel data?** If yes, **the change does not land until an `invariant/` note exists.** This one **may not lag** — the first site to hit a fact is where it is discovered, and at that moment no note exists (#151→#155, #85→#162→#163) |
| 4 | **`Cargo.toml` dependency comments** | Each states *why* a crate is here and, where temporary, **what ends it**. Load-bearing and unchecked by any gate: the `sspi` fork-bridge comment outlived its condition by six weeks (ADR-0004 Amendment, 2026-08-10). If a dependency's rationale changed, the comment is part of the change |
| 5 | **Rustdoc on the public surface** | Ships verbatim as the crate's API docs — the surface most likely to still describe the old behaviour, and often the **last thing describing a fixed bug as a contract** |
| 6 | **Recent rationale** — PR bodies, issues, ADR prose | **Reclaim what is now false.** A justification written in an earlier change can be made false by a later one and nobody re-reads it. Walk the recent rationale for the artifacts touched and retract what the new behaviour falsified; the surviving reasons are usually the transitive ones |

## Two surfaces that are deliberately not on this list

- **Changelog: none.** No `CHANGELOG.md` and nothing published, so there is no
  snapshotted release note that could disagree with a registry. Revisit at the
  first crates.io publish.
- **The cluster anchor** is `spine`'s flush on the main thread, not a sweep
  target. Do not write to the tracker from here.
