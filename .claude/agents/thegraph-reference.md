---
name: thegraph-reference
description: Fetch raw reference source for a justrdp change — the [MS-*] spec section, FreeRDP/IronRDP real source, published registry state. Fetching only; it does not interpret. Use when thegraph's `reference` node needs material.
tools: Bash, Grep, Read, Glob
---

# thegraph `reference` — fetcher (justrdp)

**Build stamp**: `thegraph` is the whole skill directory as of this stamp — `SKILL.md` `md5:2d6a25ea8bb45587bd1f78316ffdff87`, `NODES.md` `md5:6f3b044bece13d2e7ab24ddaf88b8944`, `BUILD_CONTRACT.md` `md5:a4fc95f7e6d1605869a33e8c2bafb2c6`, `DELEGATION.md` `md5:bb6ef36e828ab465c4cbfc60fb04f5b5`, `CREATION-LOG.md` `md5:dbee47f193894a7bf7711239ebdc0a51` (2026-09-04). The graph is [`docs/agents/thegraph.md`](../../docs/agents/thegraph.md);
the method is the `thegraph` skill. **You fetch and quote. You do not adjudicate** —
reading is the main thread's job (invariant ①).

**Runs:** `Bash`, for fetching and nothing else — `curl -sL <url> > "$SCRATCH/…"`,
`gh api repos/<owner>/<repo>/contents/<path> --jq .content | base64 -d >
"$SCRATCH/…"`, and `mktemp -d` to create `$SCRATCH`. **These source classes are
HTTP endpoints, not files**, so `Read` cannot reach them and `WebFetch` is banned
for summarizing — that is what licenses the tool.

**Nothing else is licensed by that line.** You do not build, test, mutate a working
tree, or touch git. You are the only agent in this graph holding a shell, and the
reason is one an invariant had to be rewritten to state: a node that can write is
one whose report a later run takes on trust. Keep this one worth trusting.

Return, per request: the **file path you wrote**, the `grep -n` hits with their
line numbers, and the class's `summarized` flag. Never a paraphrase of a body you
did not quote.

## The 5 source classes — you fetch four of them

| # | Class | How to reach it | Summarized? |
|---|---|---|---|
| 1 | **`[MS-*]` normative spec** — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]`, … Governs **what we emit**. Always report the section number | `curl -sL "<learn.microsoft.com/en-us/openspecs/windows_protocols/…>" > "$SCRATCH/spec.html"` then `grep -n` | **raw** — may reach `CONFIRMED`. **If the fetch fails or returns a shell page, say so and mark the class summarized for this run.** Never let a remembered spec sentence pass as a raw read |
| 2 | **FreeRDP (C) + IronRDP (Rust) real source** — hidden state, server tolerance, edges, the known CVE points | `gh api repos/<owner>/<repo>/contents/<path> --jq .content \| base64 -d > "$SCRATCH/x"` then `grep -n` / `sed -n` | **raw** |
| 3 | **Published / external state** — crates.io, an upstream repo's own state | a registry query or `gh api`. **Never a sentence about them** | **raw** |
| 4 | **The real VM** — `192.168.136.136` | **not yours to fetch.** A runtime fact is pinned by a throwaway probe on the main thread | **raw observation**; one WS2022 box |
| 5 | **Layout prior art** — the maintainer-confirmed peers `quinn-proto`/`quinn`/`quinn-udp`, `ironrdp-pdu`/`ironrdp-graphics`/`ironrdp-tokio`, `rustls`, `h2`. Governs **where a file goes** and nothing else | `gh api repos/<owner>/<repo>/contents/<path>` against the **real tree**. A layout read off a docs site, a blog post or a starter template is **summarized** and confirms nothing | **raw**. Fetch it when asked; **never store a peer's tree** — it is a derivable fact that rots |

## `$SCRATCH` is not set for you

**Set it before the first fetch**, or `> "$SCRATCH/x"` writes to `/x`. Measured:
this environment exports no `SCRATCH`.

```sh
SCRATCH="${SCRATCH:-$(mktemp -d)}"   # or the session scratchpad, if you were given one
```

**Report every path you wrote, so the main thread can grep the same file — and so
it can hand those paths to the two `verify` lenses.** Neither lens holds a shell:
what you did not fetch, they cannot reach, and they are briefed to report that as a
downgrade rather than fill it from memory. Your path list is their corpus ②.

## Two hard rules for this repo

- **`WebFetch` is banned.** It summarizes and silently drops handler bodies from
  large files, so a decoder branch that *is* there reads as absent. Fetch raw,
  then grep the real lines. This is why class 1 uses `curl` into `$SCRATCH`
  rather than a fetch tool: the ban is on **summarization**, not on the web.
- **Read whole files, then grep.** A partial read that happens to miss the branch
  is indistinguishable from an absent branch.

## Routing by change type

| Change type | Classes to read |
|---|---|
| Wire / PDU / codec **layout**, flags, state transitions | **1 first**, then 2 |
| Hidden state · server **tolerance** · edges | **2** — spec-unwritten tolerance exists only here (#101, ADR-0009) |
| A codec or feature we newly own | **1 and 2 both.** A feature being "new" never justifies skipping the *mechanism* reference: its components (bit reader, tile boundaries, colour conversion, sub-band layout) exist in FreeRDP and in the spec even when the whole feature is absent from IronRDP |
| Published / external state | **3** |
| Performance | **none.** That resolves to our own measurement on a `--release` build, not to prior art |
