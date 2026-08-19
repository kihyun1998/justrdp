# Oracle agreement is not independence

## The fact

`ironrdp-graphics` is a **differential oracle**, not an authority. It shares this
project's lineage — the same spec, read the same way, by an implementation this
project was written against — so *agreement* is weaker evidence than the
byte-identical comparison makes it look, and *disagreement* does not automatically
mean justrdp is wrong.

Two consequences, and both are asymmetric:

- **Agreement** proves the two implementations made the same decisions. Where the
  spec is ambiguous, that is one reading confirmed twice, not a reading validated.
- **Disagreement** is an adjudication, not a verdict. The tie-break is FreeRDP
  and the real-server corpus — and it has already gone *against* the oracle.

## Why it is cross-cutting

Every codec claim, the pointer decoder, the licensing crypto and the PDU
round-trips all rest on the same evidence type. The limit is a property of the
*method*, not of any decoder, so it cannot be stated inside one territory without
being re-derived in the next one. It also crosses from code into process: it is the
reason ADR-0007 verifies stage boundaries, and the reason the ClearCodec corpus
exists as data rather than as a test assertion.

## Territories it holds in

- [Bitmap codecs](../territory/bitmap-codecs.md) — the primary consumer of the
  oracle.
- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — the phase-2
  rewrite's exit criterion is an oracle pass.
- [Verification harness](../territory/verification-harness.md) — where the limit
  bounds what the whole harness can claim.
- [Licensing](../territory/licensing.md) — `differential_license_crypto` is that
  territory's only proof.
- [Pointer & cursor](../territory/pointer-cursor.md) —
  `differential_pointer_ironrdp`.

## What a violation looks like

Three shapes, and none of them announces itself:

1. **A green oracle pass read as correctness.** Both implementations mishandle the
   same ambiguous field identically; the test is byte-identical and the picture is
   wrong on a server neither was tested against.
2. **A "fix" that regresses against real servers.** The oracle rejects a stream a
   real Server 2022 sends, someone treats the divergence as our bug, and the
   corpus-required tolerance is removed. `justrdp-codecs`'s own module doc records
   that ClearCodec **corrects two bit-level defects in the oracle** which otherwise
   reject genuine Server 2022 streams — so this is not hypothetical here.

3. **An owned basis that is derived too narrowly to be independent of anything.** The
   subtlest shape, and the only one that survives *replacing* the oracle: hand-derived
   expectations, written precisely because the oracle could not arbitrate, transcribe a
   function without the initial state its caller sets — and so certify a decoder that is
   correct symbol-by-symbol and wrong from the first symbol on. #168 is the worked
   case: five of eight FreeRDP-derived SRL vectors were computed at `kp = 0`, where
   FreeRDP's `progressive_rfx_upgrade_component` sets `kp = 8` — 110 lines outside the
   range the vectors cited. Re-running them at `kp = 0` reproduced all eight claimed
   values exactly, so the wrong initial state was the whole of the error.

   **Whether the oracle *caused* it is not settled, and the shape does not need it to
   be.** `kp = 0` is `ironrdp-graphics`'s initial value, so the basis may have adopted
   the state of the thing it was replacing; but FreeRDP also declares its state
   `WINPR_C_ARRAY_INIT` before assigning `kp`, so a reader who stops at the declaration
   lands on 0 too. Both hypotheses predict the same 8-of-8 fit and nothing separates
   them. Recorded here as the weaker, load-bearing claim rather than the stronger,
   unfalsifiable one — a shape stated beyond its evidence is the next thing to be
   walked past.

The tell for the first two: the argument for a change is *"the oracle does X"* with no
FreeRDP citation and no corpus fixture. The tell for the third is mechanical and needs
no attribution at all — **a citation that spans fewer lines than the state it depends
on**. Initial state is set by callers; a range that covers only the algorithm cannot
show it.

## Discovery history

- **ADR-0003** — the oracle strategy, adopted with the phase-out condition built in.
- **ADR-0007 (#58/PR #81), amended #118** — where no assembled oracle exists,
  verify stage boundaries; the amendment adds *assembly-layer independence*, which
  is this fact applied one level down.
- **#127** — ClearCodec divergences from FreeRDP adjudicated as **required
  tolerances**, backed by the `clearcodec_corpus` fixtures (memory
  `clearcodec_corpus_required_tolerances`). The oracle lost that argument.
- **#194 → #168** — the third shape above, found one slice after the basis landed.
  #194 built an owned basis precisely *because* the oracle could not arbitrate SRL, and
  the basis was still derived at the wrong initial state. The lesson is not that #194
  was careless: it is that "derived from FreeRDP" is a claim about a *range of lines*,
  and the range that holds the algorithm is rarely the range that holds its initial
  state. A second round of the same pass then found the mirror image — properties and a
  fuzz target *generated inside* the guarantee they existed to be independent of, so
  neither could reach the defects they were added for.
- Memory `ironrdp_oracle_shares_lineage` records the lineage limit itself, naming
  ClearCodec and RemoteFX compositing as the weakest cases for DoD ④ independence.

## Where it will recur

**If a change's evidence is "the oracle agrees" or "the oracle disagrees", it is
subject to this.** The test is one question, asked before acting on a divergence:

> Restate the finding without naming the oracle. *"Our decoder does X and the spec
> section / the corpus says Y"* survives; *"ironrdp-graphics does it differently"*
> does not.

**And it recurs on a schedule nobody sets: whenever the oracle's own version moves.**
A dependency bump normally changes the code under test; this one changes the
*measuring instrument*, so a green suite afterwards means "the two still agree",
which is a different sentence from "we are still correct". The bump is therefore
gated on **reading the upstream changelog for codec-behaviour changes**, not on the
suite going green — and the reading has three possible answers, each with a
different consequence:

| The oracle changed… | What it means here |
|---|---|
| a codec we **delegate to at runtime** — **none since #189**, when zgfx was self-owned and `egfx-bootstrap` deleted; kept as a row because the answer "there is no live path" is the thing to re-check, not to assume | was: a live-path change, not just a test change — prove it on the VM |
| a codec we **self-own** | our differential's expected value moved; adjudicate against FreeRDP/corpus before touching our code |
| a path we **do not implement** | expected no-op; say so, and check the differential actually walks the case rather than assuming |

Worked example, 0.8 → 0.9 (#184/#186): the single behavioural change was
Devolutions/IronRDP#1395 (Progressive stops requiring a CONTEXT block per frame) —
row 1, so it was proven against the real VM and recorded on #170, whose slice must
reproduce it. `ironrdp-pdu`'s mouse wheel-rotation decode fix was row 3, because
justrdp encodes input and has no mouse decode path. Nothing touched ClearCodec,
NSCodec, pointer or RemoteFX WTS1, so the #127 tolerances were not re-litigated.

Concretely:

- Adjudicate a divergence against **FreeRDP source and `clearcodec_corpus`**, not
  against the oracle, before changing anything.
- Check `crates/justrdp-codecs/tests/fixtures/` for a corpus case covering the input
  in question — a tolerance that exists there is a requirement.
- When the tie-break lands *against* the oracle, record it as a deliberate
  divergence in [`docs/agents/theflow.md`](../../agents/theflow.md), or the next
  completeness pass proposes reverting it.
- **When a hand-derived expectation is written, derive its initial state from the
  reference's caller, not only from the function being transcribed** — and prove the
  basis is independent without the oracle's help. `rfx::srl`'s bit-cursor unit tests
  do that job for the SRL vectors: they pin bit order and end-of-stream behaviour with
  no second implementation involved, which is what the vectors' old "positive controls"
  only appeared to do.
