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

Two shapes, and neither announces itself:

1. **A green oracle pass read as correctness.** Both implementations mishandle the
   same ambiguous field identically; the test is byte-identical and the picture is
   wrong on a server neither was tested against.
2. **A "fix" that regresses against real servers.** The oracle rejects a stream a
   real Server 2022 sends, someone treats the divergence as our bug, and the
   corpus-required tolerance is removed. `justrdp-codecs`'s own module doc records
   that ClearCodec **corrects two bit-level defects in the oracle** which otherwise
   reject genuine Server 2022 streams — so this is not hypothetical here.

The tell for both: the argument for a change is *"the oracle does X"* with no
FreeRDP citation and no corpus fixture.

## Discovery history

- **ADR-0003** — the oracle strategy, adopted with the phase-out condition built in.
- **ADR-0007 (#58/PR #81), amended #118** — where no assembled oracle exists,
  verify stage boundaries; the amendment adds *assembly-layer independence*, which
  is this fact applied one level down.
- **#127** — ClearCodec divergences from FreeRDP adjudicated as **required
  tolerances**, backed by the `clearcodec_corpus` fixtures (memory
  `clearcodec_corpus_required_tolerances`). The oracle lost that argument.
- Memory `ironrdp_oracle_shares_lineage` records the lineage limit itself, naming
  ClearCodec and RemoteFX compositing as the weakest cases for DoD ④ independence.

## Where it will recur

**If a change's evidence is "the oracle agrees" or "the oracle disagrees", it is
subject to this.** The test is one question, asked before acting on a divergence:

> Restate the finding without naming the oracle. *"Our decoder does X and the spec
> section / the corpus says Y"* survives; *"ironrdp-graphics does it differently"*
> does not.

Concretely:

- Adjudicate a divergence against **FreeRDP source and `clearcodec_corpus`**, not
  against the oracle, before changing anything.
- Check `crates/justrdp-codecs/tests/fixtures/` for a corpus case covering the input
  in question — a tolerance that exists there is a requirement.
- When the tie-break lands *against* the oracle, record it as a deliberate
  divergence in [`docs/agents/theflow.md`](../../agents/theflow.md), or the next
  completeness pass proposes reverting it.
