# theflow bindings (justrdp)

Project-specific data for the `theflow` skill (the working discipline for a
substantive change to the sans-IO core / PDU / codecs / adapter). The skill holds
the portable *method* (seven steps + reasoning habits); this file holds justrdp's
*bindings* — which reference to read, what wins an argument, where the boundary
falls, how to prove behavior, which gates to run. The method defers every concrete
value here. (Authored/updated via `/grill-the-flow`.) Per-incident evidence:
[`lessons.md`](lessons.md).

Identity and the boundary invariant live in `CLAUDE.md`; the ubiquitous language in
**`CONTEXT.md`**; decisions in **`docs/adr/`** (0001–0010); the build plan in
**`docs/plan.md`** (§2–§23).

Prior art cross-checked throughout: **`[MS-*]` normative specs · FreeRDP (C) ·
IronRDP (Rust) · a real RDP VM** (`192.168.136.136`, memory `test_environment`).

## Tie-breaker — what wins when prior art and justrdp's own evidence disagree

Not one value: the authority differs **by layer**, and flattening it breaks one of
them. The sharpest case is send vs. receive — writing to the spec and accepting
what a real server sends are opposite disciplines on the same protocol, so a single
tie-breaker is necessarily wrong on one side.

| Layer | Authority | Grounds |
|---|---|---|
| **What we emit** — wire layout, flags, state transitions | the **`[MS-*]` spec**, cited by section | Writing to spec is what makes us connect to servers nobody tested us against. ADR-0003 *derive, don't copy*: FreeRDP/IronRDP are cross-checks, never the source |
| **What we accept** — server tolerance, violated caps, absent/oversized fields, and **receive-side state transitions the spec phrases as server obligations** (#252) | the **real VM's observed behaviour**, then FreeRDP's tolerance code | ADR-0009 / #101: servers violate the spec and mstsc connects anyway, so strictness on the receive path is a defect, not rigor. **Caveat:** the VM is one WS2022 box (memory `vm_advertised_graphics_caps`) — a tolerance derived from it alone is a hypothesis until FreeRDP shows the same shape |
| **Codec byte-exactness** | an **owned basis** where one exists (real-server corpus + independently-derived expectations), else the **differential oracle** (`ironrdp-graphics`) — with **FreeRDP as the tie-break** when the oracle and we disagree | ADR-0003/0007, **narrowed by ADR-0011 §3** (#225): *"The oracle never outranks the owned basis"* — this row named the oracle as the authority outright until then, which is the pre-ADR-0011 answer. The oracle shares justrdp's own code lineage (memory `ironrdp_oracle_shares_lineage`), so agreement is weaker evidence than it looks and disagreement is not automatically ours |
| **Public API shape** — `FrameUpdate`, feature-flag exposure, host injection points | **this repo's own precedent + `CLAUDE.md` identity** | IronRDP's API is the thing being replaced. It is a design *input*, never a validator |
| **Performance claims** | **our own measurement on a `--release` build** | No precedent yet; stated so a debug-build number never becomes a claim |

A layer not in this table has **no recorded tie-breaker** — say so and ask, rather
than borrowing a neighbouring row.

## Deliberate divergences — where justrdp does *not* follow its prior art, on purpose

The table above says who wins an argument; this says **which arguments are already
over**. It is what Step 5's reference-free restatement test is checked against: a
finding that lands here is `DELIBERATE` with the citation, never a defect, however
confidently a lens reports it.

| We do | The prior art does | Decided by |
|---|---|---|
| **The host holds every RDP feature flag** — the core hides no capability bit | `ironrdp-connector` 0.9.0 curates them internally and omits `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), so EGFX cannot be enabled | `CONTEXT.md` §Project intent — that single hidden flag is *why this project exists*. "Narrow the surface to a curated config" is not an open question |
| **ClearCodec tolerances** — RLEX runs that overflow the declared rect are clipped; the NSCodec subcodec path is skipped rather than rejected | FreeRDP treats both as errors | #127 + memory `clearcodec_corpus_required_tolerances` — the real-server corpus *requires* them. A lens reporting "FreeRDP rejects this" is `DELIBERATE`, cited to the corpus, not a defect |
| **`FrameUpdate` carries a dirty rect and no owned pixels**; surfaces blit straight into the host framebuffer | IronRDP's `DecodedImage` owns a full-frame copy the consumer reads out of | ADR-0010 (#85), realized in #162/#165 and #163/#166. "Let the core own the frame" reverses a measured performance decision |
| **Accept capability sets and negotiation responses that violate the letter of the spec** | a **strict reading of `[MS-RDPBCGR]`** — note the divergence here is from the *spec's strict interpretation*, **not** from FreeRDP/IronRDP, both of which are tolerant too | ADR-0009 (#101) |
| **Progressive: `quality = 0xFF` is a full-quality sentinel, and a region needs no preceding `WBT_CONTEXT` for its `codecContextId`** | `ironrdp-graphics` indexes its progressive-quant table by `quality` (0.9.0 `progressive.rs:1231`, `:1268`) and errors on an undeclared context id — note this diverges from **the oracle only**, not from FreeRDP, which special-cases the sentinel (`progressive.c:997`, `:1407`) and gates a region on `FLAG_WBT_FRAME_BEGIN` alone (`:2129`) | #194 + the corpus at `justrdp-codecs/tests/fixtures/progressive/`, where the real server needs both tolerances (2 of 52 payloads survive the oracle). Binds #169/#170: "require a context block" is not an open question |
| **Progressive upgrade: a refinement that cannot be represented in `i16` is a typed error** (whether from the accumulate, a too-wide raw read, or a shift that discards it) | **FreeRDP** truncates — `WINPR_ASSERTING_INT_CAST` is an assert in debug and a plain cast in release (`progressive.c:1223`, `:1252`), and `rawShift` (`:1192-1201`) uses a plain cast | #168. The receive-path row normally makes FreeRDP's tolerance the authority and this deliberately goes the other way: the coefficient store **survives across passes**, so a wrapped value corrupts every later refinement of that tile rather than one frame of it — the error is not local, so tolerating it is not tolerance. **Two caveats kept on the record rather than argued away:** reachability is *not* established — the corpus bounds the addend (`shift` 5..=11 against a magnitude ≤ 3) but says nothing about the accumulated coefficient it is added to, and no gate yet drives a pass against a non-zero store (#169); and because the pass refines in place, the error leaves a partially-refined store, so the caller's obligation is to **discard the tile's state**, not merely skip the tile |

| **Progressive first pass: the reduce-extrapolate inverse DWT saturates** its lifting taps | the **oracle** wraps (`dwt_extrapolate.rs:420-422`, `t(v) = v as i16`) | #169. FreeRDP's `clampi16` (`progressive.c:591-598`) is the tie-break, and the two differ by a full `u16` on an overflowing tap — a wrapped tap turns a clipped highlight into its photographic negative. Diverges from **the oracle only**; asserted by a test rather than left as a doc claim |
| **Progressive: a base quant band below 6 is decoded, not rejected** | **FreeRDP** rejects the whole region (`progressive_rfx_quant_lcmp_greater_equal(quantVal, 6)`, `progressive.c:2177`) | #169 + ADR-0009. The shift formula is total for `1 <= bitPos <= 16` and FreeRDP's floor sits inside that window, so the check buys no arithmetic safety on a receive path. **The oracle is not a second opinion here** — it has no such branch in any published version, and #167's "it defines a rounding right-shift for `q < 6`" described the *encoder* (`progressive.rs:315`). Unreachable on the corpus: no real region goes below 6 |
| **Progressive: an upgrade pass whose band layout disagrees with the layout its tile's store was written at is refused** | **FreeRDP** hardcodes the extrapolate walk and forwards the *current* region's flag to the DWT, so it refines one layout and reconstructs another | #169. Silent by construction — plausible pixels, no error, the shape #167 records. Stricter than the reference on a receive path, and **unreachable on the corpus** (52 of 52 regions set the flag), so it is a FreeRDP-derived hypothesis rather than a measured behaviour: guessing what such a server meant would be worse than refusing it |
| **Progressive: a first-pass dequantization shift of 16 or wider fails the tile** | **FreeRDP** refuses the same widths (`prim_shift.c:38-39`, generic and SSE3 alike) and then **discards the refusal** — the tile work callback is `void` (`progressive.c:1659-1684`), so the stale tile is blitted and the region reports success | #169. Reachable: `shift = quant + prog_quant - 1` runs to 29, not 15. Painting a stale tile from an already-overwritten sign store is the silent-corruption shape this territory refuses, so the divergence is from FreeRDP's *handling*, not from its threshold |
| **Progressive: the tile store is keyed by surface** | the **bootstrap oracle** keys by `codecContextId` alone with no cap (#83) | #169, and it is a **correctness** difference, not only a leak: `RFX_TILE_DIFFERENCE` adds a tile's coefficients to the store held for that grid position, and 1405 of 2943 real first passes carry it. Under context keying a rotated id starts from zeroes and the previous frame's contribution is dropped — measured, the two keyings paint differently. FreeRDP keys by `surfaceId` (`progressive.c:314`, `:471`). It also bounds the memory: 260 live stores against 2940 over one session |
| **Progressive: the tile store is freed by `DELETESURFACE` and by nothing else** — `DELETEENCODINGCONTEXT` and `RESETGRAPHICS` free nothing | the **bootstrap oracle path** frees on both (`justrdp/src/egfx.rs:319`, `:484`), which is #83's fix and is correct while contexts are keyed by `codecContextId` with no cap | #170. FreeRDP agrees with us on every row — its `DELETEENCODINGCONTEXT` handler is a literal no-op (`gdi/gfx.c:1239-1246`) and its `RESETGRAPHICS` reaches `progressive_context_reset`, a stub (`progressive.c:2635`) — so this diverges from *our own current call sites*, not from the reference. `RESETGRAPHICS` is the load-bearing one: the server's encoder keeps its reference frames across a reset and `RFX_TILE_DIFFERENCE` adds against them, so clearing desyncs while keeping cannot (an encoder that did reset cannot send a difference tile at all). **Landed in #172**: both call sites are retired and the passing test that pinned them was *inverted* rather than deleted (`reset_graphics_keeps_the_tile_stores_it_used_to_clear`), because a green test asserting the retired behaviour is the strongest possible "do not touch this" and deleting it would have thrown away the reason it was wrong |
| **Progressive: a tile index is bounded per axis, and a grid is replaced when the surface's grid dimensions change** | **FreeRDP** bounds the *linear* index only (`zIdx >= surface->tilesSize`, `progressive.c:473`) and its create is idempotent on the surface id alone (`:546-548`) | #170. Two different silences on the reference's side: a linear-only bound lets `(gridWidth + 5, 0)` alias onto `(5, 1)` and write the wrong tile, and an idempotent create lets a surface recreated at a new size keep the old `gridWidth` so every `zIdx` addresses the wrong tile. FreeRDP's grid is also **wider than ours for every surface** — it rounds up to the next multiple rather than `div_ceil` (`:447`) and 16-aligns the width first (`gdi/gfx.c:1284`) — so it accepts a column we reject. Unreachable on the corpus (widest index 19 on a 1280-wide surface), so the accept-side half is a hypothesis; the alias-side half is not |

| **Progressive assembly: a tile is clipped to its region's rects, and each region is clipped against its *own* rects** | **`ironrdp-graphics`** does not clip at all — `decode_bitmap` hands back whole 64 x 64 tiles — and **FreeRDP** clips the frame's accumulated dirty set against `progressive->region`, which after the parse loop holds the payload's *last* region (`update_tiles`, `progressive.c:2329-2412`) | #171. We follow FreeRDP on *whether* to clip and diverge on *which* region, and both halves are measured rather than argued: not clipping leaves **57 386 of 1 024 000** surface pixels different over the corpus (909 of 6193 tiles are genuinely cut), and **52 of 52 payloads carry exactly one region**, so the last-region rule and the per-region rule agree on every byte this server has sent. The oracle agreeing with the pre-#171 client here is [oracle-agreement-is-not-independence](../map/invariant/oracle-agreement-is-not-independence.md) again, not a second opinion |
| **Progressive assembly: overlapping region rects paint the overlap twice** | **FreeRDP** unions the rects into a `REGION16` first (`progressive.c:2331-2344`), so its copies are disjoint | #171. Both writes come from the same tile buffer at the same source offsets, so the *pixels* are identical and the cost is one redundant blit plus a doubled dirty area. Measured: **0 overlapping rect pairs** across the corpus' 52 regions, so a region-union implementation would be untested machinery guarding an unobserved case |
| **Progressive assembly: FreeRDP's deferred re-blit is not modelled** | **FreeRDP** re-blits the frame's whole accumulated dirty set on every payload of that frame (`frameId` / `updatedTileIndices`, `progressive.c:2437-2441`, `:2346`), which needs every tile's decoded *pixels* retained (+16 KiB on top of `TileState`'s 48 KiB) | #171, and the validity condition is recorded because the mechanism turned out to be **reachable**: probed live, **4 of 65** frames carried two WireToSurface2 payloads. Replaying that capture both ways, the carried-over set contributed **0 rectangles and 0 pixels** — inert *as long as a frame's successive regions do not overlap each other's tiles* |
| **Progressive assembly: the tile store has its own byte budget, and exceeding it skips the new tile** | **FreeRDP** allocates the whole grid up front per surface (`progressive_allocate_tile_cache`, `progressive.c:426`) and has no session-wide bound at all | #171. A `TileState` is 48 KiB per 16 KiB of RGBA, so `justrdp::egfx`'s 256 MiB surface cap admits ~768 MiB of store its accounting cannot see, against dimensions a *server* chose. Skipping the new tile rather than failing the payload is the direction that keeps every already-admitted tile refinable |

| **zgfx bounds what one compressed segment may expand to (65 536) and what a multipart may declare (64 MiB)** | **FreeRDP** caps the segment at the same number (a fixed `OutputBuffer[65536]`, `zgfx.c`) but bounds a multipart only by its own `u32` `uncompressedSize`, so ~400 KiB of input can demand 4 GiB; **`ironrdp-graphics`** has *no* output bound at all, and a ~20-byte segment can demand gigabytes (a match length is `2^(k+1) + v` for a unary-coded `k` the stream picks) | #189, and the requirement is older than the slice — `docs/plan.md` §V.3 wrote *"malformed sequences could cause OOM; use a max-decompressed-size limit"* before either decoder existed. The **uncompressed** segment path is deliberately left uncapped, diverging from FreeRDP the other way: those bytes are copied rather than expanded, so they are already bounded by the input the DVC layer capped, and refusing a long one would only kill a channel over wasted bandwidth |
| **zgfx refuses what no conforming encoder can emit** — a match distance past the 2.5 MB window, a bit pattern matching no token (`10000` and `101111111` name none), a compressed segment longer than the spec's own ceiling — **and tolerates what costs nothing**, an empty compressed segment | **FreeRDP** wraps an over-long distance modulo the window and emits whatever is there, silently skips an unknown token by consuming nine bits, and *refuses* the empty segment (`segmentSize < 2`); **`ironrdp-graphics`** panics on the first and errors on the second | #189. Refusing here is not strictness on a receive path: the referenced bytes have never existed, so there is no server intent to be tolerant *of* — where ADR-0009 applies (an empty segment, an over-long uncompressed one) this goes the tolerant way instead. The tell that the two halves are different questions: one is "what did the server mean", the other is "what could any encoder have meant" |
| **WireToSurface1: a dequantization shift of 16 or wider fails the component**, and an NSCodec colour-loss level that implies one fails the reconstruction | **FreeRDP** refuses the same width inside the shift primitive (`-1` from `general_lShiftC_16s_inplace`, `prim_shift.c:38-39`) and then **discards** the refusal — all ten `rfx_quantization_decode_block` calls drop the status and `rfx_quantization_decode` returns `TRUE` regardless (`rfx_quantization.c:73-83`), leaving the band unshifted and the tile decoding. `ironrdp-graphics`'s `quantization.rs` has no bound at all and carries the identical latent panic | #211 + [ADR-0012](../adr/0012-consumption-site-totality.md). Same split #169 already recorded for the Progressive first pass: the divergence is from FreeRDP's *handling*, not from its threshold. **Unreachable from the wire on both sites** — `Quant::decode` masks to nibbles (widest shift 14) and `parse_header` bounds the colour-loss level to `1..=7` — so this is a contract about what the `pub fn` admits, not a live guard; the priority (P2) follows the reachability and the contract does not. Note the threshold is on the **shift**, not on the nibble: an exponent of 16 shifts by 15 and is accepted |
| **WireToSurface1: a quantization exponent of 0 fails the component** — and it is the first refusal in this family a server can actually reach, a `0x00` byte being two zero nibbles | the **oracle** treats `0` and `1` alike as no-ops (`quantization.rs` `decode_block`, `if factor > 0`), so it under-scales the subband and decodes on. **FreeRDP agrees with us** and in the same shape — validate all ten, then apply — refusing at `if (val < 1) return FALSE` (`rfx_quantization.c:66-71`) and propagating it through `rfx_decode.c:66-67` to `rfx.c:1082-1086`, though its threadpool path (`rfx.c:787-788`) logs and continues instead | #233 + [ADR-0012](../adr/0012-consumption-site-totality.md) §3, which is the reason rather than FreeRDP: `progressive::first_pass_shift` already refused the identically undefined `bitPos == 0`, and one quantity gets one answer across a family. Diverges from **the oracle only**, which is no second opinion here — it shares this decoder's lineage and carries #211's unbounded shift besides. The receive-path objection is removed by ADR-0009 §3(a) (tolerance scopes to *which features may appear*; typed errors hold over contents), not by a tolerance judgement: `shift = -1` is the absence of a value, not one we dislike — the line #189 drew for zgfx. **The VM cannot corroborate** (it never emits CAVIDEO), so this is a FreeRDP-derived position, not an observed one; `[MS-RDPRFX]` constrains the *encoder* to 6..=15, so no conforming encoder emits it |
| **A failed zgfx message poisons the decompressor** — every later call is a typed error | **both references** leave the object usable with a half-written history window | #189. Same reasoning as #168's Progressive store and for the same structural reason: the 2.5 MB window spans messages, so a half-written one silently mis-decodes every later match rather than failing locally. Unreachable in the client (`justrdp::egfx` already treats a zgfx error as fatal for the channel), so it is a contract assertion rather than a live guard — and it is what makes the ordering contract testable, which the issue asked for |

| **A Font Map whose body is shorter than its mandatory 8 bytes is a typed error, and the connect fails** | **FreeRDP** refuses to fail: `rdp_recv_font_map_pdu` (`libfreerdp/core/activation.c:552`) carries the comment *"Do not fail here, see https://github.com/FreeRDP/FreeRDP/issues/925"*, warns on a short payload, and still calls `rdp_finalize_set_flag(rdp, FINALIZE_SC_FONT_MAP_PDU)` — so finalization completes on a zero-byte body. **But that tolerance is bought, not free**: FreeRDP gates every finalization advance on `rdp_handle_sc_flags` (`libfreerdp/core/rdp.c:1867`) walking four states (`rdp.c:2176-2190`, Sync → Cooperate → GrantedControl → FontMap), so reaching `CONNECTION_STATE_ACTIVE` already proves all four replies arrived and parsed. It relaxes the **body** because it never relaxed the **place**. **Two corrections #252 measured, both to sentences this row used to carry.** It is a *completeness* gate, not an *ordered* one: `finalize_sc_pdus` is only ever OR-ed (`rdp.c:2714`) and cleared solely at reset (`:2699`/`:2701`), so out-of-order replies satisfy every rung one PDU behind and still reach ACTIVE. And it is the **transition** that is gated, not the handler — `rdp_recv_data_pdu`'s switch (`rdp.c:1235-1311`) consults no connection state, so `rdp_recv_font_map_pdu` runs at any rung. **And the gate never fails**: the else branch (`rdp.c:1884-1893`) warns and leaves `status` untouched, so a missing reply parks FreeRDP on the rung rather than dropping the session. It failed for one stretch of 2022 and was deliberately relaxed — `ff2509bbc4e9` (Armin Novak, 2022-11-29, *"[core,client] relax sc flags state checks"*) deleted `status = STATE_RUN_FAILED`, one day after FreeRDP#8458 reported an xrdp resolution change disconnecting on the reactivation leg (*"microsoft's clients seem to work"*). And the maintainer who landed it said so on the record (`bmiklautz`, #925, 2013-02-11): *"It's not really clean solution since it violates the protocol imho."* **IronRDP** rejects, like us, and goes further by rejecting unknown `SequenceFlags` bits — enforcing a spec `SHOULD` as a `MUST`, since `[MS-RDPBCGR]` 2.2.1.22.1 marks all four body fields `SHOULD` and only the Share Data header fields `MUST` | #237 + [ADR-0009](../adr/0009-tolerant-negotiation-posture.md) §3(a), which is the record and reads against the reference here: *"A tolerated order with a malformed body is still a typed error."* A missing mandatory body **is** a malformed body, and §2's tolerance is scoped to *rendering-feature self-inconsistency* — an unadvertised order, an over-advertised capability — which a truncated finalization PDU is not. **The open question is at the consumption site, not the parser**: `FontMap::decode` returning `NotEnoughBytes` is what §3(a) prescribes; whether `justrdp::connect::finalization_step` should tolerate that error the way FreeRDP does would widen §2 past rendering features, which is an ADR amendment rather than a fix. **Settled by #242 (2026-08-25): the row stands, and here is what the earlier version of it left out.** *"A real server produced it"* was true and incomplete — #925's server is **Oracle VirtualBox VRDP 4.2.6**, and the reporter adds *"i can connect to Ms RDP Windows"*. One modern Microsoft instance exists (winapps-org/winapps#244, 2024, FreeRDP 3.8.0, Windows 10 LTSC, `paylaod size is 0 instead of 8`) — but it is preceded 28 ms earlier by two `SSL_CERT_NOT_ON_SERVER` failures, and `nego.c`'s handler for that code disables nothing (unlike `SSL_REQUIRED_BY_SERVER`/`HYBRID_REQUIRED_BY_SERVER`), so the ladder steps down. With no server certificate every TLS-bearing rung fails for one reason, leaving **`PROTOCOL_RDP` as the only survivor** — Standard RDP Security, which `connect.rs:577` rejects (`selected.bits() != 0`) six stages before `finalization_step` exists. **So every published observation of this input arrives over a transport justrdp refuses.** That is not *"no server sends it"*: the search was FreeRDP's `paylaod` typo across public GitHub, which cannot see mstsc users, private trackers, or pre-3.x log text — unconfirmed ≠ absent. **Validity condition: this holds only while justrdp refuses `PROTOCOL_RDP`.** Supporting Standard RDP Security reopens #242 by itself. The larger finding #242 produced is not the body check — it is that justrdp has **no ladder at all** and reaches session-active on the Font Map alone. **Settled by #252 (2026-08-25): no ladder, deliberately, and now measured rather than argued.** A capture of the real VM (`JUSTRDP_CONNECT_CAPTURE_FILE`, four activations, connect leg *and* reactivation leg, pinned as `justrdp-pdu/tests/fixtures/connect/finalization-replies.bin`) shows it sends all four in spec order every time — the premise #242 asserted and nothing in the repo could check. ADR-0009 reaches the case from neither side: §1's predicate is *"where a violation is an attack vector"* and no scenario is constructible for a peer that has already completed CredSSP, MCS and licensing; §2's grant is scoped by enumeration to rendering-feature self-inconsistency, which a missing finalization PDU is not. So the record was extended, not the machine — with one exception, the orthogonal half: the **field values** the spec does fix are now checked on both legs (`Synchronize.messageType`, and a server `Control.action` restricted to Cooperate / Granted Control), where justrdp had been the sole outlier against both references. The completeness question stays open on purpose and its home is #252 |

Add a row when a decision *chooses against* a reference or against a strict spec
reading — that is cheaper than re-defending it every time a lens finds it.

## Crate / module map

Virtual workspace (no root `[package]`, edition 2024). `--workspace` is required at
the root and **does not build** the out-of-workspace `fuzz`.

| Member | In `--workspace`? | Role |
|---|---|---|
| `justrdp-pdu` | yes | **dependency-free** PDU encode/decode (0 external crates) — `x224` · `mcs` · `gcc` · `capability` · `fastpath` · `egfx` · `dvc` · `rfx` · … |
| `justrdp` | yes | sans-IO core (`connect` / `session` state machines, `framebuffer`, `egfx`, `dvc`) + leaf deps (`rustls`, `x509-cert`) |
| `justrdp-codecs` | yes | codecs (`rle` · `planar` · `nscodec` · `clearcodec` · `rfx/` · `pointer`); owns them via phased-c2 with `ironrdp-graphics` as a **dev-dependency oracle** (ADR-0003) |
| `justrdp-tokio` | yes | ~30-line I/O adapter — `tokio` / `sspi` / `tokio-rustls` and the TLS trust policy (`trust.rs`) live **only** here |
| `fuzz` | **no** (own `[workspace]`) | cargo-fuzz, nightly CI only (#99) — the `--workspace` blind spot |

**`--workspace` blind spot:** `fuzz` is out of the workspace, so the top-level gate
does not even *build* it — a public-API change needs a separate `cargo check
--manifest-path fuzz/Cargo.toml`.

**Consumers: none.** Nothing is published to crates.io yet and there is no in-repo
consumer seam. Everything the method marks *cross-repo only* — the SDK-floor
constraint, the two-consumer signal, the report-upstream duty, the after-merge
downstream migration, the Step 4 "link into a real consumer" proof — is **N/A on
that ground**, not skipped. When a consumer appears, derive the list on the spot
(`grep` the sibling manifests for the crate name); never store it here.

## Step 1 — verify against real source, before guessing

Read real source with `gh api repos/<owner>/<repo>/contents/<path> --jq .content |
base64 -d > "$SCRATCH/x"`, then `grep -n` / `sed -n` — **`SCRATCH` is not
exported for you**, so set it first (`SCRATCH="${SCRATCH:-$(mktemp -d)}"`) or the
redirect writes to `/x`. **WebFetch is banned** — it
summarizes and silently drops handler bodies from large files, so a decoder branch
that *is* there reads as absent. **Derive, don't copy** — re-derive from the spec
and prove by differential test, not structural similarity (ADR-0003).

### Three ledgers to open before Step 2 — none of them is the issue body

1. **The cluster (decision side).** Read the worked issue's **spine**, or its
   epic where one exists (`gh issue view <n> --comments`), and treat the suspected
   root as a *hypothesis to test*. justrdp currently groups by **epic issues** whose
   slices name them in the title (`epic #158, slice 3`) — see the tracker note in
   Step 6 for the parent/child mechanism this should use instead.
2. **The map (blast-radius side) — [`docs/map/`](../map/README.md).** Open the
   territory notes the change touches. Their `## Blast radius` is *what else moves
   when you touch this* (a checklist — opening one and finding nothing to do is a
   correct outcome), their `## Cross-cutting invariants` are the facts that hold
   beyond the territory you are standing in, and `## Governing decisions` /
   `## Known holes / open` say what is already decided and what is deliberately
   absent. Read it **here**, before the boundary is drawn — reaching for it at
   Step 5 turns everything it would have told you into rework.
3. **The plan and the glossary.** `docs/plan.md` §0 (*traps already PROVEN on the
   real VM — do not re-discover*), §1 (capability → feature coupling table, the
   closest thing to a blast-radius list today), and §2–§23 for the layer the change
   sits in; `CONTEXT.md` for the term you are about to reuse or redefine.

### Reference routing table

| Change type | Real source to read |
|---|---|
| **Wire / PDU / codec layout** | the **normative spec first** — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]`, … — for layout, flags, state transitions (cite the section number). The spec is the "first principles" source RDP has that a terminal does not |
| **Hidden state · server tolerance · edges** | **FreeRDP** (C, the CVE knowledge source) + **IronRDP** (Rust) real source. Spec-unwritten tolerance (caps servers violate — #101, ADR-0009) exists only here |
| **Concept ≠ mechanism** | a codec we newly own may be absent from IronRDP, but its *components* (bit reader, tile boundaries, colour conversion, sub-band layout) exist in FreeRDP and in the spec — read **both**. A feature being "new" never justifies skipping the mechanism reference |
| **Published / external state** | crates.io / the upstream repo, never a sentence about them. Worked example: three artifacts said *"remove the `sspi` fork when #689 ships"*; it had shipped six weeks earlier (0.21.1, 2026-06-26) and nobody re-read them. One registry query settled it — see ADR-0004's 2026-08-10 Amendment and [`docs/map/`](../map/territory/nla-credssp.md) |

**Spec ≠ interop.** Code that matches the spec can still not be byte-identical to a
real server — *derive from spec, prove against oracle/VM* (Step 4).

### Where the hidden-state list lives

- **VM-observed traps → `docs/plan.md` §0.** Anything the real server forced on us
  (an ordering, a field a server insists on, a cap it violates) is recorded there so
  it is not re-discovered a third time.
- **Per-territory hidden state → the map's `## Design model`**, and anything that
  holds across territories → an [`invariant/`](../map/invariant/) note. The four
  that exist today — 32-bit dimension overflow, no-owned-pixels, never-panic decode,
  oracle-agreement-is-not-independence — each carry a `## Where it will recur` test,
  which is the enumeration this bullet used to ask you to redo by hand.
- **Per-codec state the map does not yet name** (tile boundaries, quant tables,
  progressive pass state, palette/run state) goes into the issue *before*
  implementing — and if it turns out to hold outside its territory, Step 6's
  promotion obligation says it does not land until an invariant note exists.
- **Removing a field is the mirror image.** A value read *incidentally* elsewhere
  (feeding a boolean, gating a branch) is unpinned the moment you delete it — grep
  every read site, including ones that only compute something from it.

**To pin a runtime fact, instrument a throwaway probe** against the VM (a real
coordinate, an actual cap byte, the order a server sends surface commands), read the
number, delete the probe, and record the number in the issue. Reading the code is not
observing what it does.

**"Unconfirmed ≠ absent"** — a search not showing a server behaviour does not make it
absent; that is a gap to surface, never a silent load-bearing assumption. Its inverse:
**a cleared concern is recorded with its validity condition** ("this path is fine *as
long as the server advertises X*"), in the issue.

## Step 2 — boundary rule (sans-IO core vs adapter, ADR-0001)

- **The core is a pure state machine** — `bytes in → (Action, bytes) out`. **No I/O,
  no runtime embed, policy-agnostic.** It never reads a socket, never knows `tokio`,
  never sees a `TSRequest`.
- **Mechanism → core** (wire parsing, state transitions, codecs, surface/framebuffer
  composition). **Policy → adapter**: TLS trust (ADR-0005), credential source, frame-sink
  behaviour are *injected* by the host adapter (`justrdp-tokio`).
- **`sspi` (NLA CredSSP token loop) and `rustls` live in the adapter** — security-critical,
  non-RDP leaf deps (ADR-0002). The core owns every RDP-native protocol layer itself
  (X.224 · MCS · GCC · capability · session loop · virtual channel · codec · surface).
- **The host owns by definition** (not a workaround): the socket and runtime, the TLS
  trust decision, credentials, the frame sink / presentation, input device semantics,
  clipboard and redirection policy, reconnect strategy, and **every RDP feature flag**.
- The payoff: the core is **independently, deterministically testable** with no socket
  and no runtime (oracle round-trip + real VM).

**Do not misdiagnose a contract as a defect.** When something reads as a bug, first ask
*whose invariant broke*. Policy-agnosticism and the dirty-rect `FrameUpdate` (ADR-0010)
are contracts justrdp deliberately holds — "the core should resolve this for me" is a
host standing on nothing valid.

**No consumer workaround for an upstream defect.** The worked instance is the `sspi`
CredSSP defect (ADR-0004): it was reported and fixed *upstream*, bridged meanwhile with
`[patch.crates-io]`, and the bridge was deleted once the fix shipped (2026-08-10) — not
worked around locally at any point. When you feel the urge to compensate in a shallower layer to
make a test pass — **stop, explain, ask** — do not work around it alone and do not
silently file an issue and move on.

## Step 3 — the test-trust gate

Beyond `/tdd` RED → GREEN, a passing test earns trust only after two bars:
**discriminating power** (turn the fix off, confirm it goes red — a green from a test you
never saw fail is not evidence) and **right reason** (assert the side conditions: the
exact byte count, the state after, the branch that must *not* be taken).

Two justrdp-shaped traps for the first bar:

- **A differential-oracle test can be green for the wrong reason** — see the Step 4
  traps below; a vector both implementations decode identically proves agreement, not
  correctness.
- **A guard that only 32-bit reaches cannot go red on x64.** Dimension/offset overflow
  guards must be mutated and re-run on `i686-pc-windows-msvc` (memory
  `wasm32_overflow_proof_via_i686`, #151/#155), or the RED you never saw is on a target
  the gate never ran.

Where compilation itself enforces completeness (a new wire field every layer must
thread), strict RED is awkward — a round-trip test takes its place, but still write it
*before* the implementation.

## Step 4 — proof method per layer (real round-trip, not a fake)

| Layer | Real proof |
|---|---|
| **`justrdp-pdu`** | `encode → decode` round-trip on hand-built PDUs **plus** the proptest no-panic / round-trip properties (ADR-0008, #98). A decoder that only ever sees vectors we authored is untested against the input space a server actually spans |
| **`justrdp-codecs`** | a **differential oracle** (ADR-0003/0007): feed the same bitstream to *our* decoder **and** `ironrdp-graphics`, assert the output `Vec<u8>` is **byte-identical**. ~~100% pass is the gate to drop the dependency.~~ **Retired by ADR-0011 §Consequences** (#225): *"ADR-0003's phase-3 exit criterion is no longer sufficient on its own"* — the dependency drops on an **owned basis**, and its 2026-08-26 amendment keys that on **role**, since a canary and a generator do not exit the way a verifier does. Stage-boundary verification (ADR-0007) applies per pipeline stage, not only end-to-end |
| **`justrdp` (connect / session)** | a **real RDP VM** round-trip (`192.168.136.136`; memory `test_environment`) — the full connect sequence to session-active, not a mock server |
| **`justrdp-tokio`** | the same VM, driven end-to-end (its integration tests are `#[ignore]`d in CI by design — they need the VM, which is why `coverage.yml` excludes this crate) |
| **strongest — a real consumer** | **N/A: no consumer exists.** When one does, link a local build in via `[patch.crates-io]` / a path override in the consumer's manifest, run its **full** suite, and the strongest evidence is a consumer test that pinned the old bug as expected now *breaking* |

Traps this project must respect:

- **The oracle shares our lineage.** `ironrdp-graphics` and justrdp descend from the same
  reading of the same spec (memory `ironrdp_oracle_shares_lineage`), so byte-identical
  agreement is *not* independence — for ClearCodec and RemoteFX compositing in particular,
  cross-check FreeRDP before calling a match "proof".
- **A vector proves only what it contains.** A corpus can supply an axis and still miss the
  *combination* (a codec exercised, but never at a tile boundary, never with a quant table
  that changes mid-frame). Measure what the fixture actually exercises; do not infer
  coverage from the feature the fixture was named for.
- **One VM is one server.** The WS2022 box advertises a specific cap set
  (memory `vm_advertised_graphics_caps`) — it can *prove* the paths it exercises (#150/#91)
  and cannot say anything about the ones it does not advertise. "The VM is happy" is not
  "servers are happy".
- **x64 cannot reach the 32-bit guards** (memory `wasm32_overflow_proof_via_i686`).
- **A demo or a fake is a smoke test, not proof** (DoD ④).

## Step 5 — adversarial completeness pass (one lens, both corpora)

Gate on **enumeration risk**, not diff size: any change where *your own hidden-state
enumeration could be incomplete* (a decoder, a parser, a state machine with many edges,
cross-feature interaction) makes this mandatory. A genuinely closed surface may skip it —
**record that judgement explicitly**.

**One lens, briefed on both corpora — not one lens per corpus.** A lens holding half the
material can see that two things disagree but not which one is wrong, so every divergence
comes back to the main thread to be adjudicated from cold.

- **① this repo's siblings — from [`docs/map/`](../map/README.md), not from a list
  here.** The touched territory's `## Blast radius` *is* the sibling set, and its
  `## Cross-cutting invariants` carry the recurrence tests that derive the affected
  sites. A hand-kept copy in this file is what goes stale and disagrees, so there is
  deliberately none. Add `docs/plan.md` §0 for VM-proven traps.
- **② the reference** — FreeRDP and IronRDP real source at the known CVE points
  (rle/planar/clearcodec/nsc OOB; memory `rdp_decoder_robustness_refs`) and the `[MS-*]`
  section that governs the field.

**Carry into the brief, or the lens cannot grade its own findings:** the frontier (the
functions the diff touches + one hop), the open-issue list, **the tie-breaker row for this
layer**, **the deliberate-divergence table above**, and the four output grades
(`CONFIRMED` / `UNADJUDICATED` / `INERT` / `DELIBERATE`). A brief missing the last two
produces reference-shaped proposals that read as urgent defects.

**Direction, not just difference.** Only this layer diverges → move toward the reference.
This layer *and* its sibling decoders agree against the reference → a **family** decision:
hold the current behaviour and track the parity fix as one coordinated change.

**Unconditional triggers — three paths that run the pass regardless of the judgement
above, and the only places the second, *refuting* lens is worth its cost.** justrdp has no
money path, no production mutation and nothing destructive; here a path is sacred when it
is **silent** (wrong, and nothing crashes) or **irreversible**:

1. **Untrusted-input decoders and parsers.** Every byte comes from a server we do not
   control; a wrong bound yields plausible pixels or a panic (DoS), not an error. **Do
   not enumerate the surfaces here** — the derivation lives once, with the invariant:
   [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md)
   carries the commands that produce *what is parsed*, *what is fuzzed* and *what consumes an
   already-parsed value as arithmetic*, and the gaps between them. **Three of them since
   #241/#238, not two** — the parse derivation was scoped to `crates/justrdp-pdu/src` and so
   could not see a parser in the core, and both original commands were byte-scoped and so could
   not describe a consumption site at all. The continuous half of this axis is **proptest (#98) + cargo-fuzz
   (#99)** (ADR-0008) — the fuzz lane is **nightly-only**, so a *new* target is not
   covered by the PR gate on the day it lands.
2. **The TLS trust decision** — `crates/justrdp-tokio/src/trust.rs` and
   `crates/justrdp/src/tls.rs` (ADR-0005, #36). Silent by construction: a wrongly-accepted
   chain produces a perfectly working session, and the host's whole security posture is
   this one decision.
3. **The NLA credential path** — the CredSSP token loop in `crates/justrdp-tokio/src/lib.rs`
   plus the SPKI public-key binding it authenticates against (`x509-cert`, in
   `crates/justrdp/src/{tls,connect}.rs`), and every `sspi` version bump (ADR-0004
   requires the real-VM suite for one). A wrong binding or token order can still
   complete a handshake.

A gap sends you back to Step 3. **Never drop a corpus because the fix looks small.**

## Step 6 — behavior-describing surfaces (sweep by hand)

- **`CONTEXT.md` glossary + `docs/adr/`** — the domain SoT, and a **write** surface, not
  only a read one: a change that falsifies a record's premise amends *that record* (a
  status note, a superseded-by line) in the same change. An ADR's Consequences must be
  *currently true*.
- **`docs/plan.md`** (§2–§23) — the build plan; keep the slice's entry honest, and add to
  §0 any trap the VM just proved.
- **[`docs/map/`](../map/README.md) — two obligations, and the second is what makes
  the map preventive rather than archival.** ① **Coverage**: is the touched territory
  present, and is its `## Blast radius` still right? (May lag.) ② **Promotion**: *is
  the fact this fix revealed also true outside this territory?* Answer by grep, in
  this repo's terms — *does it hold at any site that sizes a buffer from
  server-declared dimensions, parses an untrusted length, or forwards pixel data?* If
  yes, the change **does not land** until an `invariant/` note exists. (May **not**
  lag: the first site to hit a fact is where it is discovered, and at that moment no
  node exists — which is exactly how #151→#155 and #85→#162→#163 happened.)
- **`Cargo.toml`'s dependency comments** — each one states *why* a crate is here and,
  where it is temporary, what ends it. Those sentences are load-bearing and unchecked:
  the `sspi` fork-bridge comment outlived its condition by six weeks (ADR-0004
  Amendment 2026-08-10). When a dependency's rationale changes, the comment is part of
  the change.
- **Rustdoc on the public surface** ships as the crate's API docs — the surface most likely
  to still describe the old behavior.
- **Changelog: none.** No `CHANGELOG.md` and nothing published, so there is no snapshotted
  release note to keep consistent. Revisit at the first crates.io publish.
- **Reclaim now-false rationale** — a justification written in an earlier PR, issue, or ADR
  can be made false by a later one, and nobody re-reads it.

**Promotion destination and format.** A promoted rule becomes an **ADR** under
`docs/adr/NNNN-<kebab-title>.md`, following the house shape: `Status` (with amendment
history inline), `Context`, `Decision`, `Consequences`, and **`Rejected alternatives` with
reasons** — ADR-0002 and ADR-0007 are the models, both carrying later Amendments rather
than being rewritten. A record earns its place by **deriving** decisions already taken,
not by listing them.

**Areas that already carry a record** (the list the filing step checks *before* proposing
a spine — a cluster with a home never gets a second one). All **Accepted**; none Proposed:

| # | Area |
|---|---|
| 0001 | sans-IO state-machine core / crate split |
| 0002 | dependency boundary (+ codec-ownership amendment, #100) |
| 0003 | phased codecs & the differential oracle |
| 0004 | `sspi` contribute-and-bridge (#61) |
| 0005 | TLS trust policy (#36) |
| 0006 | supply-chain action pinning |
| 0007 | stage-boundary codec verification (+ assembly-layer amendment, #118) |
| 0008 | robustness testing — fuzz & property (#97/#98/#99) |
| 0009 | tolerant negotiation posture (#101) |
| 0010 | `FrameUpdate` dirty-rect contract (#85) |
| 0011 | zero `ironrdp` as the terminal state; the oracle retires per codec (#194) |
| 0012 | consumption-site totality — a parser's guarantee is not held at the point of use (#211/#233) |
| 0013 | pinned build inputs — every pin names its bumper; the compiler pin (#235) |

**Tracker parent/child: GitHub sub-issues are in use on one cluster and nowhere else.**
Measured 2026-08-13, not inferred — an earlier revision of this paragraph asserted the
relation was unused because it said so, and the one command that checks it disagreed:

| Epic | `sub_issues` |
|---|---|
| **#158** (Progressive) | **7** — slices #167–#172, plus #194; #194 in turn carries #200 |
| #132, #45, #29, #21, #28, … | **0** |

**A `- [ ] #NNN` task list in the body does not create the relation.** #132's body lists
`#137`–`#141` in exactly the format #158's uses and has zero sub-issues, so #158's tree is
a deliberate act someone performed, not a side effect of the checklist. Enrolling an epic's
slices is therefore real work with a real result, and it is worth doing when you next touch
one. **Use the relation** for new follow-ups and spines rather than adding another prose
convention.

The API has two traps, both cost a few minutes to rediscover:

- `sub_issue_id` is the issue's **database id**, not its number, and `gh api` needs `-F`
  rather than `-f` — with `-f` it sends a string and the API answers **422**.
- Re-adding an existing child *also* answers **422**, with a message that reads as if the
  child belongs to some other parent: *"Issue may not contain duplicate sub-issues and Sub
  issue may only have one parent."* It usually means the edge is already there. **List the
  parent's `sub_issues` before believing it** — `.parent` is absent from the REST issue
  payload, so a child's own record cannot answer the question.

```sh
gh api repos/kihyun1998/justrdp/issues/<parent>/sub_issues --jq '.[].number'   # check first
ID=$(gh api repos/kihyun1998/justrdp/issues/<child> --jq .id)
gh api --method POST repos/kihyun1998/justrdp/issues/<parent>/sub_issues -F sub_issue_id=$ID
```

## Step 7 — gate matrix + PR

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --manifest-path fuzz/Cargo.toml     # out-of-workspace blind spot
python .github/scripts/check_map.py --selftest  # the gate's own defect kinds, first
python .github/scripts/check_map.py             # docs/map: links, anchors, symbols, reciprocity
# + just-shield supply-chain scan (ADR-0006): SHA-pinned actions
# + 32-bit guards. `overflow-32bit.yml` now runs this in CI on any change under the three
#   crates, so locally it is a pre-check rather than the only proof it used to be.
#   Two things this line used to get wrong, both measured:
#   - It named `-p justrdp-codecs` alone, and the invariant names five territories — two of
#     them (EGFX surface allocation, the framebuffer) live in `justrdp`. The command was
#     narrower than the thing it guards.
#   - The `target add` is not ceremony. A rustup target is per-toolchain, so ADR-0013's pin
#     means a target added under the old default is absent under the pinned one; it had
#     silently gone missing within a day of #235. `targets` is deliberately kept out of
#     `rust-toolchain.toml` (the file is shared with the ubuntu runners), so this line is
#     what keeps it runnable.
#   rustup target add i686-pc-windows-msvc
#   cargo test -p justrdp-codecs -p justrdp --target i686-pc-windows-msvc
```

Run each gate **bare, never piped** (a pipeline's exit status is `tail`'s, so the gate
cannot fail), and **never move a threshold to turn a build green**.

**These commands mirror CI because the compiler is pinned, and only because of that**
(ADR-0013, #235). `rust-toolchain.toml` fixes the channel at an exact version and CI installs
it by naming no toolchain, so the skill's *"do not sit watching CI during implementation — the
local gates mirror it"* is a fact rather than a hope. It stops being one the moment the pin is
removed or CI names a toolchain of its own: before #235 the maintainer's host was three months
behind the runner and a lint that failed the gate could not fire locally at all. The two still
differ in **OS** — the runner is `ubuntu-latest`, the host is Windows MSVC — so a
platform-conditional path is the residue this does not cover.

**CI jobs — five workflows, four of them gates:**

| Workflow | Gate? | Notes |
|---|---|---|
| `test.yml` → job `test` | **yes** | fmt → clippy `-D warnings` → `cargo test --workspace`, stable, on PR + master |
| `test.yml` → job `map` | **yes** | `.github/scripts/check_map.py` — [`docs/map/`](../map/README.md) links, `#anchors`, `## Code` symbols **at the path their bullet names** (#224), section sets, invariant↔territory reciprocity. Runs `--selftest` first, which requires the gate to fail on each of its eight defect kinds. Toolchain-free, so a docs-only PR answers without waiting for cargo |
| `fuzz.yml` | **yes** | nightly cargo-fuzz lane (#99) — a *new* target is not covered on the day it lands |
| `supply-chain.yml` | **yes** | just-shield, SHA-pinned actions (ADR-0006); pins auto-managed by `just-shield fix` + Dependabot |
| `overflow-32bit.yml` | **yes** | `cargo test -p justrdp-codecs -p justrdp --target i686-pc-windows-msvc` on `windows-latest`. The only gate that can reach the dimension-overflow class ([the invariant](../map/invariant/decoder-dimension-overflow-32bit.md)) — on x86-64 a wrapping `width * height * bpp` is merely a large number, so every other gate is green over it. **Path-filtered** to the three crates that hold the sites, because a Windows runner bills at 2x and the class only moves when the arithmetic does |
| `coverage.yml` | **no** | cargo-llvm-cov discovery tool (#102), post-merge/dispatch, **no threshold**; scopes to the sans-IO core and excludes `justrdp-tokio` (its tests need the VM) |

- Branch → commit `feat(<scope>): … (#issue)` (**no `Co-Authored-By` / AI-attribution
  trailer** — memory `feedback_no_ai_attribution_external`) → squash PR (`Closes #issue`)
  → confirm CI green.
- Always label a new issue **triage + type** on creation (memory
  `feedback_label_issues_on_creation`); see `docs/agents/triage-labels.md`.
- Do **not** ask "shall I stop?" at a phase boundary of an agreed multi-step plan (memory
  `feedback_no_stop_prompts`).
- **After merge — downstream loop: N/A, nothing is published and there is no consumer**
  (see the crate map). Re-derive, never store, once that changes.

## War-story index

Per-incident and per-decision evidence lives in [`lessons.md`](lessons.md), indexed by step
and anchored to the ADRs and issues (#36, #61, #98, #99, #101, #127, #151/#155, #162/#163).
