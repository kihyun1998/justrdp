# 0009 — Negotiation posture: tolerant of server self-inconsistency in rendering, strict on security integrity

- Status: Accepted — amended 2026-08-25 (#252), 2026-08-31 (#268), 2026-09-04, 2026-09-16 (#286) and 2026-09-18 (#297); see the Amendments below
- Date: 2026-07-03
- Closes issue #101

## Context

Real RDP servers advertise capability and drawing-order sets they then violate, and misreport their own version (RDP 5.0–8.1 all report build "4"). The two mature reference clients sit at **opposite default postures**, which is itself the evidence that this needs a deliberate decision:

- **FreeRDP defaults strict, with an opt-in escape hatch.** An unadvertised order hits `check_order_activated` (`libfreerdp/core/orders.c:271`), which returns `FALSE` — a hard parse failure that aborts the connection — logging *"SERVER BUG: … not announced! Use /relax-order-checks to ignore"*. The `/relax-order-checks` flag (`client/common/cmdline.c:4982` → `FreeRDP_AllowUnanouncedOrdersFromServer`) downgrades the error to a warning-and-accept, but it defaults **OFF**. So a spec-literal FreeRDP drops otherwise-healthy sessions against xrdp / Server 2008 R2 unless the user opts out (issue #7216).
- **IronRDP defaults tolerant by construction** — it performs *no* cross-check of server updates against advertised capabilities. Unsupported/unadvertised orders and codecs are `warn!`-ed and skipped, the session continues (`ironrdp-session active_stage.rs:411` for MS-RDPEGDI orders; `fast_path.rs:479/528` for surface codecs). There is no relax knob because nothing is ever enforced. But this tolerance is **unbounded and silent**: `fast_path.rs:168` even swallows a malformed fast-path update's `InvalidField` decode error into `UpdateKind::None`, with a code comment admitting the "fragile logic … rationale not obvious".

Both are, notably, **tolerant on version misreporting**: FreeRDP takes `MIN(server, client)` and accepts even an unknown version (logged, not aborted — `libfreerdp/core/gcc.c:210`); IronRDP does no version gating on the graphics path.

justrdp already applies a **split posture** in code, without having named the principle:

- **Strict** where a mismatch is a security/integrity threat: the connect machine rejects a server that selects a security protocol we never advertised (`connect.rs`), rejects Standard RDP Security, rejects an unsolicited Channel Join Confirm, and the DVC layer rejects a compressed chunk when compression was never advertised (`dvc.rs`).
- **Tolerant** where a mismatch is a rendering-feature divergence: the ClearCodec decoder keeps real-server leniencies the spec and the ironrdp oracle reject (over-region RLEX clip, NSCodec subcodec) because the captured WS2022 corpus requires them (ADR-0007 amendment, #120/#121/#127).
- **Not yet exercised** for drawing orders — order decode is epic #22, so the advertised-but-violated-order problem has not bitten us yet. This ADR sets the posture *before* it does.

This mirrors the project's stated identity (`CLAUDE.md`): *derivation from the normative spec, proof from the oracle/real VM* — "스펙 ≠ 상호운용". We already accept that real servers diverge from spec; the open question is only where the tolerance lives and how it is bounded. justrdp takes **IronRDP's default-tolerant stance on rendering, but with the two bounds IronRDP lacks** (still-validate-the-bytes, always-observable) — neither FreeRDP's disconnect-by-default nor IronRDP's silent, unbounded swallow.

## Decision

Be **tolerant by default of a server's self-inconsistency in rendering features, and strict on security/protocol integrity.** The dividing line is the threat model, not the spec letter:

1. **Strict — reject — where a violation is an attack vector.** Protocol downgrade (an unadvertised or weaker security protocol), injection that breaks the connect/session state machine (unsolicited or out-of-order security-relevant PDUs), and unannounced compression/encoding that could smuggle bytes. These reject today; they keep rejecting. Trust failures and negotiation violations stay typed errors on their stage.

2. **Tolerant — accept-and-log — where a violation is a rendering-feature self-inconsistency.** A drawing order absent from the server's Order Capability Set, a capability the server under- or over-advertises, a misreported version. Do not drop the session: decode what actually arrives and continue.

3. **Leniency lives at the point of use, bounded by three invariants:**
   - **(a) The bytes are still fully validated.** Tolerance is about *which features are allowed to appear*, never about trusting their contents: bounds checks, typed errors, and the ADR-0008 no-panic contract hold unconditionally. A tolerated order with a malformed body is still a typed error, never an OOB or panic.
   - **(b) Every tolerance is observable.** Each accepted divergence is logged via `tracing` (a `rdp_interop`-targeted debug/warn record naming the advertised-vs-seen mismatch). Silent masking is forbidden — a tolerance you cannot see is indistinguishable from a bug.
   - **(c) Security integrity always wins.** Rule 1 is never relaxed by rule 2; no rendering-tolerance path can accept a downgrade or an injection.

4. **Tolerant is the default with no opt-out knob (initially).** Unlike FreeRDP's opt-in `/relax-order-checks`, justrdp treats tolerance as the *correct* behavior for rendering self-inconsistency, not a workaround — so there is no strict mode to select. A future `observe`/strict mode (surfacing divergences as errors for security research or conformance testing) may be added if a use case needs it, but is out of scope here.

## Consequences

- **The two cross-cutting hard-spots #101 lists are strict-side mechanism, not posture questions — and verification (before this ADR) shows both are already handled, so nothing is split out.** FreeRDP and IronRDP converge *exactly* on both (unlike the order-posture split above), confirming they are pure mechanism, not a decision — and justrdp already implements them the same way:
  - **HYBRID_EX Early User Authorization Result PDU** — already implemented and tested. The core reads it **only when HYBRID_EX is the *selected* protocol** (`connect.rs:495` → `Stage::EarlyUserAuth` / `Action::AwaitEarlyUserAuth`), as an unframed fixed 4-byte AUTHZ code (`AUTHZ_SUCCESS = 0x0000_0000`, `connect.rs:1173`; nonzero → `ConnectError::EarlyUserAuthDenied`), with the adapter's exact-4-byte read at `justrdp-tokio lib.rs:514`. Five unit tests cover granted / denied / unrecognized-or-truncated / HYBRID_EX-gating / unexpected-substage (`connect.rs:1445–2071`), and the real-VM connect exercises the live path (it requests `SSL|HYBRID|HYBRID_EX` and reaches session-active). This matches FreeRDP (`nego.c:314`/`nla.c:2189`) and IronRDP (`credssp.rs:220`) exactly.
  - **CredSSP version + public-key binding hash (CVE-2018-0886)** — owned by the `sspi` crate behind the **ADR-0002/0004 delegation boundary**, exactly as IronRDP does it (IronRDP implements none of this either — it delegates to the same `sspi-rs`: v6 client, 32-byte nonce, `check_peer_version` lock, `<5` echo / `>=5` SHA-256 binding hash with direction-specific magic strings). Our adapter drives `CredSspClient` (`justrdp-tokio lib.rs:27`); the connector's only obligation — reaching a completed CredSSP exchange with the negotiated version — is proven by the real-VM session-active round-trip. No justrdp-side work remains.

  So #101's "related hard-spots" were **stale** — both were solved before this ADR was written. This ADR records only the negotiation *posture*; no follow-up implementation issues are filed for them.
- **Order decode (#22) is built tolerant from day one** — accept-and-log unannounced orders rather than adding strictness later and then relaxing it.
- **Generalizes the ADR-0007 codec-tolerance precedent** from the codec layer to the negotiation layer: the corpus-required leniencies were the first instance of this principle; ADR-0009 names it.
- **Risk: tolerance can mask a bug in our own decoder as "server inconsistency."** Mitigated by invariant (b) — every tolerance is logged — and by the differential/corpus tests that still assert byte-identity wherever an oracle or a captured stream exists. Tolerance widens *what we accept*, never *what we stop verifying*.

## Amendment (2026-08-25, #252): §1 and §2 are not a partition

Measured rather than argued. A wire field whose legal values `[MS-RDPBCGR]` fixes —
`Synchronize.messageType`, a server `Control.action` — is refused by both reference clients and
by us, and it falls in neither half: §1's predicate is *"where a violation is an attack vector"*
and none is constructible for a peer that has already completed CredSSP, MCS, channel join and
licensing, while §2's grant is scoped **by enumeration** to rendering-feature self-inconsistency
(a drawing order, an under- or over-advertised capability, a misreported version). **§3(a) is
what licenses the refusal** — *"tolerance is about which features are allowed to appear, never
about trusting their contents"* — as a removal of the objection rather than a mandate.
[ADR-0012](0012-consumption-site-totality.md) §3 hit the same wall from the codec side and
routed around it the same way (#233); two instances at opposite layers is why this is recorded
instead of re-derived a third time. **What this does not decide** is the *completeness* question
— whether the Font Map alone may gate session-active — which #252 settled as "no ladder" on its
own evidence and which is not a posture question at all.

## Amendment (2026-08-31, #268): §3(b) names a `tracing` target that has never existed

And the first record written *because of* §3(b) could not use it. The rule says each accepted
divergence is logged as *"a `rdp_interop`-targeted debug/warn record"*. `rg rdp_interop` over the
whole repository returns **one hit — this line**; `git log -S` finds it in no commit that ever
touched `crates/`. The convention that actually shipped is **per-area**: 19 `rdp_egfx`, 6
`rdp_drdynvc`, plus `rdp_finalization`, `rdp_shutdown_denied`, `rdp_demand_active` and eight
more, each named for where the divergence was seen rather than for the fact that it *is* one.
#268's per-frame paint-budget warn follows the shipped convention (`target: "rdp_egfx"`), so
**read §3(b) as requiring an observable `tracing` record and not as fixing its target string**.
Recorded rather than silently corrected because the mechanism half of §3(b) is the half a reader
would otherwise try to obey: it is a decision surface with no gate over it, and it drifted from
day one.

**Second, and reported rather than resolved: §2's enumeration does not reach this instance
either.** An over-budget entry count is not a rendering-feature self-inconsistency — it is
well-formed, spec-legal, and inconsistent with nothing the server advertised. What justifies
skipping it is a **resource ceiling that is ours**, and §3(b) is what obliges the record. That is
the same shape the 2026-08-25 amendment above recorded from #252 (§1 and §2 are not a partition;
§3 does the licensing), now with a third instance at a third layer, so it is **deliberately not**
widened here: the amendment above already says the enumeration is not a partition, and adding "a
resource bound we chose" to §2's list would convert an enumeration of *server* behaviours into a
mixed list. The posture stands: tolerate, and make it observable.

## Amendment (2026-09-04): one VM is one server, and a conformance proof cannot answer a refusal claim

Salvaged from a retired build document. This record routes receive-path questions to what a
real server actually does; what follows bounds that authority, and was written down nowhere
else.

**One VM is one server.** The authority for *what we accept* is a single WS2022 box (memory
`test_environment`, `vm_advertised_graphics_caps`). It proves the paths it **advertises** and
says nothing about the ones it does not. *"The VM is happy"* is not *"servers are happy"*, and
a tolerance derived from it alone is a **hypothesis** until FreeRDP shows the same shape.

**And it structurally cannot answer a refusal claim.** A conforming server cannot produce
non-conforming input, so the VM is unable to exercise a guard that only fires on input it will
never send. The two claim classes therefore need different methods:

| Claim | Method | The trap it still carries |
|---|---|---|
| **conformance** — we speak the protocol a real server speaks | the **real VM** round-trip, full connect to session-active | one VM is one server, as above |
| **refusal** — we reject what no conforming server can send | a **wire-format round-trip through the public entry point**: build the non-conforming PDU as bytes and drive it through the public session API — **never a mock, never the private method**. Plus mutate-and-re-run on `i686-pc-windows-msvc` wherever the guard is arithmetic | **the PDU is a vector *we* authored.** It bounds false positives, not false negatives — a real capture stays the only authority on what a server actually sends |

Recorded because it recurred rather than because it is elegant: **#263** substituted the
32-bit rule by judgement and **#268** substituted a wire-format round-trip, and two
substitutions in a row is a standing gap, not a one-off.


## Amendment (2026-09-16, #286): the per-axis dimension caps are a deliberate divergence, and this is the row

§3's invariants license **tolerances**. This records the one standing **refusal** that is ours
rather than the spec's, because a refusal nobody wrote down reads as a defect to whoever meets
it next — which is how #286 came to be filed.

### What justrdp does

A surface edge above `MAX_SURFACE_DIM` (16384) is refused by `GraphicsProcessor::process`; an
output size above `MAX_DESKTOP_DIM` (the same 16384) is refused by the framebuffer. Both end the
session, per [ADR-0014](0014-dvc-processor-error-posture.md) Decision 1.

### What the wire allows, read raw rather than from either client

| Section | Field width | Stated maximum |
|---|---|---|
| `[MS-RDPEGFX]` 2.2.2.9 `RDPGFX_CREATE_SURFACE_PDU` | `u16` | **none** — the section states no maximum at all, so the wire ceiling is 65535 |
| `[MS-RDPEGFX]` 2.2.2.14 `RDPGFX_RESET_GRAPHICS_PDU` | `u32` | **32766**, with `monitorCount` MUST ≤ 16 |
| `[MS-RDPEDISP]` 2.2.2.2.1 `DISPLAYCONTROL_MONITOR_LAYOUT` | `u32` | **8192** per monitor, and ≥ 200 |

Two consequences the ticket did not carry. **32766 is not a surface number** — `egfx.rs` cited
2.2.2.14 as the ceiling for `MAX_SURFACE_DIM` until this change, and that section bounds the
Graphics Output Buffer, a different quantity. And **32766 bounds a virtual desktop spanning up
to sixteen monitors**, while a single monitor's legal maximum is 8192 — which justrdp's own
`request_resize` already enforces on the outbound side. justrdp does not consume `monitorCount`
(`justrdp-pdu/src/egfx.rs` decodes width and height and skips the rest), so it cannot tell a
one-monitor 32766-wide output from a four-monitor one. Multi-monitor is epic #27, unbuilt.

### What the references do, each re-opened at source

- **Microsoft's client conformance suite** (`microsoft/WindowsProtocolTestSuites` `2447a665`)
  exercises 32766 in two `[TestCategory("Positive")]` tests that expect a frame acknowledge:
  `RDPEGFX_SurfaceToScreen_PositiveTest_CreateSurface_MaxWidth` and
  `RDPEGFX_SurfaceToScreen_PositiveTest_ResetGraphic_MaxHeighWidth`, both in
  `RdpegfxSurfaceToScreenTest.cs`. **Neither asks for 32766 square.** The other axis is the
  1024x768 test desktop, so the largest allocation either demands is 134_209_536 bytes —
  128 MiB, already under `MAX_TOTAL_SURFACE_BYTES`. justrdp fails both, and it fails them at the
  first `ResetGraphics` rather than at `CreateSurface`. (The suite's own inline comment
  *"the output window is too large 32766\*32766"* is wrong about its own test.)
- **FreeRDP caps neither site.** `gdi_CreateSurface` scanline-aligns and lets
  `winpr_aligned_malloc` return NULL; `gdi_ResetGraphics` sets `FreeRDP_DesktopWidth`/`Height`
  with no check (`libfreerdp/gdi/gfx.c`). It is the **only independent reference here**, and it
  would pass both tests.
- **IronRDP is not a second vote.** `ironrdp-egfx`'s compositor carries
  `MAX_SURFACE_DIM: u16 = 16384` and `MAX_COMPOSITOR_BYTES = 256 * 1024 * 1024` — both of
  justrdp's constants, at the same values, with near-identical justifying prose about a 4K
  surface being ~33 MiB and servers keeping a handful. The direction of the lineage is
  unestablished; the independence is not
  ([oracle agreement is not independence](../map/invariant/oracle-agreement-is-not-independence.md)),
  and this is that invariant's first instance at the **design-constant** layer rather than at
  decode output. Its *output* handling is inapplicable for a second, structural reason: its
  compositor holds no retained output buffer — `output_width`/`output_height` are clip bounds and
  output leaves as `OutputUpdate` deltas — so its `unwrap_or(u16::MAX)` clamp bounds nothing.
  justrdp holds the retained framebuffer by [ADR-0010](0010-frameupdate-dirty-rect-contract.md).

### Decision

**Keep 16384 at both sites and record the divergence rather than closing it.** The licence is
the one the 2026-08-31 amendment above already names: this is **a resource ceiling that is
ours**, and the spec asks for it neither way. Two measurements decide it against raising:

- **No server has ever sent a dimension above 16384.** The one VM is 1280x800, and per the
  2026-09-04 amendment a conforming server *structurally cannot* exercise a refusal guard. There
  is therefore no further evidence to gather here; the choice is made on what exists.
- **Raising it is not a constant change.** At 16384 the product is exactly 1 GiB and fits a
  32-bit `usize` by construction. At 32766 it is 4_294_443_024 — which clears `u32::MAX` by
  524_271 bytes and then overflows on the very addition that checks it against
  `MAX_TOTAL_SURFACE_BYTES`, and which is twice `isize::MAX`, the band
  [ADR-0012](0012-consumption-site-totality.md) §2's 2026-08-31 extension measured. So the
  alternative is a checked product at both sites, a framebuffer byte ceiling that does not exist
  and has no derivation (the 256 MiB is derived for *surfaces*), a placement decision for a
  helper that is `pub(crate)` in another crate, and two *by construction* comments plus an
  invariant entry rewritten — for a geometry no server has asked for.

**Kind: judgement.** Three shapes were enumerated with their consequences and the maintainer
chose this one. A better derivation does not reopen it; the maintainer does.

### What this does not decide

- **Whether a refusal in this class should keep ending the session.** That is ADR-0014
  Decision 1, and the recovery ladder is #272's. If that ladder ever gives the core a non-fatal
  verdict, this row is a candidate for it — ADR-0014's own not-covered list named this rung.

### The two rows this record was already owed

`egfx-graphics-pipeline.md` recorded both as *"a deliberate-divergence note is owed"* and
neither had anywhere to go. Both citations below were re-opened at source on 2026-09-16 rather
than copied from that note.

**Row 2 — an inverted `destRect` is tolerated as an empty rectangle; both references refuse it.**
`Rect16::width()` is `right.saturating_sub(left)`, so `right < left` yields extent 0 and, since
#262, `Ok(Vec::new())` — nothing painted, no error. FreeRDP refuses it on the receive path before
anything else: `RecvWireToSurface1Pdu` logs and returns `ERROR_INVALID_DATA` for `right < left`
and again for `bottom < top` (`channels/rdpgfx/client/rdpgfx_main.c`). `ironrdp-egfx` returns
`Err(pdu_other_err!("invalid destination rectangle ordering"))` for the same condition
(`crates/ironrdp-egfx/src/client.rs`) — and it is that crate's **one** hard error on this path;
the surface-bounds check immediately below it only `warn!`s. `[MS-RDPEGFX]` 2.2.1.2 states no
ordering requirement, so tolerating it is spec-legal, and §3(a) holds: the bytes are still fully
validated. **Kept**, because the cost of tolerating it is zero — an empty rectangle paints
nothing either way. Note that all three clients compare *strictly*, so `right == left` is
accepted everywhere; that is a legal empty rectangle and a different case, which is #262's.

**Row 3 — an over-budget paint entry is skipped, and both the channel and the session survive.**
Past the per-frame paint budget the three list-bearing commands skip their remaining entries and
return `Ok` (#268). FreeRDP closes the dynamic channel whenever a processor fails:
`if (status != CHANNEL_RC_OK) status = dvcman_channel_close(channel, FALSE, FALSE);`
(`channels/drdynvc/client/drdynvc_main.c`, at both the data-first and data paths). `ironrdp-egfx`
does not bound the count at all, and its compositor's `solid_fill`, `surface_to_surface`,
`surface_to_cache` and `cache_to_surface` all return `()` — so it has no place to put a refusal
even if it wanted one. **Kept**, on the ground the 2026-08-31 amendment already names: an
over-budget count is well-formed and spec-legal, and refusing it would end a session over a
resource ceiling that is ours — which [ADR-0014](0014-dvc-processor-error-posture.md) then priced
at the whole session rather than the channel. This row used to carry a second ground, that
Microsoft's conformance suite drew the same line; ADR-0014's enumeration **measured that false**,
and the row stands on the first ground alone.

## Amendment (2026-09-18, #297): row 4 — a cache slot outside 3.3.1.4's one-based range is skipped

`GraphicsProcessor` keyed its bitmap cache by whatever `u16` the server sent, so slot 0 and slots
above the confirmed cache's maximum were stored, pasted and evicted like any other. Memory was
never at risk — the byte budget (#273) bounds it — so this was a conformance gap. It is now
closed on **rung 1**: out of range is warned (`rdp_egfx`) and the PDU is skipped, on all three of
`RDPGFX_SURFACE_TO_CACHE_PDU` (2.2.2.6), `RDPGFX_CACHE_TO_SURFACE_PDU` (2.2.2.7) and
`RDPGFX_EVICT_CACHE_ENTRY_PDU` (2.2.2.8). The maximum reads the **same predicate** as the byte
budget, so the two cannot disagree about which cache was confirmed.

### What the spec actually says, re-opened at source on 2026-09-18

`[MS-RDPEGFX]` 3.3.1.4 has **one MUST, and it is on bytes**: *"The size of the bitmap data stored
across all of the in-use variable-length slots at any point in time MUST NOT exceed the total size
of the cache."* The slot index is described, not mandated — *"a variable-length slot (identified
by a one-based slot index)"* and *"The maximum possible number of variable-length slots is 25,600
in the case of a 100 MB cache and 4,096 in the case of a 16 MB cache."* The three PDU sections say
only *"The value of this field is constrained as specified in section 3.3.1.4."*

**This matters because #297 was filed, and triaged, on the reading that an out-of-range slot
violates a MUST.** It does not. The maintainer's original call (refuse, ending the session) was
made against that reading, so it was untested rather than settled, and it was re-taken on the
corrected one.

### Both references, re-opened at source on 2026-09-18

**FreeRDP refuses it**, `ERROR_INVALID_INDEX`, in `rdpgfx_set_cache_slot_data` and
`rdpgfx_get_cache_slot_data` (`channels/rdpgfx/client/rdpgfx_main.c`), and the error propagates
out of `rdpgfx_recv_pdu`. **Part of that check is memory safety rather than posture**: its cache
is `void* CacheSlots[25600]` (`channels/rdpgfx/client/rdpgfx_main.h`) indexed directly as
`CacheSlots[cacheSlot - 1]`, so an unchecked slot is an out-of-bounds write and `cacheSlot == 0`
underflows. Two things separate the rest from the guard, and both were checked: the array is
`[25600]` **whatever the cache size**, while `MaxCacheSlots` is `4096` under `FreeRDP_GfxSmallCache`
(`rdpgfx_main.c`, `init_plugin_cb`) — 6.25x tighter than safety needs, so the small-cache bound is
a conformance choice; and FreeRDP does **not** bound surface ids at all, because `SurfaceTable` is
a `wHashTable`. It also sizes `MaxCacheSlots` from its **own setting** at plugin init and never
from the Caps Confirm, which is the opposite of what this change does.

**`ironrdp-egfx` does not bound it at all.** `Compositor::cache_to_surface` is
`let Some(tile) = self.cache.get(&cache_slot) else { return; }` and every cache operation returns
`()` (`crates/ironrdp-egfx/src/compositor.rs`) — the same structural reason row 3 already records
for the paint budget: it has nowhere to put a refusal.

### Measured on the WS2022 VM, 2026-09-18

Throwaway `eprintln!` instrumentation in the three arms, never committed; two invocations, four
runs, **9,965 slot observations**, each run ~45 s of mouse sweeps and Start-menu opens.

| | default config | `versions: [CAPVERSION_103]` |
|---|---|---|
| confirmed capset | `0x000a0400`, flags `0x20` | `0x000a0301`, flags `0x20` |
| so the budget is | 100 MB → 25,600 slots | 16 MB → **4,096 slots** |
| `SURFACE_TO_CACHE` | n=201, slots **2..202** | n=215, slots **2..216** |
| `CACHE_TO_SURFACE` | n=2,196, slots 2..170 | n=2,197, slots 2..186 |
| `EVICT_CACHE_ENTRY` | **n=0** | **n=0** |
| slot 0, and slots > 4,096 | **0, 0** | **0, 0** |

**No counterexample, so nothing reopened.** Two facts decided the rung instead. First, **the
server does not track the maximum**: slots are a plain counter from 2, contiguous and strictly
increasing, with no reuse and no eviction — and the run that confirmed the *16 MB* cache used
*more* slots (216) than the 100 MB run (202), so the number follows session length and not the
budget. Second, **`EVICT_CACHE_ENTRY` was never sent**, so a refusal there would put a
session-ending failure on a path nothing has observed.

**A fifth run settled what the first four left open, and it corrects an argument this row
originally carried.** Entry sizes at a confirmed 10.3, 43 entries: exactly two values, **16 384
bytes (64x64 RGBA) and 8 192 (64x32)** — independently the same shapes #268 measured. Break-even
for the slot bound to bind first is `16 MB / 4 096 = 4 096` bytes, and the **smallest** entry this
server produces is twice that, so the 16 MB budget is reached by slot ~2 048 in the worst observed
case and ~1 240 at the mean. **The byte budget always fires first at a confirmed 10.3, and the
slot bound is unreachable there.** This row first argued the opposite — that a 10.3 session
crosses 4 096 in about fifteen minutes — which was an extrapolation from slot counts with no
entry size behind it. The rung does not change: it rests on the normative reading and on the
server not tracking the maximum, neither of which this touches. What changes is that **choosing
skip over refuse costs nothing measurable against this server**, because the range this guard
protects cannot be entered before a different guard ends the session.

Still bounding only this traffic: **no run measured peak cache use**, and the cache-exhaustion
consequence that falls out of these numbers is a separate finding, not this row's — see
[the EGFX territory note](../map/territory/egfx-graphics-pipeline.md)'s Known holes.

**Kept as a skip**, on the ground row 3 already names: the refusal would end a session over a
ceiling that is ours in the only sense that counts here — the section's own MUST is the byte
total, which is enforced and still drops (ADR-0014's 2026-09-17 amendment, Decision 2) — and
ADR-0014 prices a processor refusal at the whole session rather than the channel. §3(a) holds
unchanged: the bytes are still fully validated, and this narrows only which slots may appear.

**Kind: judgement.** Four postures were enumerated with their consequences — refuse (fatal),
warn-and-skip, semantic miss taking the 3.3.5.19 reset, and do not implement — and the maintainer
chose warn-and-skip. A better derivation does not reopen it; the maintainer does.

### What this does not decide

- **Whether the evict-side guard earns its place.** Its skip is unobservable by construction: the
  fill path already prevents an out-of-range slot from being occupied, so `remove` was always a
  no-op there. Mutation testing confirms it — deleting that one guard reddens no test. It is kept
  for the warn and for uniformity across the three PDUs, and this crate has no tracing-assertion
  facility to pin the warn (neither does #268's row-3 warn).
- **Whether an in-range unfilled slot should keep taking the reset.** Unchanged, and neither
  reference has this two-rung split: FreeRDP fails both cases identically and `ironrdp-egfx`
  tolerates both silently.
- **Cache import** (2.2.2.16/.17) and the persistent bitmap cache (3.3.1.5, epic #28), neither of
  which this client implements.
- Any server but one WS2022 box, at any version but 10.4 and 10.3.
