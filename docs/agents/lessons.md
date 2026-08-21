# Lessons — justrdp (war-story index)

What gives each `theflow` rule its teeth in this repo. Indexed by step, anchored
to the ADRs and issues. This project is young (0.1.0, plan-driven), so most
entries are **decision anchors** — the concrete reason a rule exists here — rather
than "a step was skipped and it cost us" incidents; add the latter as they occur.

Read this before starting so the bindings do not read as abstractions.

---

## Origin — why justrdp exists (the boundary has teeth)

- **A single hidden flag.** `ironrdp-connector` 0.9.0 omits
  `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), so EGFX cannot be enabled — one flag,
  buried, un-overridable. justrdp is the rewrite that lets the **host hold every
  RDP feature flag**. The boundary invariant (core owns all RDP-native layers,
  delegates only security-critical non-RDP crates) exists to keep that control.
  (`CONTEXT.md` §Project intent.)

## Step 1 — spec + real source, derive don't copy

- **Spec ≠ interop.** Code that matches `[MS-*]` can still not be byte-identical
  to a real server; the tolerance a server actually needs (caps it violates) is
  spec-unwritten and lives in FreeRDP/IronRDP source — #101 / ADR-0009 (tolerant
  negotiation posture) is the standing form of this.
- **Derive, don't copy (ADR-0003).** IronRDP code is re-derived from spec, and
  correctness is proven by differential test, not structural similarity — which is
  also what lets the `ironrdp-graphics` dependency be *dropped* once the oracle passes.
- **A dependency's decode path is a surface neither of this repo's rosters can
  name (#189).** zgfx was the *outermost* decoder on the EGFX path — every server byte
  crosses it before `justrdp_pdu::egfx::decode_all` — and it had neither a proptest nor a
  fuzz target, not by oversight but because it was delegated to `ironrdp-graphics`. The two
  derivations the never-panics invariant carries (`ls fuzz/fuzz_targets/` and a walk of
  `crates/*/src`) both enumerate *our* code, so they answered "fully covered" while a live
  decoder sat outside them. Probed rather than reasoned about: **5 of 7** crafted
  `RDP_SEGMENTED_DATA` messages panicked, and the panic surfaced at
  `justrdp::egfx::GraphicsProcessor::process` — the core. The generalisation is small and
  worth keeping: **a completeness claim inherits the scope of the list it was derived from**,
  so the question to ask a green roster is what it enumerates, not how long it is.
- **A blocker nobody re-checked was inherited by two issues in a row (#230).** #203 and #230
  both recorded that the `&mut ReadCursor<'_>` entry points *"have no signature to point
  `fuzz_target!` at directly"*, and #230 named that as why #200 could not add them mechanically.
  It is false twice over: `cursor` is a `pub mod`, and `fuzz_targets/license.rs` has built a
  cursor inside the target since **#99**, two issues before the claim was first written. What
  actually blocked #200 was that `gcc` and `mcs` have no single top-level `decode` — a real
  constraint that happened to travel with the same modules and got restated as this one.
  The cost was not a wrong implementation; it was a **wrong estimate**, carried across three
  issues, of how hard a piece of work was. `grep` for one existing target settled it, and the
  general rule is the one this section already states about external facts: the rationale *this
  repo* writes is a verification target too, and a filed issue is exactly where an unre-read
  sentence goes to be believed.
- **A missing map edge is invisible to the gate that checks map edges (#237).** The
  untrusted-decode invariant carries two derivation commands *and* a human-readable
  **Territories it holds in** list — which is the one a reader following the map lands on, and
  which was missing three of them: capability exchange & activation, MCS / GCC channel setup,
  X.224 negotiation. Two were covered anyway; the third is where `finalization`'s three
  undriven parsers lived, and the absent edge is why nothing pointed at them.
  `check_map.py`'s reciprocity check is green over this by construction: it verifies that an
  edge which *exists* runs both ways, and a territory claiming no invariant is consistent with
  an invariant claiming no territory. **A reciprocity gate proves the edges you drew are
  symmetric, never that you drew them** — the same shape as #200's hand-kept matrix and #230's
  module-name roster, one artifact further out. The check that finds it is one line in a
  completeness pass: list every territory whose `## Code` names a parser module and ask which
  do not claim the invariant.
- **CVE knowledge is a reference, not a memory** — rle/planar/clearcodec/nsc OOB
  points (memory `rdp_decoder_robustness_refs`); read them at FreeRDP source.

## Step 2 — sans-IO core vs adapter (ADR-0001/0002)

- **The core never sees a `TSRequest`.** `sspi` (CredSSP/SPNEGO/NTLM/Kerberos) and
  `rustls` are security-critical, non-RDP leaf deps, so they live in the adapter
  (`justrdp-tokio`), not the core — the core stays socket-free, runtime-free, and
  policy-agnostic, which is exactly what makes it deterministically testable.
- **`ring` over `aws-lc-rs`** — the rustls provider is chosen to avoid the NASM
  build requirement on Windows; `rustls-platform-verifier` supplies the OS trust
  store (#36).

## Step 3 — the test-trust gate

- **A mutation harness can report a false green, and the tell is not in its output
  (#189).** Nine mutations were run in batches: write the mutation, `cargo test`, parse the
  FAILED lines, revert. One of them — a single wrong literal in the zgfx token table —
  came back **"no test went red"**, which reads as a coverage hole in the differential and
  would have been written up as one. Re-run alone it turns **two** tests red. The cause is
  mtime granularity: the previous mutation's revert and this one's write landed in the same
  filesystem timestamp tick, so cargo skipped the rebuild and the batch tested *unmutated*
  code. The harness never checked `returncode`, so "no failures parsed" and "nothing ran"
  were indistinguishable in its output.
  Two things this pins. **The instrument that proves a test can fail must itself be provably
  running** — the gate turned on itself, and the cheapest guard is asserting the process
  actually failed (`returncode != 0`) rather than trusting a parse of its stdout. And **a
  false green here is worse than a false red**: a false red gets investigated, while a false
  green is *evidence of a hole that does not exist*, which sends the next hour into writing
  a test for a case already covered.

- **A no-panic property can be structurally unable to reach the arithmetic it is named after,
  and the hand-written test beside it is what exposes that (#230).** `pointer`'s two entry-point
  properties were written the way every other one in this repo is — `vec(any::<u8>(), 0..=512)`
  into the `pub fn` — and both passed over an out-of-bounds read injected into the mask
  `read_slice`, while `malformed_pointers_are_typed_errors`, four screens down the same file,
  went red on it. Random bytes must land `messageType` on one of two values (2/65536) **and**
  both dimensions inside the 96-pixel cap ((97/65536)²) before either mask read executes: about
  **6.7e-11** per case against a 2048-case budget.
  This is #211's `nscodec` finding run backwards, and the pair is the thing to remember. There a
  generator **bounded** to the parser's range asserted the parser instead of the function; here
  a generator too **wide** to satisfy the parser asserted the dispatch instead of the function.
  Same worthless green from opposite directions, and the only instrument that tells either of
  them from a real one is the mutation. The shape that works is to **weight** each header field
  into the range the parser admits while keeping an `any::<...>()` arm on it, so the reject arms
  stay driven — a bound with no arm is the #211 failure, an arm with no weight is this one.
- **Two sequential reads from one hostile-length family: the first masks the second (#230).**
  Same change, found by running the mutation twice. With both pointer mask lengths generated as
  arbitrary `u16` (mean 32768) against a tail of at most 512 bytes, `read_slice(lengthXorMask)`
  errors before the AND read in nearly every case, so an out-of-bounds read injected into the AND
  mask is caught by `decode_fastpath` in **1 of 3** runs — against **3 of 3** once the length
  strategy also emits satisfiable values. The generator needs both kinds of length, or everything
  downstream of the first length field is reached only by accident.
  The cheap general form: **mutate every read in the sequence, not the first one that goes red.**
  One red is enough to claim discriminating power and not enough to know what it discriminates.
- **Weighting a generator is something you *add*; substituting is how the shallow reads go dark
  (#230).** Fixing the reachability problem above by replacing the undirected body with a
  structured one made the mask arithmetic reachable and made `decode_slowpath`'s `pad2Octets`
  read **unreachable** — every generated body now carried a 4-byte prefix, so a body too short
  for that read could not be produced at all. Measured: an unchecked read injected there, three
  runs, nothing in the module red. One `truncate_to` arm at 10% weight took it to 3 of 3. The
  shape to watch for is a generator that *assembles* rather than *samples*: it can only produce
  inputs at least as long as what it assembles.
- **The #189 mutation-harness trap recurred, in the repo that already had the note, and it
  fabricated a finding (#230).** A harness that mutates, tests, reverts and immediately writes
  the next mutation lands two writes in one filesystem timestamp tick; cargo skips the rebuild
  and the run tests unmutated code. Three numbers came out wrong: an AND-mask row that read
  "green" is "1 of 3", a run that read 0 red is 3, and an entire finding about `license`'s
  `MACData` bound — *"5 of 10 property-runs red, a coin flip"* — evaporated on re-measurement
  (unweighted catches it 2 of 2, every run). A weighted generator had already been written to fix
  it and was reverted.
  Three things this pins beyond #189's own entry. **The guard has to be in the harness, not in
  the operator** — knowing the note existed did not prevent it; adding `Compiling <crate>` to the
  assertions did. **A false green does not merely cost an hour, it manufactures a hole**, and
  work then flows toward guarding a case nobody observed — which is the same waste as #171's
  region-union machinery, arrived at from the other direction. And **a subagent lens using the
  same broken instrument produces confident, reproducible, wrong numbers**: the refuting lens on
  this change reported the `license` finding at 1/5 and 3/5, and it was reproduced here before
  anyone thought to doubt the instrument. Reproducing a lens's claim with the lens's method is
  not verification.
- **When the suite is already green, the discriminating power has to come from somewhere
  that is not the suite (#198).** The change made every synthesised desktop step wait for the
  server's own repaint before sending the next one — and the VM suite passed 15/15 both before
  and after, because the race it removes is a race. A VM run therefore proves *nothing about
  this change*; it only shows nothing broke. What proved it were two things that need no VM at
  all. **Six mutations**, each turning one part of the fix off and each caught by a named test:
  dropping the `> 0` settle guard, settling on any non-decreasing read, counting the count you
  started from, forgetting the `/` that `shutdown /l` needs, sending the Start click once
  instead of retrying, and not counting the retried clicks. And **a fake shell** — a task that
  reads the input channel and simply declines to draw for the first two clicks, which is
  exactly a cold logon where the desktop is up and the taskbar is not. The retry is the new
  behaviour, so it is the one worth proving against something that can be made to misbehave on
  demand; the real VM cannot be asked to have a slow shell.
  The corollary is about *where* the primitives live. Extracting `await_desktop` /
  `painted_since` / `vk_for` out of five open-coded copies is what made them testable at all —
  the same logic inside a `tokio::spawn` in a `#[ignore]`d test is reachable only by a VM.
- **`0 == 0` is a settled desktop, and that is the whole bug (#198).** Five VM tests spun on
  *"the frame count stopped changing"*; **three** wrote `now == last && now > 0` and **two**
  wrote `now == last`. The guard looks like defensive padding and is load-bearing: before the
  first frame ever arrives the count is 0, has been 0, and the loop exits immediately — so the
  test proceeds to click Start and type into a desktop that has not painted a pixel. It only
  became reachable when #197 replaced the suite's warm reattach with a cold logon, and the one
  test #197 measured red is one of the two without the guard. Two readings: **a guard present
  in most copies of a pattern and absent in the rest is a finding, not a style difference** —
  the divergence is cheap to grep for and it names the bug; and a fix that deletes the copies
  is what stops the next one being written without it.

## Step 4 — real round-trip, not a fake (ADR-0003/0007)

- **Codec proof is byte-identical, or it is not proof.** The same bitstream through
  our decoder and `ironrdp-graphics` must produce an identical `Vec<u8>`; 100% pass
  is the gate to drop the oracle dependency. connect/session proof is a real VM
  round-trip (`192.168.136.136`, memory `test_environment`) — a demo is not proof.

- **A measurement that can misread itself, built and thrown away (#172).** The
  bindings name that trap; this is what it looked like. Wiring the self-owned
  Progressive decoder into `justrdp::egfx` seemed to admit a decisive check: assemble
  the *same* real-VM payloads twice — once through the core (`Surface::blit`, the
  dirty list, the surface→framebuffer blit) and once directly onto a canvas — and
  since the decoder is shared, any disagreement localises in the new wiring. It
  measured **17–19% agreement**, which reads as a serious defect and is not one. The
  replay canvas is a WireToSurface2-only *accumulation* that never forgets — it still
  held the wallpaper, a Start menu closed thirty seconds earlier, and a boot-time
  overlay — while the live `Surface` receives ClearCodec and WireToSurface1 blits into
  the same buffer and holds the session's true final screen. The number was **the
  fraction of pixels where Progressive happened to be the last writer**: a property of
  the server's codec scheduling, not of this client.

  Two things it pins. **The artifacts have to be produced before the assertion, or a
  70-second run costs 70 seconds and leaves nothing to look at** — the first two runs
  panicked before the PPM dumps and the number was unreadable; moving the dumps ahead
  of the check settled it in one glance. And **a plausible number is the dangerous
  outcome**, not an implausible one: 0% would have been read as "the comparison is
  broken" immediately, where 18% invites tuning the threshold until it passes. The
  comparison was removed rather than tuned, with what would make it well-posed
  recorded where it stood (drive the replay through a `GraphicsProcessor` so both
  sides see every codec in arrival order — which needs a core-side replay seam that
  does not exist).

- **The VM proves what the VM sends, and the only way to know that is to count it
  (#189).** The zgfx swap's round-trip was the existing EGFX acceptance test, and it passed —
  198 frames, a correct Server 2022 desktop, dumped and looked at. What the pass does *not*
  say is which of the decoder's paths carried it, so a throwaway probe counted: **25 messages,
  every one `ZGFX_SEGMENTED_SINGLE` and every one `PACKET_COMPRESSED`** — 18 488 literals,
  19 024 matches, 7 unencoded runs, longest match 5 062 bytes, **longest distance 133 937**.
  Two opposite conclusions came out of the same five minutes, and neither was guessable. The
  token decoder is *heavily* exercised, and the 133 937 is direct evidence of the history
  window spanning messages on a real wire — stronger than the hand-built test that asserts the
  same thing. And the **multipart descriptor never appeared at all**, so `0xE1`'s framing is
  proved by the spec vector and the oracle differential and by nothing a server has done.
  Recorded in the territory's `## Known holes`, because "the VM renders the desktop" would
  otherwise have been written as if it covered the whole module.

- **A five-minute probe killed a direction the issue had spent a day arguing for (#198).**
  #198 listed three ways to make the VM teardown robust and chose none; the second — implement
  the RDP Shutdown Request PDU — came with a real argument (it is a protocol capability we lack,
  and it would turn a refusal into a *typed* answer instead of a modal to read off a
  screenshot). The issue also recorded, honestly, that *"the spec pages do not state the
  condition under which the server denies"*. One throwaway probe answered it: send `pduType2`
  **0x24** to this VM on a **clean** desktop — nothing open, nothing unsaved — and **0x25,
  Shutdown Denied**, comes back and the session stays up. The direction dies as a teardown
  mechanism in five minutes rather than after a day of implementing it.
  Two things worth keeping beyond the number. **`docs/plan.md` had already guessed it** —
  §V.3's slice reads *"assert the server replies with Shutdown Denied (typical)"*, written
  long before — so the ledger Step 1 makes you open contained the answer to the question the
  issue said was open, and reading it first is what made the probe a confirmation rather than
  a discovery. And **the direction is still worth doing, just not for this**: the probe turns
  §6b's unwritten slice from speculative into pre-measured, which is the difference between
  killing an idea and relocating it.
- **The premise was already false before the work started — and so was the issue's (#198).**
  Two of them, in opposite directions, and both had to be measured rather than reasoned about.
  *Its Definition of Done was already met*: #198 was filed at 11 of 12 passing and asks for
  "12/12 in parallel, twice"; measured before touching anything, the suite was **15/15 in
  parallel** (it had grown to 15 tests), 620 s. So the acceptance criterion could have been
  signed off on a green run, and should not have been — **a green run does not make an
  open-loop step closed-loop, it makes it lucky today.**
  *And its central claim was wrong.* The issue rests on Microsoft's `shutdown` reference —
  *"the /l parameter works independently and can't be combined with any other parameters …
  is ignored"* — to conclude that the `/f` in `shutdown /l /f` is dead text and the comment
  crediting it with forcing applications closed is false. Acting on that read the flag was
  removed, the suite went red at exactly the test that leaves Notepad holding unsaved work,
  and the PPM the teardown dumps showed **Notepad's own save prompt**. A/B from a clean
  session, one variable: `/l /f` signs out in 63 s, `/l` is blocked at 150 s. The flag is
  load-bearing and the documentation does not describe this path.
  The lesson is sharper than *"verify external facts"*, because that rule was followed — the
  reference was fetched and read verbatim off its primary source rather than taken from the
  issue's quote, and it was still wrong about the machine. **A correctly-read document is a
  claim, not an observation**, and for what a real system *does* only the system arbitrates
  (the receive-side half of the bindings' tie-breaker, and ADR-0009's posture one layer out).
  The thing that made it recoverable in one run is #182's PPM dump: two modals with two
  different causes — Notepad's *"save changes?"* and Windows' *"close N apps and sign out"* —
  are indistinguishable from a timeout message and obvious from a screenshot.

- **Eight green mutations, two green fake shells, and the real VM found the defect anyway
  (#198).** The change made every synthesised desktop step wait for the server's repaint. It
  was mutation-tested (eight, each caught by a named test) and driven against a fake shell
  that declines to draw. All green. The VM then failed at the first teardown, and the PPM
  showed the Start search box holding **`hutdown /l /f`** — Windows answering *"no results"*
  to a command whose leading `s` had been dropped.
  The bug is one word wide: `painted_since` answers **"it started drawing"**, and typing needs
  **"it finished"**. A menu that has begun opening is not yet taking input. Closing a loop on
  the wrong *edge* is its own defect class, and none of the VM-free machinery could see it
  because every one of those tests modelled a shell that draws instantly.
  Three things worth keeping. **A fake is only as good as the failure it can express** — the
  fix was not to trust the VM more but to teach the fake shell to swallow input while it is
  still painting, at which point the mutation goes red like the others. **The blind
  `sleep(2s)` this change removed happened to cover exactly this case**, which is the honest
  reading of a fixed sleep: not wrong about everything, *unfalsifiable* — it covered this and
  missed the cold logon, and the code said which for neither. And the pass that found it is
  the one this repo already had: **Step 4 is not a formality when Steps 3 and 5 came back
  clean**, it is precisely then that it is load-bearing.
- **A guard nothing can turn red is a decoration (#198).** Of the two quiescence waits added
  above, mutating the first turned a test red and mutating the second turned **nothing** red —
  it guarded Enter committing a half-resolved search result, which no fake modelled. That is
  the same finding as #224's non-discriminating self-test case, one layer out: the fix is to
  extend the fake until the mutation bites, not to keep the guard on the strength of the
  argument for it. Both are now caught by the same shell.
- **A mutation harness that aborts leaves the tree mutated (#198, after #189).** #189 taught
  it to check `returncode`; this run taught the other half. Two aborts — one where a `cargo
  fmt` had reformatted a mutation's target string so the pre-write assert threw, one where the
  reader closed the pipe — each left a *previous* iteration's mutation on disk, and the next
  run then captured the mutated file as its `ORIGINAL`, so the restore would have written the
  mutation back permanently. The guard is one line, `atexit.register` the restore, and the
  tell that you need it is that the harness's own failure mode is silent: the tests still
  pass, on code you did not write.

- **"Remove the hazard" beat "handle the hazard" on paper and lost on the VM (#198).** The
  teardown signs out through the Windows UI and an application holding unsaved work can veto
  that; slice-7 was the only test that left any. Two ways out: force past it (the sign-out's
  `/f`, measured) or delete the cause (launch a console instead of Notepad, close it with
  `exit`). The second is strictly safer by inspection — nothing to save, nothing to veto,
  nothing to guess at — and it is what the maintainer chose when the modal count reached six.
  The VM priced it in one run: a console's client area carries the **same arrow as the
  desktop**, so the server never pushes a *decoded* pointer shape and slice-7's `shapes >= 1`
  (issue #41) saw 60 cursor events without a single `Set`. The I-beam over Notepad's edit area
  is the only surface in the suite that produces one.
  The generalisable part is not about Notepad. **The hazard was also carrying a proof**, and
  nothing in the reasoning that removed it could see that, because the proof lived in a
  different assertion in the same test — one about pointers, not about sign-outs. Before
  deleting a thing to remove its risk, ask what *else* is standing on it; a test that asserts
  two unrelated properties is exactly where that goes unnoticed.

- **A throwaway probe's bytes outlive the probe, and they are the best send-path test there
  is (#228).** #198's probe hand-built a Shutdown Request to find out what the VM would answer.
  The answer settled that issue; the **32 bytes** settled the next one. `request_shutdown` is
  pinned to them exactly — `request_shutdown_encodes_the_frame_the_vm_answered` — so the test
  does not say *"we read `[MS-RDPBCGR]` 2.2.2.1 the same way twice"*, it says **a real Windows
  server parsed this frame and replied to it**. That is a different class of evidence, and it
  costs nothing but remembering to keep the array.
  The generalisation: a probe run to answer a question is also a **capture**. Copy the bytes
  into the issue before deleting the probe — Step 1 already says to record the number, and
  this is the same rule one level down, on the wire.
- **"Decoded and skipped" is not handled quietly, it is unlearnable (#228).** `pduType2` 0x25
  fell into `on_data_pdu`'s catch-all, so a host that sent a Shutdown Request and a host that
  sent nothing produced **identical** observable behaviour — the session simply carried on in
  both cases. The map's own rule is what names this: the five `SessionOutput` variants are the
  host's whole view of a live session, so anything not among them cannot be learned at all. A
  catch-all arm is a fine default for PDUs nobody asked about; it stops being one the moment
  the client can *cause* the PDU.

## Step 5 — adversarial completeness is automated (ADR-0008)

- **proptest no-panic (#98) + cargo-fuzz (#99)** make the completeness axis
  *continuous* for untrusted parsing — the decoder enumeration you cannot trust
  yourself to have finished. (They are two automations of **one** property, not two
  lenses; the pass itself is one lens briefed on both corpora — see the bindings.)
- **Its surface is covered by derivation rather than by a list, and this bullet is the
  worked example of why** — it read "ten fuzz targets exist" until #200 (a sentence
  praising derivation while hand-copying the number in its own second half, wrong from
  the day `progressive` landed), then read "the connect-sequence parsers have none"
  until #203, having been left alone while #200 gave six of them both artifacts. Twice
  stale, both times in the half that was a hand-kept fact rather than a rule. The
  standing derivation is in
  [`docs/map/invariant/untrusted-decode-never-panics.md`](../map/invariant/untrusted-decode-never-panics.md);
  what it now finds uncovered is `ber`/`per` (deliberate), `share`/`update`/`errinfo`,
  and the #230 pair.

- **The pass found a panic in the code written to remove panics (#189).** The whole
  point of self-owning zgfx was that the delegated decompressor panicked on untrusted input;
  the replacement shipped with three no-panic proptests, two of them *directed* (prefixed with
  a valid wrapper, because a descriptor byte and a compression-type nibble gate the token
  decoder behind 1-in-2048 of random prefixes). All green at 2048 cases each. The adversarial
  pass then walked the bit cursor's invariants by hand and found that the byte-alignment step
  before an unencoded run could push the position **past** the segment's budget, after which
  `remaining()`'s subtraction underflows. Reproduced in one hand-built message, confirmed as a
  real panic, fixed by making the alignment refusable.
  Why the property could not find it: the input needs a specific first body byte, a specific
  trailing unused-bit count *and* a specific length to coincide — the same three-way
  coincidence #219 records, and the same conclusion. It also sharpens what "directed" buys: the
  prefix got the generator past the wrapper, which is necessary and nowhere near sufficient,
  because the depth that matters is *inside* the bitstream's own arithmetic.
- **The lane's first crash, and it is the sequel to the entry below (#219).** The
  #168 bullet *"`checked_shl` checks the shift amount, never the value"* records why
  `rfx::srl::accumulate` grew a round-trip guard. On 2026-08-19 the nightly fuzz lane
  panicked in that same function — `attempt to add with overflow` — because the
  round-trip has a blind spot exactly one value wide: an arithmetic right shift of
  `i64::MIN` by 63 is `-1`, so `-1 << 63` round-trips **perfectly having wrapped all
  the way**, and the widening to `i64` that the addition leaned on is one value short.
  A family, not a point: any `input == -(1 << j)` at `shift == 63 - j`.

  Four things this pins that #168's entry could only assert.

  - **Two automations of one property is not redundancy, and now there is a
    measurement.** `fuzz.yml`'s header argued the lane exists because coverage
    guidance reaches depth random sampling does not. The sibling proptest generates
    **every value involved** and has since #168 — full-`u8` quant nibbles, `i16::ANY`
    seeds. What it cannot do is make *three* of them coincide. Recorded in the
    invariant's discovery history rather than left in a PR body.
  - **A test can cover the line and miss the sign.**
    `a_shift_that_discards_the_whole_refinement_is_an_error_not_a_no_op` **already
    drove `shift == 63`** — with `sign = 1`, so it landed on the positive branch where
    `2 << 63 == 0` and the guard fires correctly. Line coverage would have called this
    surface done.
  - **The defect was in a written argument, not in a line.** The doc comment directly
    above the panicking `+` named two guards and rested the third on the accumulator's
    width. Which is the shape Step 1's *"external facts and secondhand statements are
    verification targets too"* warns about, turned inward: a rationale committed to
    the repo gets believed, including by its own author one slice later.
  - **"Unreachable through the parser" is not a severity argument on this surface.**
    The parser masks quant fields to nibbles, `quant_add` saturates at 30 and
    `upgrade_shift` subtracts one, so the live path tops out at `shift == 29`. What
    broke was `upgrade_component`'s *declared* contract — total for any `u8` — which
    the module chose deliberately because `ProgressiveQuant`'s fields are plain
    `pub u8` and the bound lives in arithmetic elsewhere. #211 is the same family at
    `rfx/quant.rs` and its evidence table cited this site as already settled.

- **The first incident, and it is about the pass declaring victory (#168).** A solo
  completeness pass on the Progressive SRL decoder found two panics, fixed them, and
  recorded convergence. A second pass — **two subagent lenses split by stance**, one
  hunting gaps and one briefed to *refute* the first's claims, both reading both
  corpora — refuted that convergence and found more than the first round had:
  - **A wrong premise, not a wrong line.** The first round asserted `num_bits` and
    `shift` were 4-bit nibbles bounded by 15 and sized two guards on it. A bit
    position is `quant + prog_quant`, the *sum* of two nibbles, so the real range is
    `0..=30`. One guard then truncated the SRL magnitude loop above 15, leaving the
    shared bit cursor short — **plausible wrong coefficients with `Ok(())`**, which
    the invariant ranks worse than a panic.
  - **`checked_shl` checks the shift amount, never the value.** `2i64 << 63` is
    `Some(0)`, so a real refinement was accepted as a no-op and the pass reported
    success having applied nothing.
  - **A mutant that passed the entire suite.** Resetting `kp`/`nz`/`mode` at every
    band boundary while leaving both bit readers threaded changed 15,786 of 19,500
    real corpus decodes and went green everywhere — because all nine value vectors
    drove a single band, and the one multi-band test set every sign non-zero so the
    SRL path was never entered. The property it broke was one the module names as
    load-bearing.
  - **Two generators built inside the guarantee they existed to test.** The first
    round caught this shape in its proptest ("seeded, not zeroed") and reproduced it
    in the very fuzz target and corpus gate it added in the same commit — both
    zeroed the coefficient and sign arrays, which made two of three routing arms
    unreachable and the divergence's own reachability claim unfalsifiable.

  Three things this pins that the rules only asserted. **The second, refuting lens
  earns its cost on an unconditional trigger** — the bindings say so and this is the
  evidence. **Splitting by stance rather than by corpus is what made the findings
  arrive adjudicated**: both lenses had read FreeRDP *and* the map, so each could say
  which way a divergence went instead of handing it back cold. And **a lens report is
  a candidate, not a finding** — reproducing each one locally is what narrowed the
  reported "family" of four shift sites to exactly one (`planar` is bounded by its
  mask, `nscodec` by parse-time validation), which is a different and more useful
  issue than the one that would have been filed on the report alone (#211).

  The refuting lens also **weakened a claim in the fix itself**: the docs had said the
  owned basis inherited the *oracle's* initial `kp`, when FreeRDP's own
  `WINPR_C_ARRAY_INIT` declaration predicts the same mistake and nothing separates the
  two hypotheses. Restated as the weaker claim that survives. A pass that only ever
  confirms the author is not adversarial.

- **#169 (Progressive slice 3) — the pass found three defects the author's own tests
  were structurally unable to see, and broke six claims the change made about itself.**
  Same two-lens stance split as #168, same unconditional trigger, and worth recording
  separately because *what* it caught was a different class.

  The three defects shared one root: **a tile's store has a history, and the history
  was not modelled.** The layout guard read the current region's extrapolate flag
  rather than the layout the store was written at — and region flags are
  per-`WBT_REGION`, so a first pass in one region followed by an upgrade in another
  slipped through exactly the silent mismatch the guard existed to refuse. A first
  pass that failed at its second component left one component from this pass and two
  from the last, which a later upgrade then refined and returned `Ok(())`. And nothing
  anywhere asserted that an upgrade pass *changes* a coefficient: deleting the
  refinement entirely left the whole corpus gate green.

  The refuting lens then broke the claim that had **justified a decision**. The store's
  key had been argued as a resource question — both keys decode the corpus, so the
  difference was said to be memory. The evidence offered was a count of "non-black"
  tiles, which cannot see a pixel change at all, because the colour step writes
  `alpha = 255` unconditionally. Hashing the tiles showed the two keyings *paint
  differently*, and the mechanism was measurable in the corpus: 1405 of 2943 first
  passes carry `RFX_TILE_DIFFERENCE`, which adds to whatever store is held for that
  grid position. It was a correctness question, and the test had asserted the opposite.

  Two rules earned here. **A test's discriminating power has to be asserted in the same
  run as the thing it asserts** — three of this slice's tests passed against wrong
  implementations because a later stage (a clamp, a constant alpha, a private helper
  standing in for its caller) destroyed the difference before the assertion saw it.
  Promoted to [`a later stage can hide an earlier
  defect`](../map/invariant/a-later-stage-can-hide-an-earlier-defect.md). And **check
  that a mutation landed before believing it survived**: a "surviving" mutant in the
  first sweep turned out to be a `replace(…, 1)` that hit a doc comment rather than the
  code, and a timed-out sweep left a live mutation in the tree that the next sweep then
  took as its baseline. A mutation harness needs the same trust gate as a test.

  Also: **twelve FreeRDP line citations were off by 1–15 lines.** #168's whole lesson
  was that a cited range can hold the algorithm and not its initial state; this slice
  re-learned the cheaper half, that a range can simply be wrong. Grepping each cited
  symbol for its line number cost minutes and is now the only way these are written.

- **The measurement was right and the inference was wrong, and only an A/B could tell
  them apart (#203).** `gcc` and `mcs` were the two parsers #200 could not add a target
  to. Two of #203's own statements were checked rather than inherited, and they came out
  opposite ways — which is the point of the entry, because they *felt* equally solid.

  - **Its shape premise was false, and the call graph said so for free.** "Nine `gcc`
    entry points, no single top-level `decode`" is a true count and a misleading shape:
    they are two trees with one root each, and `ClientGccBlocks::decode` — four of the
    nine — has no caller outside the crate's own tests and parses bytes no server sends.
    The decision was never 14 targets versus one selector; it was reachability. Reading
    the entry points is what #200 already had to do to get its own census right, and it
    is cheap enough that not doing it has no excuse.
  - **Its seeding prediction was true, including the half it had left unmeasured — and
    this work claimed the opposite first.** 200k undirected inputs reach **11.98%** of
    `gcc.rs`'s regions, every per-block decoder dark behind a ~12-byte magic prefix.
    That reads exactly like `rfx::progressive`'s 8.9% wall, and it was taken as proof a
    seed corpus was mandatory. The lane disagreed: **empty `cov: 515` against seeded
    `cov: 699`**, nothing like progressive's 62-versus-425 collapse.
  - **Why they diverge, which is the reusable half.** A comparison against a byte string
    feeds libFuzzer's auto-dictionary (`__sanitizer_cov_trace_cmp`); random sampling has
    no equivalent. So **magic constants are climbable and self-consistent nested lengths
    are not**, and `progressive` needed its seed for the second reason. `fuzz.yml`'s own
    header says "magic-plus-nested-lengths"; the load-bearing half is the nesting.
  - **The undirected number still governs — the other automation.** proptest samples the
    same way libFuzzer does not, so 11.98% is why `gcc` carries nine per-entry-point
    properties rather than one on the root. ADR-0008 pairs two automations and this is
    the first time they were measured *against each other* here rather than assumed to
    agree. The #219 entry above showed they are not redundant; this shows a number from
    one of them does not transfer to the other.
  - **The arm layout was settled by mutation, not by the percentage.** An out-of-bounds
    read injected into `ServerNetworkData::decode` turns that parser's own property red
    while `server_gcc_blocks_…`, which *calls* it, stays green — random bytes never hit
    the exact `u16` block type. A property driving only the root passes over the defect,
    which is the same "covers the line, misses the case" shape as #219's entry.
  - **Two real-byte sweeps, and only one of them discriminates.** The captured
    Connect-Response is truncated at all 101 offsets and bit-flipped in all 496
    positions. The injected defect turns the **corruption** sweep red and leaves the
    **truncation** sweep green: truncation always fails in an outer parser first
    (`read_block` wants `block_len >= 4` and then a `read_slice` a clipped buffer cannot
    satisfy), while a flipped byte can set that same length *to* 4. Kept as two sweeps
    for that reason rather than merged.
  - **A round-trip cannot reach a decoder whose encoder does not exist.** Every encoder
    in `justrdp-pdu` writes client-to-server, because justrdp is a client — so the seed
    had to be captured off the VM, and no amount of test-writing substitutes. It is also
    why #98 gave `decode_connect_response` a no-panic property and no round-trip.
  - **The derivations match by name, and a name can be taken by a covered sibling in
    another crate.** `pointer` and `rfx` appear in both of the invariant's lists.
    `rfx` is genuinely covered (the codec calls the PDU parser); `pointer` is not —
    `justrdp_codecs::pointer::decode_pointer` takes dimensions and masks *already
    parsed*, so the `TS_POINTERATTRIBUTE` header parse is driven by nothing while
    sitting on the live session path. Filed as #230. Same shape as #200's stale count
    one level up: the roster answers *"is there a file called X"*, the question is
    *"is this function driven"*.
  - **#230 then found the same defect with no cross-crate tell, and it was the bigger
    one.** `license` sits in one crate, in one module, with no twin to be suspicious of
    — and four of its five live-path parsers had neither artifact, because the target
    and the property both name `ServerLicenseRequest::decode`, which calls none of
    `LicensePreamble` / `LicenseError` / `PlatformChallenge` / `NewLicense`. **ADR-0008
    itself carried the claim** (*"the `fuzz/` lane carries libFuzzer targets for the same
    entry points"*), which is what a false status report looks like when it reaches the
    decision trail. Two readings worth keeping. **A same-name match across crates is
    conspicuous and a same-name match inside one module is not**, so the cross-crate case
    is the easy half of this family, not the representative one. And the fix is a
    mechanical cross-reference rather than more care: list the `pub fn`s in
    `justrdp-pdu` that `crates/justrdp/src` names, check each **by function** against the
    properties and the targets. Run once, that census also surfaced `finalization`
    (`Synchronize` / `Control` / `FontMap`), which no roster and no known-holes list had
    ever mentioned.
  - **A piped gate cannot fail, and it was reproduced while checking a retraction.**
    `cargo clippy … | tail -2; echo "GATE: $?"` printed `0` over a real compile error,
    because the exit status is `tail`'s. The gate matrix already says *run each gate
    bare*; knowing the rule did not help, running it did.

## Step 6/7 — surfaces & gates

- **The `fuzz` crate is the `--workspace` blind spot** — out of the workspace by
  design (its own `[workspace]`), so `cargo test --workspace` does not build it. A
  public-API change needs a separate `cargo check --manifest-path fuzz/Cargo.toml`.
- **A gate that keeps a *memory* of its own verification is the same failure one
  level up (#224).** `supply-chain-and-gates.md` recorded that the map gate *"was
  verified to pass on known-good notes, fail on each of five defect kinds, and ignore
  link-shaped text inside code spans"*. True when written, unrepeatable, and by the time
  anyone re-read it one of the five had **silently weakened**: the symbol check searched
  the whole tree rather than the file the bullet named, so a note could claim a symbol at
  a path it had moved out of and pass. That is exactly what #221 did with `Progressive`
  and `ProgressiveTile`, and the gate said `0 failing`. The fix is the same shape as the
  entry below — make the claim a command, not prose: `check_map.py --selftest` builds a
  throwaway mini-map, breaks one thing at a time, and requires the gate to notice each of
  eight defect kinds plus a clean baseline.

  Three things this pins that the #200 entry could not.

  - **"Verified once" and "not verified" are indistinguishable from the outside**, and
    the artifact that records the verification is written by the person least likely to
    re-run it. A sentence in a note is a test with no runner.
  - **A baseline case is a failure direction, not ceremony.** Of five mutations run
    against the fix, **two** were caught only by "a known-good map still passes clean" —
    breaking the directory walk and dropping `.rs` from the readable extensions both make
    *valid* notes fail. The territory's own principle says why that matters more than it
    looks: a gate with false positives gets ignored, and an ignored gate returns its
    defect class to being silent.
  - **A test case that never goes red under any mutation is not a case.** The first
    directory-scope case named a symbol that existed nowhere, so it was a duplicate of
    "symbol not in the tree" and survived every mutation green. Rewriting it to name a
    symbol that exists **outside** the named directory is what gave it the one thing it
    was for: separating *scoped* from *scoped correctly*.

- **Precision made the gate nine times cheaper, which is the opposite of the assumption
  (#224).** Scoping each symbol search to its bullet's own files took the map gate from
  **1.885s to 0.215s** per run — measured interleaved (after, before, after) because the
  first reading was taken in order and could have been warm-cache noise. The cause is
  arithmetic rather than cleverness: ~295 `re.search` calls over a multi-megabyte
  concatenation of every source file became ~295 searches over a few KB each. Worth
  keeping because the instinct runs the other way — "check more precisely" reads as
  "check more" — and that instinct is what makes a gate stay coarse.

- **A gate that keeps its own copy of a list is a gate that will one day run on the
  wrong list — the war story for *derive, don't copy*, applied to CI (#200).**
  `fuzz.yml`'s matrix transcribed `ls fuzz/fuzz_targets/` by hand and drifted **twice
  without a signal**: `nscodec` (#143) and `progressive` (#192) each landed a
  compiling fuzz target that CI never once executed, `nscodec` for months. Nothing
  was violated — both PRs satisfied the recurrence test in
  [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md)
  exactly as it was written, because it named the artifact and not the thing that
  consumes it. Three lessons, and the second is the one that shaped the fix:
  **a rule is only as strong as its most literal reading**; **the roster had five
  copies, not two** — the directory, `fuzz/Cargo.toml`'s `[[bin]]` entries, the
  matrix, and a *count* in prose in two more places, both of which had also gone
  stale at #192, so a hand-kept number is a hand-kept list with one entry; and
  **derive from the copy whose failure is loud** — the matrix now reads the directory
  and asserts the manifest agrees, because a `.rs` with no `[[bin]]` is compiled by
  nothing, not even `cargo check --manifest-path fuzz/Cargo.toml`, and so reads as
  covered while being dead text.
- **"Temporary and tracked" decayed into "still here and untracked" — the war story
  for *external facts are verification targets too*.** The `[patch.crates-io]` bridge
  to `kihyun1998/sspi-rs` waited on Devolutions/sspi-rs#689, which **merged 2026-06-17
  and shipped in `sspi` 0.21.1 on 2026-06-26** — and it was still in the tree six weeks
  later. #61, named as the removal tracker by `Cargo.toml`, `.github/dependabot.yml`
  *and* ADR-0004, was **closed** against its own comment saying it must not be; the
  Dependabot "tripwire" could not fire because its condition was already met; and
  ADR-0004's own amendment asserted the bridge *did not exist*, so nothing greppable
  contradicted any of it. **Removed 2026-08-10** (`sspi = "=0.21.3"`, exact pin per the
  ADR), with the loopback full-CredSSP test green on the published crate — the real-VM
  gate deferred because the VM's credentials fail, which an A/B run proved is not a
  client regression. Two lessons: *"remove when X ships"* is a **status** claim that
  rots the moment it comes true, and a record asserting the **absence** of something is
  the hardest drift to notice (ADR-0004 Amendment 2026-08-10; memory
  `sspi_rs_contribution_setup`).
- **Supply-chain is a gate** — `just-shield` scans for SHA-pinned actions (ADR-0006,
  `supply-chain.yml`; memory `justrdp_ci_policy`).
- **No `Co-Authored-By` / AI-attribution** in commits (memory
  `feedback_no_ai_attribution_external`); label every new issue triage + type on
  creation (memory `feedback_label_issues_on_creation`).
