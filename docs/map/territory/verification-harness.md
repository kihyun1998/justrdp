# Verification harness

## What it is

How this project knows it is right: a differential oracle against
`ironrdp-graphics` / `ironrdp` for codecs and crypto, a corpus of real Server 2022
captures for ClearCodec, property tests that assert decoders never panic, a nightly
libFuzzer lane, a coverage discovery job, and a real Windows Server 2022 VM for the
things only a server can prove. Verification is a territory because it is something
the system does — and because a claim about correctness here is load-bearing
everywhere else.

## Governing decisions

- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) — the oracle
  strategy and the phase-out condition.
- [ADR-0007](../../adr/0007-stage-boundary-codec-verification.md) — stage-boundary
  verification where no assembled oracle exists; the #118 amendment adds
  assembly-layer independence.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — proptest on
  stable in the PR gate, coverage-guided fuzzing on a nightly CI lane.

## Design model

- **Byte-identical output or it is not proof** (codecs). A visual check or a demo is
  a smoke test.
- **The corpus encodes tolerances that no spec states** — `clearcodec_corpus`
  fixtures are real Server 2022 streams, and the divergences from FreeRDP they force
  are requirements, not bugs (#127).
- **The oracle is scaffolding with a retirement condition, not a standing gate**
  (ADR-0011). A codec's oracle dev-dependency drops once its correctness rests on an
  owned basis: a real-server corpus plus expectations derived independently of our
  implementation. Progressive is the worked example (#194) — there the oracle decodes
  **2 of 52** real payloads, so a green diff against it would measure nothing.
- **An owned basis has two halves, and a corpus is only one of them.** A capture proves
  *acceptance* — that nothing a real server sends is rejected. It cannot prove *values*
  without independently-derived expectations, because the pixels a stream should produce
  are the very thing in question. `progressive_srl_freerdp.rs` is the second half:
  hand-computed from FreeRDP with its bit-level derivation written out.
- **Robustness is a property, not a vector**: "decode never panics on arbitrary
  bytes" covers an input space hand-written vectors cannot reach.
- **The VM proves what only a server can** — the full connect sequence, licensing's
  "error means proceed", the graphics caps a real host advertises.
- **Coverage is a discovery tool with no threshold**, scoped to the sans-IO core;
  the adapter is excluded because its tests need the VM.

## Code

- `justrdp-codecs/tests/` — `differential_ironrdp_graphics.rs`,
  `differential_rfx.rs`, `differential_pointer_ironrdp.rs`, `differential_zgfx.rs`,
  `clearcodec_corpus.rs`, `progressive_corpus.rs`, `progressive_srl_freerdp.rs`,
  `fixtures/`
- `justrdp-pdu/tests/` — `differential_ironrdp.rs`, `differential_activation.rs`,
  `real_server_connect.rs`, `fixtures/connect/`
- `justrdp/tests/` — `differential_input_ironrdp.rs`,
  `differential_license_crypto.rs`
- `fuzz/fuzz_targets/` — **not enumerated here on purpose**; the list below is the
  derivation and this file kept a copy of it that was already four targets stale by #200
  and would have gone stale again with #189's `zgfx.rs`
- `justrdp-tokio/src/lib.rs` — the `#[ignore]`d VM tests and the loopback CredSSP
  test
- Target list derivation: `ls fuzz/fuzz_targets/` — and since #200 this is not just how
  a reader derives it but how `.github/workflows/fuzz.yml` builds its matrix, so the
  roster has one home

## Reference behaviour

**None.** No verified external-fact store — which is a pointed absence *here*: the
oracle compares behaviour at test time and records nothing, so a divergence
adjudicated once (say, in #127) leaves no citable artifact behind, only a fixture.

## Cross-cutting invariants

- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
  — the limit on what this harness can prove.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  the property this harness automates.
- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
  — the class x64 CI structurally cannot observe.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — a corpus is evidence about a server *and* a client config, never the server alone.
- [A later stage can hide an earlier defect](../invariant/a-later-stage-can-hide-an-earlier-defect.md)

## Blast radius

- [Bitmap codecs](bitmap-codecs.md) — every correctness claim there routes through
  here.
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — the phase-2 rewrite's exit
  criterion is an oracle pass.
- [Licensing](licensing.md) — the differential crypto test is its only proof.
- [Supply chain & gates](supply-chain-and-gates.md) — which of these run in CI, and
  which are nightly-only or VM-only.
- [Adapter drive loop](adapter-drive-loop.md) — hosts the VM and loopback tests.

## Known holes / open

- **Fuzz coverage was codec-shaped and is now parser-shaped.** #200 gave the
  connect-sequence framing layer targets and no-panic properties and #203 added `gcc` and
  `mcs`, so the connect sequence is covered end to end. The enumeration of what is left is
  **owned by** [untrusted decode never panics](../invariant/untrusted-decode-never-panics.md),
  which carries the two commands that derive both lists — deliberately not copied
  here, because a second hand-kept list is what diverges. This bullet said "ten
  targets" until #200, having been written when that was true and left alone when
  `progressive` landed: a *count* is a hand-kept list with one entry, and it rots the
  same way.
- **The two derivations match by name, and #203 found a name that lies — then #230 found the
  form with no tell.** `pointer` and `rfx` appear in both lists, so both read as covered; both
  targets drive `justrdp-codecs`, and the identically-named `justrdp-pdu` modules are different
  code. `rfx` is covered anyway (the codec calls the PDU parser), `pointer` is not —
  `decode_pointer` takes dimensions and masks already parsed, so the `TS_POINTERATTRIBUTE` header
  parse behind them is driven by nothing. Same shape as the count above one level up: the roster
  answers *"is there a file called X"* and the question is *"is this function driven"*.
  **`license` is the harder case, and it is the one to remember**: same crate, same module, no
  twin to be suspicious of, and four of its five live-path parsers had neither artifact because
  the target and the property both named `ServerLicenseRequest::decode`, which calls none of
  them. #230 closed `pointer`, `client_info` and `license`; the enumeration and the mechanical
  cross-reference that finds the next one are
  **owned by** [untrusted decode never panics](../invariant/untrusted-decode-never-panics.md),
  not copied here.
- **A capture is a seed only if something else reads it.** #203's Connect-Response fixture is
  the `gcc`/`mcs` seed corpus *and* is asserted by `justrdp-pdu/tests/real_server_connect.rs` in
  the stable gate, because the lane that consumes it is nightly and would report a stale fixture
  as a corpus that merely decodes badly — indistinguishable from one doing its job. It is also
  the first server-to-client connect bytes in the repo that no encoder of ours produced, which
  is what makes it an acceptance proof rather than a round-trip.
- **"Undirected bytes barely reach it" is not "the fuzz lane barely reaches it", and #203 spent an
  A/B learning the difference.** `gcc.rs` takes 11.98% of its regions from 200k random inputs and
  **515 `cov:` from an empty corpus on the lane** — coverage guidance climbs a magic prefix on its
  own, because a comparison against a byte string feeds libFuzzer's auto-dictionary. The seed is
  still worth its capture (699 vs 515 `cov:`, 1987 vs 1207 `ft:`, in 4x fewer executions) but it
  is an improvement, not a rescue. `progressive`'s wall was **nested lengths that must agree**,
  which no dictionary can synthesise, and that is the distinction to test before predicting a wall
  from a coverage percentage. The derivation to run is the A/B on the lane, not the local
  llvm-cov number: the second one measures proptest's reach, which is a different automation.
- **"The target runs" and "the target covers anything" are separate claims, and for one
  format the gap was total.** `fuzz/corpus/` is not committed — corpora live as Actions
  cache entries — so a new target starts from nothing. Measured across two runs of the
  same target at the same 300s budget (#200): from empty, `progressive` ended
  `cov: 62 corp: 6/29b` after **149M executions** with coverage flat from the 8M mark,
  never having assembled a valid block header; seeded from the real-VM capture it ended
  `cov: 425 corp: 198/1153Kb` in **8M** executions. `nscodec`, cold in the same first run,
  reached `corp: 85/9477b` — so the wall is the input grammar (magic plus nested lengths),
  not cold starts as such. The lane now seeds from committed fixtures where one exists,
  which is a **derivation, not a second corpus**: `.github/scripts/seed_fuzz_corpus.py`
  splits the fixture at run time rather than duplicating ~900 KB into `fuzz/`.
- **One VM is one server.** The WS2022 box advertises a fixed cap set; paths it does
  not advertise have never been exercised against anything.
- **A test can pass on pixels another test's session painted, and only a working teardown
  exposes it.** `progressive_assembles`' live-framebuffer floor (≥ 1/8 of the screen
  non-black) asserts that the client paints a desktop over a WireToSurface2 path. That test
  connects with `connectionType = MODEM`, which it needs — LAN gives the server bandwidth to
  spare and it sends `TILE_FIRST` at `quality = 0xFF` with **zero** upgrade passes, so half
  the codec goes unexercised. But MODEM also makes the server strip the wallpaper, and
  `performanceFlags = 0` does **not** override it (measured: MODEM+0 → 10 322 lit,
  LAN+0 → 1 023 477, MODEM+0x7 → 11 574). A MODEM desktop is icons, taskbar and clock on
  black — about 7 400 lit — so the floor is unreachable by construction.
  It nevertheless passed for a long time, on **borrowed pixels**: while teardown was
  unreliable the session survived between tests, so this one reattached to a desktop another
  test's session had already painted with a wallpaper. #198 made teardown reliable, every
  test now gets a fresh logon, and the borrowing stopped. The finding is the shape, not the
  number: **a correctness proof was resting on another test's leftovers, and the thing that
  revealed it was fixing the isolation.**
- **The suite has a named VM-configuration dependency, and it is not in the repo.** The
  teardown signs out through the Windows UI, and Server 2022 answers a sign-out with the
  **Shutdown Event Tracker** — a dialog whose description field is *mandatory*, so its OK
  button stays disabled and no blind keystroke clears it. It is raised on the **next
  logon**, not at the shutdown, so a single occurrence poisons every later test exactly the
  way #182's leftover window did. Any VM this suite drives needs the policy off:
  `ShutdownReason` ("Display Shutdown Event Tracker"), key
  `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability`, value `ShutdownReasonOn` = 0
  — verified against `C:\Windows\PolicyDefinitions\Reliability.admx` rather than inferred
  from a support article, which gives only the Group Policy path.
  This is the honest shape of the fix and worth stating as such: it is **not** a guard the
  harness can hold. #198 tabulated four blocking modals, this work found a fifth, and each
  fix revealed the next — which is the signal that the set is not enumerable from inside a
  client driving a UI it does not own. The alternative that *is* enumerable is out-of-band
  (WinRM), and it was declined because it moves the configuration burden onto every machine
  that runs the suite instead of onto the one VM.
- **Driving a desktop by synthesised keystrokes is open-loop, and the acknowledgement
  the harness needs is the one it already receives.** Every VM test that has to make
  something happen *inside* Windows — sign out, launch an app, run `tsdiscon` — types
  into whatever happens to be on screen and finds out much later that it was not what it
  assumed (#198). We are the RDP client, so the screen answers: a Start click that opened
  the menu repaints, one that landed on a shell still loading does not. `start_menu_run`
  waits for that repaint and re-clicks, and its three frame counts *are* the assertions
  the input test makes — the check that keeps the step reliable and the check that makes
  the test meaningful are one measurement rather than two that can drift apart. The
  specific shape it cost: **"the frame count stopped changing" is trivially true of
  `0 == 0`**, so a settle loop written without a `> 0` guard falls through *before the
  first frame arrives*; three of five copies had the guard, and the two that did not
  included the one test #197 measured red.
- **Closing a loop on the wrong edge is its own defect, and the first closed-loop
  version of `start_menu_run` had it.** *"Something drew"* answers **it started**; the
  step needs **it finished**. Typing on the first frame of the opening Start menu loses
  the leading character — measured, the search box read `hutdown /l /f`, Windows
  answered "no results", the command never ran, and the only evidence was the PPM. Every
  typed step now waits for the repaint to *quiesce*, and so does the Enter that commits
  whichever result is highlighted. The blind `sleep(2s)` that preceded all this happened
  to cover exactly this case and missed the cold logon: **a fixed sleep is not wrong
  about everything, it is unfalsifiable**, and that is the argument for quiescence rather
  than for a longer sleep.
- **One dump path is one dump.** The teardown wrote every timeout to
  `%TEMP%\justrdp-vm-teardown-timeout.ppm`, so a run with three failures kept only the
  **last** screenshot — and the first is the root cause while the others are its
  dominoes. The name now carries the test's thread name. #182's whole lesson is that
  this image is the difference between one diagnosis and three investigations, and a
  fixed filename quietly converts a cascade back into three unrelated bugs.
- **Session isolation is fixed and the numbers that described it are dead** — kept here
  because the shape recurs, not as current state. Until #197 the suite shared one Windows
  session across all its tests and never tore it down, so each connect reattached to the
  previous test's *disconnected* session and windows accumulated:
  `keyboard_and_mouse_input_drive_the_real_vm` left Notepad open,
  `logoff_inside_the_session_yields_the_typed_reason` then stalled on Windows' *"close N
  apps and sign out"* confirmation — **N tracked the number of input tests that had run
  before it** — and that modal swallowed every later test's input, so one leftover window
  read as three or four independent bugs and the failing set moved between runs. #197 gave
  the suite `with_vm_session`, which owns the VM address, the credentials and the
  serialisation lock and signs the session out afterwards *even when the body panicked*.
  The suite no longer needs `--test-threads=1`, and **15 of 15 pass in parallel** (measured
  2026-08-19; PLACEHOLDER_RUNS). Most of that run is teardown: a single-test run
  (`connect_reaches_session_active_against_real_vm`, whose body is a connect and three
  assertions) measures **28.8 s end to end**, so the sign-out is ~26 s of it — and it runs
  after *every* test, including the twelve that dirty nothing. That is the price of #182's
  actual lesson, which is that "whichever test makes a mess cleans it up" is the property
  that failed.
- **A vendor document read correctly off its primary source still lost to a
  measurement (#198).** The teardown types `shutdown /l /f`, and Microsoft's reference
  states verbatim that `/l` *"works independently and can't be combined with any other
  parameters. Attempts to combine /l with any other parameter is ignored."* #198 was
  filed on that sentence — the flag is dead text, so the comment crediting it with
  forcing applications closed must be false. **It is not.** A/B against this VM, same
  test, same clean starting session, one variable:

  | command | slice-7 leaving Notepad holding `aaa` (what it did at the time) |
  |---|---|
  | `shutdown /l /f` | teardown signs out, 63 s |
  | `shutdown /l` | teardown **blocked** on Notepad's *"save changes?"* prompt, 150 s |

  The full-suite runs agree at the other scale: 15/15 with the flag, and a failure at
  exactly that test without it. So the `/f` force-closes an application holding unsaved
  work before it can veto the sign-out. Same discipline as [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)
  one layer out — **for what a real system does, the real system is the authority** — and
  the reason it is knowable at all is the PPM the teardown dumps on timeout: it showed
  Notepad's *own* save dialog, not the *"close N apps and sign out"* screen #182 had
  trained everyone to expect. Two different modals, two different causes, and only the
  screenshot tells them apart.

  **The obvious alternative was tried and the VM priced it.** #198 briefly removed the
  veto instead of forcing past it — slice-7 launching a console and closing it with `exit`,
  so nothing in the suite would hold unsaved work at all. It cost an assertion nothing else
  can make: a console's client area carries the **same arrow as the desktop**, so the
  server never pushes a *decoded* pointer shape and slice-7's `shapes >= 1` (issue #41) saw
  60 cursor events without a single `Set`. The I-beam over Notepad's edit area is the only
  surface in this suite that produces one. So the unsaved buffer stays and the `/f` handles
  it, which also keeps the A/B above reproducible from the suite as it stands.
  Worth keeping as a shape: **"remove the hazard" and "handle the hazard" are not
  interchangeable when the hazard is also carrying a proof.** The console looked strictly
  safer right up to the point where a real server was asked.
- ~~**32-bit guards need an i686 run** that no CI job performs.~~ **Closed** —
  `.github/workflows/overflow-32bit.yml` builds `justrdp-codecs` + `justrdp` for
  `i686-pc-windows-msvc`, so the class closed in #151/#155 is now gated rather than
  remembered. The residue is local, not CI: a rustup target is per-toolchain, so after every
  toolchain bump the local run needs its own `rustup target add` (it silently stopped working
  a day after ADR-0013's pin landed).
- No captured-stream replay harness exists for the connect sequence: a VM run is the
  only end-to-end proof, and it is not reproducible offline. **Narrowed by #252**, which
  captured the finalization leg via `JUSTRDP_CONNECT_CAPTURE_FILE` and walks it offline
  through `tpkt` → `x224` → `mcs` → `share` → `finalization`. That is a PDU-level replay,
  not a state-machine one — the machine still never sees the bytes.
- **The census the no-panic obligation is derived from was scoped by crate until #241/#238,
  and both halves of it were blind in different ways.** `rg --files crates/justrdp-pdu/src`
  could not see a parser in the core (`tls::extract_subject_public_key`), and both commands
  were *byte*-scoped so neither could describe a consumption site at all. `justrdp` now carries
  `proptest` and a fuzz target for the first time, and the derivations live in
  [the invariant](../invariant/untrusted-decode-never-panics.md). What remains open is that
  derivation ③ is an **over-approximation adjudicated by hand** — it lists ~56 candidate
  `pub fn`s and the membership judgement is ADR-0012 §1's, so it bounds the work rather than
  deciding it.
