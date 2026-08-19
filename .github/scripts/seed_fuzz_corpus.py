#!/usr/bin/env python3
"""Seed a fuzz target's corpus from a test fixture the repo already commits (#200).

    python3 .github/scripts/seed_fuzz_corpus.py <target>

Exits 0 having done nothing when the target has no seeder — most do not need one.

## Why any of this exists

A target with no corpus starts from an empty input and mutates. Whether that bootstraps
depends entirely on the input grammar, and it is not a judgement call — it was measured on
the run that first executed both of the lane's newest targets, same 300s budget, both
genuinely cold:

    nscodec       #57,174,947   cov: 125   corp: 85/9477b
    progressive  #148,786,349   cov:  62   corp: 6/29b

`progressive` ran 2.6x more executions for half the coverage and retained **29 bytes**,
with coverage flat from the 8M mark: guidance never assembled a valid block header, so the
three-deep length nesting the target exists for was never reached. A magic-plus-nested-
lengths format is a wall a mutator cannot climb from empty; a flatter one is not.

Seeding it closed exactly that gap, on the next run of the same target at the same budget:

    empty    #148,786,349   cov:  62   ft:   64   corp: 6/29b       exec/s: 494,306
    seeded   #  8,277,846   cov: 425   ft: 1713   corp: 198/1153Kb  exec/s:  27,501

6.9x the coverage in 18x fewer executions, and the exec/s collapse is the tell: the target
is now decoding rather than bouncing off a length check.

## Why derived rather than committed

The payloads are already in the repo, as `justrdp-codecs`'s Progressive corpus fixture.
Committing a second copy under `fuzz/corpus/` would be ~900 KB of duplicate bytes and a
sixth hand-kept roster of exactly the kind #200 exists to remove — the two would drift the
first time the fixture is recaptured. This reads the fixture at run time instead, so there
is one copy and the seeds cannot disagree with it.

Seeding is additive and idempotent: it writes fixed filenames beside whatever the corpus
cache restored, so a re-run neither duplicates nor discards the inputs libFuzzer evolved.

Printed output is ASCII-only on purpose. The CI runner is UTF-8, but the maintainer's host
console is cp949, where a single em dash in a status line raises `UnicodeEncodeError` and
takes the script with it -- measured, not guessed, on the first local run of this file.
"""

USAGE = "usage: python3 .github/scripts/seed_fuzz_corpus.py <target>"

import pathlib
import struct
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]


def seed_progressive(out_dir):
    """Split the real-VM `WireToSurface2` capture into one file per payload.

    Format is documented in the fixture's README: `u32 count`, then `count` records of
    `u32 codec_context_id, u16 width, u16 height, u32 len, u8 payload[len]`. Only the
    payload is a fuzz input — the target takes the raw block stream, and the context id and
    surface dimensions are the decoder state it was captured against.
    """
    fixture = REPO / "crates/justrdp-codecs/tests/fixtures/progressive/replay.bin"
    if not fixture.is_file():
        print(f"::error::seed fixture missing: {fixture.relative_to(REPO)}")
        return None

    buf = fixture.read_bytes()
    (count,) = struct.unpack_from("<I", buf, 0)
    pos = 4
    written = 0
    for i in range(count):
        _ctx, _w, _h, length = struct.unpack_from("<IHHI", buf, pos)
        pos += 12
        (out_dir / f"replay-{i:03d}.bin").write_bytes(buf[pos : pos + length])
        pos += length
        written += 1
    return written


def seed_progressive_assembly(out_dir):
    """Wrap the same capture in the assembly target's header, one seed per payload plus a few
    multi-payload runs.

    The target reads its own byte layout rather than deriving `Arbitrary` precisely so this
    function can exist -- the layout is declared in `fuzz_targets/progressive_assembly.rs` and
    this is its only other appearance:

        u16 width | u16 height | u8 flags | (u32 len, payload)*

    The dimensions written are the *real* ones the capture was taken against, which is the whole
    reason the target clamps rather than takes a modulo: a bound small enough to look prudent
    would put these seeds outside their own tile grid, and every tile would come back
    `TileOutsideSurface`. A seed that decodes nothing is worse than no seed, because it looks
    like coverage.

    The multi-payload runs are the point of this target over `progressive`: a first pass and the
    upgrades that refine it, against one live store, is the composition no single payload
    reaches. Consecutive payloads are used because the capture is in arrival order.
    """
    fixture = REPO / "crates/justrdp-codecs/tests/fixtures/progressive/replay.bin"
    if not fixture.is_file():
        print(f"::error::seed fixture missing: {fixture.relative_to(REPO)}")
        return None

    buf = fixture.read_bytes()
    (count,) = struct.unpack_from("<I", buf, 0)
    pos = 4
    payloads = []
    dims = None
    for _ in range(count):
        _ctx, w, h, length = struct.unpack_from("<IHHI", buf, pos)
        pos += 12
        payloads.append(buf[pos : pos + length])
        pos += length
        if dims is None:
            dims = (w, h)

    header = struct.pack("<HHB", dims[0], dims[1], 0)

    def record(chunks):
        out = bytearray(header)
        for c in chunks:
            out += struct.pack("<I", len(c))
            out += c
        return bytes(out)

    written = 0
    for i, payload in enumerate(payloads):
        (out_dir / f"single-{i:03d}.bin").write_bytes(record([payload]))
        written += 1
    # Runs of two and three, which is where the cross-payload store is exercised. Strided so the
    # set spans the session rather than clustering at its start.
    for n in (2, 3):
        for i in range(0, len(payloads) - n + 1, n):
            (out_dir / f"run{n}-{i:03d}.bin").write_bytes(record(payloads[i : i + n]))
            written += 1
    return written


SEEDERS = {
    "progressive": seed_progressive,
    "progressive_assembly": seed_progressive_assembly,
}


def main(argv):
    if len(argv) != 2:
        print(USAGE)
        return 2
    target = argv[1]

    seeder = SEEDERS.get(target)
    if seeder is None:
        print(f"no seeder for '{target}': starting from whatever the corpus cache holds")
        return 0

    out_dir = REPO / "fuzz/corpus" / target
    out_dir.mkdir(parents=True, exist_ok=True)
    before = len(list(out_dir.glob("*")))
    written = seeder(out_dir)
    if written is None:
        return 1
    after = len(list(out_dir.glob("*")))
    print(f"seeded '{target}': {written} payloads written, corpus {before} -> {after} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
