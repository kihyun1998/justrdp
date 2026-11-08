#!/usr/bin/env python3
"""Gate: `fuzz/fuzz_targets/*.rs` and the `[[bin]]` tables of `fuzz/Cargo.toml` agree.

Run from the repository root:

    python3 .github/scripts/check_fuzz_roster.py [--selftest]

The roster is the directory's top level. Each of these exits 1: a file with no `[[bin]]`, a
`[[bin]]` with no file, a `[[bin]]` whose `path` is not `fuzz_targets/<name>.rs`, and an empty
directory. When they agree it exits 0, and with `GITHUB_OUTPUT` set it writes
`matrix=<JSON list of target names>`, which `fuzz.yml` feeds to its fuzz job.

`--selftest` builds a throwaway roster for each defect kind and requires this gate to notice.
Printed output is ASCII-only, as in `seed_fuzz_corpus.py`.
"""

import json
import os
import pathlib
import sys
import tomllib


def check():
    files = sorted(p.stem for p in pathlib.Path("fuzz/fuzz_targets").glob("*.rs"))
    with open("fuzz/Cargo.toml", "rb") as fh:
        bins = tomllib.load(fh).get("bin", [])
    declared = {b["name"] for b in bins}

    undeclared = [n for n in files if n not in declared]
    orphaned = sorted(declared - set(files))
    misplaced = [b for b in bins if b.get("path") != f"fuzz_targets/{b['name']}.rs"]
    for b in misplaced:
        print(f"::error::[[bin]] {b['name']} has path {b.get('path')}, and the fuzz lane runs it "
              f"by name, so it must be fuzz_targets/{b['name']}.rs")
    for n in undeclared:
        print(f"::error::fuzz_targets/{n}.rs has no [[bin]] entry in fuzz/Cargo.toml, so cargo "
              f"never builds it and it cannot be fuzzed")
    for n in orphaned:
        print(f"::error::fuzz/Cargo.toml declares [[bin]] {n} but fuzz_targets/{n}.rs is absent")
    if misplaced or undeclared or orphaned:
        return 1
    if not files:
        print("::error::fuzz/fuzz_targets/ is empty, so the matrix would be a silent no-op")
        return 1

    print(f"{len(files)} targets: {' '.join(files)}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write(f"matrix={json.dumps(files)}\n")
    return 0


_ST_CLEAN_MATRIX = 'matrix=["a", "b"]\n'


def _bin(name):
    return f'[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\n\n'


# (name, target files, other files, manifest, expected stdout fragment; None is a clean roster)
_ST_CASES = [
    ("clean roster passes and writes the matrix", ["a", "b"], ["README.md"], _bin("a") + _bin("b"), None),
    (
        "any TOML spelling of the entry passes",
        ["a", "b"],
        [],
        _bin("a") + "[[bin]]\n  name = 'b'\n  path = 'fuzz_targets/b.rs' # comment\n",
        None,
    ),
    ("a file with no [[bin]]", ["a", "b"], [], _bin("a"), "fuzz_targets/b.rs has no [[bin]] entry"),
    ("a [[bin]] with no file", ["a"], [], _bin("a") + _bin("b"), "declares [[bin]] b but"),
    (
        "a commented-out [[bin]] does not count",
        ["a", "b"],
        [],
        _bin("a") + '# [[bin]]\n# name = "b"\n# path = "fuzz_targets/b.rs"\n',
        "fuzz_targets/b.rs has no [[bin]] entry",
    ),
    (
        "another table's path does not count",
        ["a", "b"],
        [],
        _bin("a") + '[[example]]\nname = "b"\npath = "fuzz_targets/b.rs"\n',
        "fuzz_targets/b.rs has no [[bin]] entry",
    ),
    (
        "a [[bin]] name that is not its file stem",
        ["a", "b"],
        [],
        _bin("a") + '[[bin]]\nname = "other"\npath = "fuzz_targets/b.rs"\n',
        "[[bin]] other has path fuzz_targets/b.rs",
    ),
    (
        "two [[bin]] entries with each other's path",
        ["a", "b"],
        [],
        '[[bin]]\nname = "a"\npath = "fuzz_targets/b.rs"\n\n[[bin]]\nname = "b"\npath = "fuzz_targets/a.rs"\n',
        "[[bin]] a has path fuzz_targets/b.rs",
    ),
    ("an empty directory", [], [], "", "fuzz/fuzz_targets/ is empty"),
]


def selftest():
    import subprocess
    import tempfile

    failures = 0
    for name, targets, others, manifest, expect in _ST_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target_dir = root / "fuzz/fuzz_targets"
            target_dir.mkdir(parents=True)
            for target in targets:
                (target_dir / f"{target}.rs").write_text("", encoding="utf-8")
            for other in others:
                (target_dir / other).write_text("", encoding="utf-8")
            (root / "fuzz/Cargo.toml").write_text(manifest, encoding="utf-8")
            output = root / "github_output"
            output.write_text("", encoding="utf-8")

            run = subprocess.run(
                [sys.executable, os.path.abspath(__file__)],
                cwd=tmp,
                env={**os.environ, "GITHUB_OUTPUT": str(output)},
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
            written = output.read_text(encoding="utf-8")

        out = (run.stdout or "") + (run.stderr or "")
        if "Traceback" in out:
            ok = False
        elif expect is None:
            ok = run.returncode == 0 and "2 targets: a b" in out and written == _ST_CLEAN_MATRIX
        else:
            ok = run.returncode == 1 and "::error::" in out and expect in out and written == ""
        print(("ok   " if ok else "FAIL ") + name)
        if not ok:
            failures += 1
            for line in out.strip().splitlines():
                print(f"       {line}")
            print(f"       exit {run.returncode}, GITHUB_OUTPUT {written!r}")

    kinds = sum(1 for case in _ST_CASES if case[4] is not None)
    print(f"\nself-test: {kinds} defect kind(s) + {len(_ST_CASES) - kinds} clean, {failures} failing")
    return 1 if failures else 0


def main():
    if sys.argv[1:2] == ["--selftest"]:
        return selftest()
    return check()


if __name__ == "__main__":
    sys.exit(main())
