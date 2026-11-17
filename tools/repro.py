#!/usr/bin/env python3
"""Build twice and compare: the same sources must give the same disk.

  python3 tools/repro.py [N]      N builds (default 2), each file on the
                                  disk image hashed and compared

llvm-mos before upstream 742d554bf (2026-09-14, "Make zero page
allocation deterministic") placed zero-page variables in the order of
pointer-keyed maps, so a build's code depended on where malloc put
things: the same commit gave a different bank and client nearly every
time (REQUIREMENTS.md, the finding of 2026-11-17). This is the check that
the compiler in use has the fix. It exits 1 if any two builds differ.
"""
import hashlib, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import build as B                                            # noqa: E402

DISK = ROOT / "bin" / {"mega-gemini": "GEMINI.D81", "mega-irc": "IRC.D81"}[ROOT.name]


def disk_hashes(c1541):
    """{name: sha256} of every file on the disk image."""
    with tempfile.TemporaryDirectory() as d:
        subprocess.run([c1541, "-attach", str(DISK), "-extract"], cwd=d, capture_output=True, check=True)
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()[:16] for p in sorted(Path(d).iterdir())}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    c1541 = B.find_tool("c1541", env="C1541")
    print(f"compiler: {subprocess.run([B.mos_clang(), '--version'], capture_output=True, text=True).stdout.splitlines()[0]}")
    runs = []
    for i in range(n):
        r = subprocess.run([sys.executable, str(ROOT / "build.py")], cwd=ROOT, capture_output=True, text=True)
        if r.returncode:
            sys.stdout.write(r.stdout[-2000:] + r.stderr[-2000:])
            print(f"build {i + 1} failed")
            return 2
        runs.append(disk_hashes(c1541))
        print(f"build {i + 1}: " + "  ".join(f"{k} {v[:8]}" for k, v in runs[-1].items()))
    bad = sorted({k for r in runs[1:] for k in set(r) | set(runs[0]) if r.get(k) != runs[0].get(k)})
    if bad:
        print(f"NOT reproducible: {', '.join(bad)} differ between builds")
        print("the compiler needs llvm-mos 742d554bf (zero page allocation made deterministic); see the finding of 2026-11-17")
        return 1
    print(f"reproducible: {n} builds, {len(runs[0])} files, identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
