#!/usr/bin/env python3
"""Build driver for mega-gemini: Python, so that Windows, Linux and macOS
are all first-class development hosts.

    python3 build.py test       the host suites: gemtext and URLs, the crypto, the TLS client
    python3 build.py            the client and bin/GEMINI.D81
    python3 build.py certs      self-signed certificates for the test server (openssl)
    python3 build.py hostclient build/host/tls_host: fetch a Gemini URL on the host through src/tls
    python3 build.py bank       the TLS bank image (build/bank/crypto.bin) and its trampoline
    python3 build.py clean

It needs llvm-mos (mos-mega65-clang), CMake, c1541 from VICE, and the two
sibling checkouts ../mega-net and ../mega65-libc; it builds mega65-libc
and mega-net's image itself when they are missing. The tests need a host
C compiler (cc, clang or gcc).

Overrides: LLVM_MOS_DIR, MEGANET (path to the mega-net checkout),
LIBC_SRC, C1541, CC.
"""
import os, platform, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
BIN = ROOT / "bin"
IS_WINDOWS = platform.system() == "Windows"
MEGANET = Path(os.environ.get("MEGANET", ROOT.parent / "mega-net")).resolve()
LIBC_SRC = Path(os.environ.get("LIBC_SRC", ROOT.parent / "mega65-libc")).resolve()
LIBC_BUILD = BUILD / "libc"

HOST_CFLAGS = ["-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function"]


def die(msg):
    print(f"error: {msg}", file=sys.stderr); sys.exit(1)


def run(cmd, **kw):
    print("  " + " ".join(Path(c).name if os.sep in str(c) else str(c) for c in cmd))
    if subprocess.run([str(c) for c in cmd], **kw).returncode != 0:
        die("command failed")


def find_tool(exe, roots=(), env=None):
    if env and os.environ.get(env):
        return os.environ[env]
    name = exe + (".exe" if IS_WINDOWS else "")
    for r in roots:
        cand = Path(r) / "bin" / name
        if cand.is_file():
            return str(cand)
    found = shutil.which(name)
    if found:
        return found
    for cand in ("/opt/homebrew/bin/" + name, "/usr/local/bin/" + name):
        if Path(cand).is_file():
            return cand
    die(f"{exe} not found")


def host_cc():
    cc = os.environ.get("CC") or next((c for c in ("cc", "clang", "gcc") if shutil.which(c)), None)
    if not cc:
        die("no host C compiler (cc, clang or gcc); set CC")
    return cc


def host_test(name, sources, extra=()):
    out = BUILD / "host"; out.mkdir(parents=True, exist_ok=True)
    exe = out / (name + (".exe" if IS_WINDOWS else ""))
    run([host_cc()] + HOST_CFLAGS + list(extra) + ["-I", ROOT / "src"] + [str(s) for s in sources] + ["-o", exe])
    r = subprocess.run([str(exe)])
    return r.returncode


def crypto_sources():
    return sorted((ROOT / "src" / "crypto").glob("*.c"))


def build_test():
    print("gemtext and URLs:")
    rc = host_test("test_gemtext", [ROOT / "tests" / "test_gemtext.c", ROOT / "src" / "gemtext.c", ROOT / "src" / "url.c"])
    print("Gemini responses:")
    rc |= host_test("test_gemini", [ROOT / "tests" / "test_gemini.c", ROOT / "src" / "gemini.c"])
    print("crypto:")
    rc |= host_test("test_crypto", [ROOT / "tests" / "test_crypto.c"] + crypto_sources_host(), ["-I", ROOT / "src" / "crypto"])
    print("signatures:")
    rc |= host_test("test_sig", [ROOT / "tests" / "test_sig.c", ROOT / "src" / "tls" / "x509.c"] + crypto_sources_host(), ["-I", ROOT / "src" / "crypto"])
    print("TLS:")
    rc |= host_test("test_tls", [ROOT / "tests" / "test_tls.c"] + crypto_sources_host() + tls_sources(), ["-I", ROOT / "src" / "crypto"])
    return rc


def tls_sources():
    return sorted((ROOT / "src" / "tls").glob("*.c"))


def build_hostclient():
    """tests/tls_host.c: the TLS client over a socket, for fetching real pages on the host."""
    out = BUILD / "host"; out.mkdir(parents=True, exist_ok=True)
    exe = out / "tls_host"
    print("host client:")
    run([host_cc()] + HOST_CFLAGS + ["-I", ROOT / "src", "-I", ROOT / "src" / "crypto", ROOT / "tests" / "tls_host.c",
         ROOT / "src" / "url.c"] + crypto_sources_host() + tls_sources() + ["-o", exe])
    return 0


def mos_clang():
    roots = [os.environ["LLVM_MOS_DIR"]] if os.environ.get("LLVM_MOS_DIR") else []
    roots += [Path.home() / "llvm-mos", "/opt/llvm-mos", "/usr/local/llvm-mos"]
    return find_tool("mos-mega65-clang", roots)


def check_rmw(elf):
    """ssh REQUIREMENTS.md 5.6: the compiler once decremented the wrong
    zero-page word in a loop; tools/orphan_rmw.py finds that shape in a
    linked ELF."""
    if not elf.exists():
        return
    objdump = find_tool("llvm-objdump", [Path(mos_clang()).parent.parent])
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "orphan_rmw.py"), str(elf), objdump])
    if r.returncode:
        die(f"{elf.name}: the loop miscompile of ssh 5.6 is back; rewrite the loop it names")


def check_headroom(mapfile):
    """The soft stack grows down from $D000 into whatever the program leaves
    above its .noinit, and the linker never reserves any: a client whose
    data ended at $D059 booted into a crash with no message (5.6). At least
    1 KB is required here."""
    import re
    end = 0
    for line in mapfile.read_text().splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\d+\s+\.(bss|noinit|data)$", line)
        if m:
            end = max(end, int(m.group(1), 16) + int(m.group(2), 16))
    room = 0xD000 - end
    print(f"  data ends at ${end:04x}: {room} bytes for the soft stack")
    if room < 1024:
        die("less than 1 KB between the program's data and $D000: the boot will crash (5.6); find the bytes")


def emit_payload(gen, tramp, image, render):
    """build/gen/ck_payload.{c,h}: the trampoline as a C array, and the
    images' sizes, for the client's boot code."""
    gen.mkdir(parents=True, exist_ok=True)
    tb = tramp.read_bytes()
    (gen / "ck_payload.h").write_text(
        "/* generated by build.py: the TLS bank's trampoline and the images' sizes */\n"
        "#ifndef CK_PAYLOAD_H\n#define CK_PAYLOAD_H\n"
        f"#define CK_TRAMP_SIZE {len(tb)}\n#define CK_BIN_SIZE {image.stat().st_size}UL\n"
        f"#define CK_RENDER_SIZE {render.stat().st_size}UL\n"
        "extern const unsigned char ck_tramp_bin[CK_TRAMP_SIZE];\n#endif\n")
    body = ", ".join(f"0x{x:02x}" for x in tb)
    (gen / "ck_payload.c").write_text(f'#include "ck_payload.h"\nconst unsigned char ck_tramp_bin[CK_TRAMP_SIZE] = {{ {body} }};\n')


def bank_sources():
    """The crypto the bank carries: chacha20_small.c in place of the SSH client's
    unrolled chacha20.c (5.4); sha512.c stays only because curve25519.c holds
    Ed25519 too, and the linker drops what nothing calls."""
    return [p for p in crypto_sources() if p.name != "chacha20.c"] + \
           [ROOT / "src" / "tls" / "keys.c", ROOT / "src" / "tls" / "x509.c", ROOT / "src" / "crypto" / "mulacc_m65.S", ROOT / "src" / "crypto" / "mp32_m65.S", ROOT / "src" / "crypto" / "mp256_m65.S"]


def crypto_sources_host():
    return [p for p in crypto_sources() if p.name != "chacha20_small.c"]


def build_bank():
    """The TLS bank: a headerless image for bank 1 and its trampoline."""
    clang = mos_clang()
    out = BUILD / "bank"; out.mkdir(parents=True, exist_ok=True)
    gen = BUILD / "gen"
    bank = ROOT / "src" / "bank"
    warn = ["-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-DX509_NO_ED25519"]   # Ed25519 and its SHA-512: 15 KB no server needs
    if os.environ.get("CK_SELFTEST"):
        warn.append("-DCK_SELFTEST")                     # the P-256 self-test entry, for timing on the machine (5.6)
    tramp = out / "ck_tramp.bin"
    print("bank trampoline:")
    run([clang, "-nostartfiles", "-nostdlib", "-T", bank / "trampoline.ld", bank / "trampoline.S", "-o", tramp])
    hi_objs = []
    for src in (bank / "render.c", ROOT / "src" / "gemtext.c"):   # named in crypto.ld: compiled apart, without LTO
        obj = out / (src.stem + ".o")
        run([clang, "-std=c99", "-Oz", "-fno-lto", "-c", "-I", ROOT / "src", "-I", bank] + warn + [src, "-o", obj])
        hi_objs.append(obj)
    both = out / "bank.bin"
    print("bank image:")
    run([clang, "-std=c99", "-Oz", "-nostartfiles", "-T", bank / "crypto.ld", f"-Wl,-Map={out / 'crypto.map'}",
         "-I", ROOT / "src" / "crypto", "-I", ROOT / "src" / "tls", "-I", bank, "-I", ROOT / "src"] + warn +
        [bank / "jumptable.S", bank / "api.c", bank / "dma.c"] + hi_objs + bank_sources() + ["-o", both])
    data = both.read_bytes()
    RAM_LEN = 0x9E00
    if len(data) < RAM_LEN:
        die("the bank image is shorter than its first region; is OUTPUT_FORMAT FULL(ram)?")
    image = out / "crypto.bin"
    image.write_bytes(data[:RAM_LEN].rstrip(b"\0") or b"\0")
    render = out / "render.bin"
    render.write_bytes(data[RAM_LEN:].rstrip(b"\0") or b"\0")
    first = image.read_bytes()[0]
    print(f"  {image.name}: {image.stat().st_size} bytes, first byte ${first:02x} ({'jmp: ok' if first == 0x4c else 'NOT a jmp!'})")
    print(f"  {render.name}: {render.stat().st_size} bytes (the renderer, for $1E000)")
    if first != 0x4c:
        die("the jump table is not at the start of the image")
    check_rmw(both.with_suffix(".bin.elf"))
    emit_payload(gen, tramp, image, render)
    return image, render


def ensure_libc():
    lib = LIBC_BUILD / "src" / "libmega65libc.a"
    if lib.is_file():
        return lib
    if not LIBC_SRC.is_dir():
        die(f"mega65-libc not found at {LIBC_SRC}; set LIBC_SRC")
    print("building mega65-libc for llvm-mos:")
    prefix = Path(mos_clang()).parent.parent
    run(["cmake", f"-DCMAKE_PREFIX_PATH={prefix}", "-B", LIBC_BUILD, "-S", LIBC_SRC])
    run(["cmake", "--build", LIBC_BUILD])
    return lib


def ensure_meganet():
    image = MEGANET / "build" / "m65" / "meganet.bin"
    tramp = MEGANET / "build" / "gen" / "meganet_tramp.c"
    if not (image.is_file() and tramp.is_file()):
        if not MEGANET.is_dir():
            die(f"mega-net not found at {MEGANET}; set MEGANET")
        print("building mega-net:")
        run([sys.executable, "build.py", "abi"], cwd=MEGANET)
    return image, tramp


def build_client():
    """The client: the portable modules, the MEGA65 side, the platform, on the bank and mega-net."""
    clang = mos_clang(); lib = ensure_libc(); image, tramp = ensure_meganet()
    bank_image, render_image = build_bank()
    BIN.mkdir(exist_ok=True)
    gen = BUILD / "gen"
    srcs = sorted((ROOT / "src" / "m65").glob("*.c")) + [p for p in sorted((ROOT / "src" / "platform").glob("*.c")) if p.name != "m65_screen.c"] + \
           [ROOT / "src" / "url.c", ROOT / "src" / "gemini.c", ROOT / "src" / "tls" / "tls.c",
            gen / "ck_payload.c", tramp, MEGANET / "src" / "abi" / "meganet_vectors.c"]
    prg = BIN / "gemini.prg"
    print("client:")
    run([clang, "-Oz", "-I", LIBC_SRC / "include", "-I", MEGANET / "src" / "abi", "-I", MEGANET / "build" / "gen",
         "-I", ROOT / "src" / "platform", "-I", ROOT / "src", "-I", ROOT / "src" / "m65", "-I", gen,
         "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"] + (["-DCK_SELFTEST"] if os.environ.get("CK_SELFTEST") else []) +   # the 't' and 'g' keys with the bank's self-test
        srcs + [lib, f"-Wl,-Map={BIN / 'gemini.map'}", "-o", prg])
    print(f"  {prg.name}: {prg.stat().st_size} bytes")
    check_rmw(prg.with_suffix(".prg.elf"))
    check_headroom(BIN / "gemini.map")
    c1541 = find_tool("c1541", env="C1541")
    d81 = BIN / "GEMINI.D81"
    shutil.copy(image, BIN / "meganet")
    shutil.copy(bank_image, BIN / "crypto")
    shutil.copy(render_image, BIN / "render")
    if d81.exists():
        d81.unlink()
    # the client first: shift-RUN/STOP runs the first program on the disk, as on the other clients' disks (5.17);
    # the images follow (5.6 wrote them first for stable sectors while the bank was being debugged)
    run([c1541, "-format", "gemini,gm", "d81", d81, "-write", prg, "gemini", "-write", BIN / "meganet", "meganet",
         "-write", BIN / "crypto", "crypto", "-write", BIN / "render", "render"], stdout=subprocess.DEVNULL)
    run([c1541, "-attach", d81, "-dir"])
    return 0


def build_certs():
    d = BUILD / "certs"; d.mkdir(parents=True, exist_ok=True)
    openssl = find_tool("openssl")
    for name, args in (("p256", ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]), ("rsa", ["rsa:2048"])):
        if (d / f"{name}.crt").exists():
            continue
        run([openssl, "req", "-x509", "-newkey"] + args + ["-nodes", "-keyout", d / f"{name}.key", "-out", d / f"{name}.crt",
             "-days", "3650", "-subj", "/CN=localhost"], stderr=subprocess.DEVNULL)
    return 0


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "client"
    if target == "test":
        return build_test()
    if target == "certs":
        return build_certs()
    if target == "hostclient":
        return build_hostclient()
    if target == "bank":
        build_bank(); return 0
    if target == "clean":
        shutil.rmtree(BUILD, ignore_errors=True); shutil.rmtree(BIN, ignore_errors=True); return 0
    if target == "client":
        return build_client()
    print(__doc__); die(f"unknown target '{target}'")


if __name__ == "__main__":
    sys.exit(main())
