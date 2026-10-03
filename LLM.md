# mega-gemini

A Gemini client for the MEGA65 on mega-net: TLS 1.3
(`TLS_CHACHA20_POLY1305_SHA256`, X25519, trust on first use by the
server's key), gemtext rendered on the 80-column screen, the gopher
client's browser underneath. C99 for llvm-mos, `-Oz`, the arithmetic
in a bank image as the SSH client does it. 0BSD.

**Status: section 4's plan done.** The
client fetches geminiprotocol.net on the MEGA65, the server's P-256
signature verified and its key pinned, in 12 s (5.6, 5.8); RSA-2048 in
11 s (5.10); RSA-4096 verifies in 5.5 s on a 32-bit Montgomery row of
any length (`mp32_m65.S`, 5.12), so skyjake.fi answers within its
request timer; the status row shows the seconds the handshake's
arithmetic took ("verified in 10 s", 5.15). Links are followed and back comes
from a page cache in attic RAM, in 0 s (5.9); the pins are kept in
GEMHOSTS and the bookmarks in GEMMARKS on the boot disk, and S saves a
page, text or not (5.8, 5.11); the test server's cases and its three
adversaries behave on the machine (5.10); the host client fetches from
every surveyed server (5.2, 5.3); bbs.geminispace.org, whose page
arrives as one record with close_notify behind it, loads whole since a
hook stopped writing over the receive buffer (5.13).

## Read first

1. This file.
2. `../mega-net/docs/PLATFORM.md`: the machine, the family's memory
   map, the traps, the tools, the test driver.
3. `REQUIREMENTS.md`: section 2 decisions, section 4 the plan, section
   5 the findings.
4. `../mega-ssh/LLM.md` and its REQUIREMENTS 5.4, 5.7, 5.22: how a crypto
   bank is built, loaded, called and made to fit.

## Commands

```
python3 build.py test         the host suites: gemtext, Gemini, crypto, signatures, TLS; all must pass before anything else
python3 build.py              the bank (build/bank/crypto.bin, render.bin), the client and bin/GEMINI.D81; refuses on the ssh 5.6 miscompile shape and on less than 1 KB of stack
python3 build.py bank         the bank alone, with its map in build/bank/crypto.map (check .noinit and .bss.hi there after touching crypto.ld: a pattern that matches nothing is silent, 5.8)
CK_SELFTEST=1 python3 build.py   the bank with its P-256 self-test on RFC 6979 (RSA left out for the room) and the client's keys for it: 't' at the address prompt runs it, 'g' leaves 2G and 3G in mp_scratch; that client leaves the bookmark screen out for the room (5.14); selftest 4 (no key) is the row benchmark of 5.12
python3 build.py hostclient   build/host/tls_host URL [--delay SECONDS]: a page fetched on the host through src/tls; the delay sits between the handshake and the request, to measure a server's request timer (5.11)
python3 build.py certs        the test server's self-signed certificates (P-256 and RSA)
python3 tools/gemini_test_server.py [--port 1965] [--cert build/certs/rsa.crt --key build/certs/rsa.key] [--adversary silent|slow|close]
                              one copy per port for the machine (1966 RSA, 1967-1969 the adversaries): a pin is per host and port, and the RSA key on the P-256 port is refused as changed (5.10)
python3 tools/rfc_vectors.py RFC8448.txt RFC8439.txt RFC7748.txt > tests/vectors.h    regenerate the RFC vectors (committed)
python3 tools/sig_vectors.py > tests/sigvectors.h                                   regenerate the signature vectors (needs the cryptography package)
```

`localhost` may resolve to IPv6 while the test server listens on IPv4:
use `127.0.0.1`.

On the machine, with the driver (the Mac's test server is at
192.168.1.232):

```
source ../mega-net/tools/m65lib.sh
put_d81 bin/GEMINI.D81 GEMINI.D81
boot_prg gemini.d81 gemini 'ddress:'               the address prompt ("waiting for an address" also has "ddress": keep the colon)
type_line '192.168.1.232'                          then poll row 23 for a '%': the page, or a message
python3 ../mega-net/tools/mon.py 'm 5e900'         the server's certificate, as the bank stored it
```

Chain a deploy on the build's exit status, never on grep's: a failed
build leaves the old disk, and the old disk was tested twice (5.5).
`put_d81` replaces the disk, GEMHOSTS and GEMMARKS with it: a
persistence test is a `boot_prg` without a put between. To read what
the client wrote, `mega65_ftp -c "get GEMINI.D81"` and walk the D81's
sector chains in Python (`c1541 -read` refuses these names).

## Layout

| Path | What |
|---|---|
| `src/gemtext.c`, `src/url.c` | The document format and URLs, portable, tested |
| `src/docmem.h` | Where the document lives (attic RAM, the link table) and the row format: the one source for the client and the renderer |
| `src/crypto/` | The SSH client's primitives, copied (`sha256`, `sha512`, `chacha20`, `poly1305`, `curve25519`, `mulacc_m65.S`, `crypto.h`, identical files), plus `hkdf.c` (HMAC, HKDF), `aead.c` (RFC 8439 AEAD, streamed), `mp.c` (Montgomery arithmetic; `mp32_m65.S` the 32-bit row of any length and `mp256_m65.S` P-256's, on the machine, 5.12), `p256.c` (ECDSA verify), `rsa.c` (RSA-PSS verify) |
| `src/tls/` | `keys.c` the key schedule; `tls.c` the engine (client side); `tlskit.h` what it asks of the crypto; `tlskit_host.c` the host's answer; `x509.c` the certificate's key, the pin, the verifiers |
| `src/bank/` | The TLS bank: the SSH client's trampoline, prologue, DMA and yield; `api.c` the kit's entries; `render.c` the renderer and its entry, in the top window with `gemtext.c` (5.8); `crypto.ld` |
| `src/m65/` | The client on the MEGA65: `main.c`, `fetch.c`, `doc.c` (the raw body in attic RAM, the rows read back), `pager.c`, `cache.c` (the pages behind, 5.9), `pins.c` (GEMHOSTS), `marks.c` (GEMMARKS), `save.c`, `lowram.h` (the low-RAM table), `tlskit_m65.c` (the kit over the trampoline), `boot.c`, `netutil.c`, `ui.c`, `rnd.c`, `screen.c` |
| `src/platform/` | The `m65_*` modules shared with the NTP, FTP and SSH clients; `m65_screen.c` is not linked (`src/m65/screen.c` replaces it) |
| `tests/` | One suite per layer; `vectors.h` from the RFCs; `tls_host.c` the host client |
| `tools/` | The test server and its site; the vector extractor |

## What is mine in memory

Bank 0's low RAM is listed in `src/m65/lowram.h`, one table: `$1400`
the engine's receive buffer (the renderer's input block), `$1500` the
screen translation buffer, `$1560` a row record (the renderer's out,
the pager's in), `$15FF` the boot crumb, `$1700` the bank's trampoline
(the SSH client's page), `$1A00-$1E23` the scratch line (the request,
the renderer's line, the address typed), `$1E30-$1F90` the small
buffers (a screen row, the note, the failure text, a row's text, a
file name), nothing past `$1FAF` (the exit stub). These are addresses,
so `sizeof` is 2: the length is written next to each (`DOC_SCRATCH`,
`LOW_NOTE_LEN`, 5.8). The TLS engine's state overlays `next_url`
during a fetch (`fetch.h`, 5.9). Bank 1: the font at `$11000`, the
bookmark text at `$11800`, the bank at `$12000-$1BDFF` with its stack
to `$1BFFF`, the link table at `$1C000`, the pins at `$1D000`, the
renderer and the bank's zero-page swap at `$1E000-$1F7FF` (the RENDER
image, 5.8). Bank 5 `$5E900`: the server's certificate. Attic: the
body at `$8000000`, the rows at `$8100000`, the link targets at
`$8200000`, the history at `$8300000`, the page cache's four 1 MB
slots from `$8400000` (5.9). The client `$2001` to `$C98C`, 1,652
bytes for the soft stack (the build refuses less than 1 KB); the bank
with 331 bytes free below its stack and 259 in its top window (5.8):
the next feature in either finds its bytes first. `marks.c` and
`cache.c` stage their text in the scratch line: nothing reads a
bookmark into the scratch line (5.8).

## Rules

- The host proves the arithmetic; the machine measures it. A primitive
  that has not passed its RFC vectors does not go near the MEGA65.
- Files copied from `../mega-ssh/src/crypto` stay identical to their origin;
  what is new here goes in new files (`hkdf.c`, `aead.c`).
- `fail()` in `tls.c` records its line: when a server refuses or a
  transfer fails, `tls_host` prints it. Find the check before changing
  the code.
- No `int64_t`; `uint32_t` only in accumulators. The multi-precision
  code multiplies in 32-bit limbs in the Q register on the machine
  (`mp32_m65.S` for any length, `mp256_m65.S` for P-256) and 16-bit
  limbs on the host, the same Montgomery form (5.12); a modulus must be
  a whole number of 32-bit limbs (`rsa.c` refuses the rest).
- The bank returns nothing in the Z register: llvm-mos assumes Z is
  zero and a store is indexed through it (trap 2), so a non-zero Z on
  a return corrupts the caller. Results larger than A and X go back in
  the parameter block by DMA (the frame counts, 5.12).
- A hook called from inside `tls_in()` (`on_data`, `on_record_end`)
  may read what it is handed and must never write `in`, the buffer
  `tls_in()` is walking: the next record's header may be behind the
  record that just ended, in the same chunk (5.13). The status-line
  parse borrows `LOW_ROW_TEXT`.
- Every wait is bounded on `$D7FA`; mega-net is polled from every loop,
  including inside the crypto (the bank yields).
- A pin without a verified signature is said so on screen; nothing is
  faked as verified.
- The bank DMAs only into named `.bss` buffers, never into a local or
  a zero-page variable (5.5); one AEAD context per direction; after a
  seal the reader's Poly1305 table is stale (5.5). The stage is
  shared by name: `rdbuf` is its first 64 bytes and the key sits at
  +130, so a certificate read is never longer than `RDBUF_CAP` (5.10).
- `byte << 8` promotes to a 16-bit int on this compiler: cast to
  `uint16_t` first, everywhere a length is read from bytes.
- The bank's trampoline mailbox gets this program's map after the copy
  (`boot.c`), or the KERNAL comes back at `$E000` (5.5).
- The math unit: never copy its product into its own operand registers
  byte by byte; each byte written restarts the multiply (5.6).
- The Q instructions clobber A, X, Y and Z: indices live in memory, and
  an indexed operand's address is patched into the instruction
  (`mp256_m65.S`).
- `build.py` refuses a client with less than 1 KB between its data and
  `$D000`; find the bytes, do not lower the check (5.6). The bank's top
  window is where code goes that the `ram` region cannot hold: an
  object named in `crypto.ld` as `*name*.o` (the assembler's objects
  are temporaries with a suffix), compiled without LTO; `.bss` there
  counts against the window's 6 KB (5.8).
- No 32-bit division in the client: `__udivsi3` is 360 bytes (5.8).
- A deploy chains on `build.py`'s exit status, never on grep's (5.6).
- The client's Finished is sent before the server's signature is
  verified, and nothing else until it has passed (`tls_verify`).
- Record every hardware finding in `REQUIREMENTS.md`, numbered.
- Commits are local until the user asks for a push or a release.

## Not to reopen

TLS 1.3 only; one suite; one group; no resumption, no 0-RTT, no client
certificates yet. Trust on first use by key, no certificate
authorities, no name or date checks. Constant time is not a goal.
