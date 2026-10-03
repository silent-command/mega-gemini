# mega-gemini: requirements, decisions, and record

## 1. Goal

A Gemini client for the MEGA65: type or follow a `gemini://` address,
read the page, follow its links, go back, keep bookmarks, save a page
to disk. Gemini is Gopher with encryption and a document format, and
the gopher client is the model for the browser; the new thing is TLS,
which the family did not have. The SSH client is the model for that:
the arithmetic proved on the host against the RFC vectors, then a bank
image on the machine.

## 2. Decisions

| Decision | Choice, and why |
|---|---|
| **Protocol** | Gemini as specified at geminiprotocol.net: one request line, one status line, the body until the server closes. `text/gemini` rendered; other text types shown as text; anything else offered for saving. Status 1x asks the user for a line; 3x is followed (five at most); 4x, 5x and 6x are shown in words. |
| **TLS** | TLS 1.3 only, one suite, `TLS_CHACHA20_POLY1305_SHA256`, one group, X25519. A survey of seven live servers (5.1) found every one accepts exactly that, so nothing else is offered. TLS 1.2 is refused, not faked. |
| **Trust** | On first use, by the server's key: the SHA-256 of its certificate's SubjectPublicKeyInfo, kept per host and port, as the SSH client keeps host keys. No certificate authorities: the Gemini world runs on self-signed certificates and its own specification says to trust on first use. Names and dates in the certificate are not checked; the key is what is pinned, so a renewed certificate with the same key is the same server. |
| **The server's signature** | Verified when the scheme is one this client has; a pin without a verified signature is a pin against passive reading only, and the client says so on screen. The survey (5.1) splits the world into ECDSA P-256 (four of eight, the project's own site among them), RSA-PSS (three) and P-384 (one). The plan is P-256 first, RSA-PSS second, both from one multi-precision Montgomery multiplier in 16-bit limbs (no 64-bit arithmetic, the family's rule), P-384 only if it turns out common. Ed25519 certificates verify already (the SSH client's code), though none were seen. |
| **Where the bytes go** | Records are decrypted as they stream through a 64-byte window and handed on before the tag is checked; the tag decides at the record's end whether the caller keeps them. So no record buffer, and a page of any size streams into attic RAM the way the gopher client's text does. The caller keeps a mark per record and rolls back on a bad tag, or when the record turns out to be a session ticket or an alert rather than data. Nothing acts on unverified bytes: a handshake message is only used once its record's tag has passed, and a page is only shown once the transfer has ended. |
| **Crypto on the machine** | A bank image at `$12000` on the SSH client's model (its trampoline at `$1700`, its yield to mega-net's POLL), carrying SHA-256, HMAC and HKDF, ChaCha20 with the RFC's 96-bit nonce, Poly1305, X25519, and the signature verifiers. Not SHA-512, not Ed25519 signing, not the terminal: the room they took is what the verifiers get. |
| **Platform code** | The FTP client's `m65_*` modules (screen, font, F011, CBM DOS, scratch) and the SSH client's boot and exit, copies shared by rule; the gopher client's text store, history and fetch loop, adapted. |
| **Build** | `build.py`, Python; the host suites (`test`), the host client (`hostclient`, a real fetch through `src/tls`), the test server (`tools/gemini_test_server.py`, with the adversaries the gopher client learned to want). |

## 3. Requirements

- **F-1** Fetch a `gemini://` URL by name or address, on any port.
- **F-2** Render `text/gemini`: headings, links, lists, quotes, preformatted text, wrapped to 80 columns; follow links; go back.
- **F-3** Answer a 1x status with a typed line; follow 3x redirects; explain 4x, 5x and 6x.
- **F-4** Trust on first use by key, the pin kept on disk; a changed key refused with a warning; a signature the client cannot verify said so.
- **F-5** Bookmarks and a home page, as the gopher client.
- **F-6** Save a page or a file to a drive.
- **N-1** Every wait bounded on `$D7FA`; mega-net polled from every loop, including inside the arithmetic.
- **N-2** One `.d81` carrying the client, the crypto bank and `MEGANET`.
- **N-3** Nothing on the machine that has not passed on the host: the vectors for every primitive, a real page through the whole client.

## 4. Plan

| Step | What | Status |
|---|---|---|
| 1 | Skeleton; gemtext parser and word wrap; URL parsing and relative resolution; the host suite | **Done** — 88 checks |
| 2 | HMAC, HKDF, the RFC 8439 AEAD; the TLS 1.3 key schedule against RFC 8448 | **Done** — 17 + 20 checks |
| 3 | The TLS client engine, streaming, no sockets; the host harness; pages from real servers | **Done** — 5.2 |
| 4 | Signature verification: a Montgomery multiplier, ECDSA P-256, RSA-PSS, against generated vectors and the live servers | **Done** — 5.3 |
| 5 | The Gemini layer: request, status, meta, redirects, input; the test server's cases on the host | **Done** on the host (52 checks); the cases on the machine are step 7 |
| 6 | The MEGA65: the crypto bank, the client on the gopher browser, a page on the screen | **Done** — 5.4 to 5.6: geminiprotocol.net on the screen, verified, in 22 s |
| 7 | Known hosts on disk, bookmarks, saving; the adversaries; the long run | **Done**: pins, bookmarks and saving on the machine (5.8); back from a page cache (5.9); the test server's cases and adversaries on the machine, RSA verified in 11 s (5.10); a non-text body saved (5.11) |
| 8 | RSA-4096 within a server's request timer: a 32-bit Montgomery row of any length on the Q register (5.11) | **Done** — 5.12: RSA-4096 verified on the machine in 5.5 s (skyjake.fi), the 16-bit row retired; the one server it exposed a transfer fault on, fixed (5.13) |

## 5. Findings

### 5.1 What the Gemini world speaks (2026-09-14)

Seven servers probed with `openssl s_client` from the host, all on
TLS 1.3, all accepting a ClientHello that offers only
`TLS_CHACHA20_POLY1305_SHA256` and X25519:

| Server | Signs with | Key |
|---|---|---|
| geminiprotocol.net | ecdsa_secp256r1_sha256 | P-256 |
| gemini.circumlunar.space | ecdsa_secp256r1_sha256 | P-256 |
| kennedy.gemi.dev | ecdsa_secp256r1_sha256 | P-256 |
| gemi.dev | ecdsa_secp384r1_sha384 | P-384 |
| skyjake.fi | rsa_pss_rsae_sha256 | RSA 4096 |
| bbs.geminispace.org | rsa_pss_rsae_sha256 | RSA 4096 |
| gemini.conman.org | rsa_pss_rsae_sha256 | RSA 2048 |

Every certificate is self-signed (warmedal.se did not resolve). So the
transport needs nothing the SSH client did not have, and the
signatures need two new verifiers. Note for the pin store: skyjake.fi
and bbs.geminispace.org present the same key (one operator), which is
fine, since the pin is per host and port.

### 5.2 A TLS 1.3 client, from the RFC to seven servers in a day (2026-09-14)

The key schedule was written against RFC 8448's trace and passed it
whole on the first run: the X25519 shared secret, every extract and
derive, both Finished MACs, the traffic keys and IVs. (RFC 8448 uses
AES-GCM, so its record contents could not be checked; the ChaCha20
AEAD was checked against RFC 8439 2.8.2 instead, encrypting in one
piece and decrypting in three.) The vectors are extracted from the RFC
texts by `tools/rfc_vectors.py` into `tests/vectors.h`, 105 blocks,
every length checked against the RFC's own count.

The engine (`src/tls/tls.c`) then met real servers through
`tests/tls_host.c`. Two faults, each found by the line number `fail()`
now records:

*The read sequence number.* The record that carries the server's
Finished ends after the message has been acted on. The client switched
its read keys and zeroed the sequence number inside the message
handler, then the record's end incremented it: the first application
record was decrypted with sequence 1 and failed its tag. The switch is
now deferred to the record's end (`rd_switch`). The write side was
already right, because the client's own Finished is sealed before the
switch.

*CertificateRequest.* geminiprotocol.net asks for a client certificate
(Gemini uses them as identities), and the client refused the message
as unexpected. It is now accepted, hashed, and answered with an empty
Certificate carrying the request's context, in the same record as the
client's Finished, whose transcript includes it (RFC 8446 4.4.4).

**Result.** Pages from the local test server (P-256) and from
geminiprotocol.net, gemini.circumlunar.space, skyjake.fi, gemi.dev,
bbs.geminispace.org (10,434 bytes, streamed) and gemini.conman.org,
each ending in the server's close_notify; the leaf certificate's key
found and its SubjectPublicKeyInfo hashed for the pin. Every signature
still reads UNCHECKED, which step 4 is for.

**Sizes on the host**, for the port's budget: `tls.c` is the engine;
the state block `struct tls` is about 1.3 KB, of which 640 is the
buffer for one handshake message (the largest, CertificateVerify with
an RSA-4096 signature, is 520 bytes) and the rest keys and contexts.

### 5.3 The signatures verified: six of seven servers (2026-09-14)

One multiplier for everything (`src/crypto/mp.c`): CIOS Montgomery
multiplication in 16-bit limbs, every intermediate sum at most
0xFFFFFFFF, so no 64-bit arithmetic anywhere; the modulus, its
Montgomery constants and the scratch in a context, one for the P-256
field, one for its order, one for an RSA modulus of up to 4096 bits.
Inversion by Fermat. On top: P-256 in Jacobian coordinates (`p256.c`,
Shamir's trick for u1 G + u2 Q, the key checked to be on the curve)
and RSASSA-PSS (`rsa.c`, MGF1-SHA256, a 32-byte salt). The vectors
(`tools/sig_vectors.py`, from Python's integers and OpenSSL) cover
products, powers and inverses under all three moduli, RFC 6979 A.2.5's
two deterministic P-256 signatures, three more from OpenSSL, and PSS
at 2048 and 4096 bits, with tampered signatures, hashes, keys and
lengths refused: 33 checks, green on the first run.

Live, both verifiers then failed on every server while passing their
vectors, so the common input was wrong: the transcript hash. It was
taken when the CertificateVerify header had arrived, and by then its
four header bytes had been hashed in. The hash CertificateVerify signs
is the transcript *before* it (RFC 8446 4.4.3); a snapshot is now
taken at the start of every message.

**Result.** geminiprotocol.net, gemini.circumlunar.space and the local
test server (ecdsa_secp256r1_sha256), skyjake.fi, bbs.geminispace.org
and gemini.conman.org (rsa_pss_rsae_sha256) all read "verified";
gemi.dev (P-384) reads UNCHECKED as designed. So a pin on any of the
six is a pin against an active attacker too.

### 5.4 The bank made to fit (2026-09-14)

The crypto compiled for the target without link-time optimisation came
to 79 KB of code: no bank holds that, so the split is the SSH client's,
with more in the bank. The bank (`src/bank/`, the SSH client's
trampoline at `$1700`, prologue, DMA and yield, copied) carries every
cryptographic step of the handshake and the record layer behind 23
entries that are the kit (`src/tls/tlskit.h`); the client keeps the
framing and the parsing (`tls.c`, 17 KB unoptimised), the Gemini
layer, the URLs and the browser. No key, and not the server's
certificate, is ever in the client's memory.

The first link of the bank overflowed its 40 KB window by 11 KB with
9 KB of `.bss`. What went: Ed25519 and its SHA-512, 15 KB that
`tk_verify` pulled in for a scheme no surveyed server uses (now behind
`-DX509_NO_ED25519` in the bank build only; the host keeps it); the SSH
client's unrolled `chacha20_block`, 4.1 KB, replaced in the bank by a
looped one of under 1 KB (`chacha20_small.c`, checked against the SSH
one on the host); two 1.5 KB Montgomery contexts where one shared one
serves ECDSA and RSA in turn, with one 1 KB scratch between them; and
three 512-byte arrays that `mp.c` had put on the stack, which on the
bank's 512-byte soft stack would have been fatal before they were
wasteful: a reduction routine in place of an array of one, the
exponent's bits read off the modulus in place of a copy. The loop
checker from the SSH client (5.6 there) refused three counted loops on
the way; each is now a pointer walk. The bank is 32,800 bytes of image
with 1.4 KB to spare below its stack.

### 5.5 A page on the screen, and the four faults on the way (2026-09-14)

The client (`src/m65/`): the NTP client's `ui` and network modules,
the platform modules, a screen module without the console library (its
765-byte escape buffer and output routines were the difference between
fitting and not, as in the SSH client), the document store in attic
RAM (raw bytes with a mark per record, then rendered once into 80-byte
rows, the links in a table in bank 1), a pager on the gopher client's
model, the fetch loop driving `tls.c` over mega-net's socket 0. The
program is 36,355 bytes with the data ending at `$CAC2`. The status line
is parsed only from bytes whose record has passed its tag; until then
they sit in the raw store.

On the machine the client loaded both images, DHCP, DNS, connect, and
the handshake ran; then four faults, each found from the screen, the
serial monitor, and the line `fail()` records:

1. *The trampoline's restore map.* The bank's trampoline puts back the
   map its mailbox holds, whose built-in default maps the KERNAL at
   `$E000`. After the first bank call (the entropy sampling) the next
   ethernet interrupt went to the KERNAL's handler, and the client sat
   at "waiting for an address" for ever: the NTP client's unexplained
   stop in its 5.3(b) looks the same. The SSH client sets the mailbox's
   map after copying the trampoline; this client now does too.
2. *DMA into zero page.* The certificate walker reads through a hook
   into small locals, which llvm-mos places in zero page. The bank's
   DMA target for a zero-page address is that address plus `$10000`,
   which is not the zero page the CPU sees. The certificate was in
   bank 5 and its length right (read through `mon.py`), and the walker
   still found no key. The hook now DMAs into a pinned buffer and
   copies with the CPU (PLATFORM.md: "pin anything a DMA job or a bank
   must see").
3. *One AEAD context for both directions.* The server's Finished
   record is still open when the client seals its own Finished; on the
   host the kit seals with a separate context, the bank had one. The
   bank now has a reader and a sealer.
4. *Poly1305's multiplier table.* On the target `poly1305.c` keeps the
   table for `r` in one global, marked valid per context by a flag;
   after the sealer built its table the reader used it and record 6's
   tag failed. The SSH client never interleaves two contexts. After a
   seal the bank marks the reader's table stale; the shared file is
   unchanged.

**Result.** From the test server on the Mac (P-256): "verified, key
pinned", the index page rendered with its headings, wrapped prose and
fourteen links. The handshake took 3 minutes 10 seconds, all of it
the ECDSA verification in compiled C over 16-bit limbs (the bank's
own P-256 self-test on RFC 6979's vector took the same); the fetch
itself is seconds. So the verifier is right on this machine and far
too slow for use: the Montgomery inner loops belong on the 45GS02's
multiplier, as the SSH client's field arithmetic is (its 5.11 took
X25519 from 14 s to 3.5 s). The AEAD self-test on RFC 8439 passed at
once. Both self-tests stay in the source behind `-DCK_SELFTEST`; the
bank has no room for their vectors otherwise.

**Memory claimed** (for PLATFORM.md's table): bank 0 `$1700` the
bank's trampoline (the SSH client's page; one program at a time); bank
1 `$12000-$1BDFF` the bank and `$1BE00-$1BFFF` its stack, `$1C000` the
link table (8 bytes per link, 500), `$1D000` the pins (100 bytes each,
16); bank 5 `$5E900-$5FFFF` the server's leaf certificate (the SSH
client's known-hosts row; one program at a time); attic `$8000000`
the raw body, `$8100000` the rows, `$8200000` the link targets,
`$8300000` the history.

### 5.6 The signature in seconds, and five more findings (2026-09-15)

**How long the verification took.** The first page from the test server
took 3.5 minutes, all of it ECDSA in compiled C over 16-bit limbs. The
Montgomery rows on the 45GS02's math unit (`mp_m65.S`, zero-page
pointers, any length) brought one verification to 43 s: the product
scanning is only a part of a row's cost on this CPU, the rest being the
carries and the byte moves. What brought it to 13 s is `mp256_m65.S`:
the SSH client's `fe_mul_m65` makes the 512-bit product (its eight
32-bit limbs are the same little-endian bytes as sixteen 16-bit ones,
its 5.11), and the reduction is eight rounds of a row in the Q register
on fixed buffers, the limb's address patched into the three
instructions that touch it, because the Q instructions clobber the
index registers. The 16-bit rows stay for RSA, whose moduli are longer.
Both forms are the same Montgomery form (R = 2^256), so the two paths
mix freely for P-256.

*The math unit's product fed back into its operand.* The reduction
first computed mu = t[i] * n0 on the math unit and copied the product's
low four bytes into MULTINA byte by byte; each byte written restarted
the multiplication, so the later bytes read came from a different
product. With p, n0 is 1 and the fault hid; with the group order n it
did not. The self-test failed at its final comparison while every
intermediate that could be read through the monitor (one product, both
conversions, an inversion, 2G and 3G) matched Python; the order-field
intermediate w did not. mu is now computed by C and handed to the
assembly; nothing reads the multiplier's output into its input.

*The trampoline restores what its mailbox holds* (5.5, item 1) has a
second half: the bank's zero page. The multiplier's rows needed three
zero-page pointers, four bytes more than the bank's page held, so the
bank now swaps `$68-$FF` instead of `$70-$FF`.

*The program's data ran into its stack.* Two builds in a row sat at
"loading mega-net" and one showed a screen of zeros. Nothing in the
boot path had changed; the client's `.noinit` (the compiler's static
frames) had grown to end at `$D059`, past the `$D000` the soft stack
grows down from, and the linker reserves nothing for the stack. The
first deep call of the load walked over live data. The FTP client's
rule "keep `.bss` below `$C900`" was this rule; `build.py` now refuses
a client with less than 1 KB between its data and `$D000`
(`check_headroom`), and the engine's receive buffer and the scratch
line live in the low RAM the family's map leaves to clients
(`$1A00-$1F6F`; `$1F00` and up only as the gopher client proved it, at
run time).

*A grep's exit status.* Twice a deploy chained on `grep` finding
"error" in the build log ran with the old disk, and two rounds of
diagnosis were of a build that had not happened. Deploys chain on
`build.py`'s exit status now.

*The ethernet controller's flags after a fetch.* Once, boots after a
fetch to a live server stuck with `$D6E1` reading `$30`, both queue
flags set, the VIC and both CIAs quiet, and the CPU in the interrupt
stub; the client acknowledges the queues as its first act now (the
sequence mega-net's driver uses) and the symptom has not returned. It
is recorded as a suspicion, not a finding: the stuck boots that
followed had the other cause above, and the NTP client's 5.3(b) may be
this or that.

**The order of the handshake.** With the verification at 43 s,
geminiprotocol.net answered the request with its own `40 request timed
out`: the session was alive after a minute, the server's request timer
was not. The client now sends its Finished before verifying the
server's signature, and verifies before sending anything else
(`tls_verify()`, `TLS_VERIFYING`), which is sound: a server that cannot
produce the signature gets a Finished and never a request. The minutes
then ran against the server's request timer instead of its handshake
timer; at 13 s they run against neither.

**Result.** The bank's P-256 self-test on RFC 6979's vector: 13 s.
geminiprotocol.net from the MEGA65: "verified, key pinned", the page
rendered, 22 s from the address typed to the page on the screen, of
which the X25519 exchange is 3.5 s and the ECDSA verification about
13 s. The bank is 34,062 bytes with 47 bytes to spare below its stack;
the client 37,274 with 1,118 for the soft stack. One fault on the
screen: a paragraph cut at 255 characters, the fold's 8-bit length
(5.7).

### 5.7 Links, back, and a paragraph cut short (2026-09-15)

From geminiprotocol.net's front page, TAB three times and RETURN opened
`/docs/faq.gmi`, a long page: 70 s, 22 of them the handshake, the rest
the transfer, which runs at about a kilobyte a second through the
bank's 64-byte decryption pieces (two bank calls and four DMA jobs per
piece; a bigger piece, decrypting in the receive buffer itself, is the
obvious step). RUN/STOP went back to the front page, refetched in 22 s:
there is no page cache yet, and there is room for one in attic RAM.

The front page's first paragraph ended at "not a vestigial c": the
FTP client's `m65_fold_utf8` takes an 8-bit length, so a paragraph
longer than 255 bytes was cut. The client's screen module now folds a
whole line in place with 16-bit lengths (`m65_fold_utf8_line`), which
also freed the 256-byte fold buffer.

The same page then showed a "=" at the end of full rows: a row record
is 80 bytes, three of them the kind and the link index, so it holds 77
characters, and the renderer wrote 78. The 78th spilled past the
record and the pager read a neighbour's byte in its place. `DOC_ROW_TEXT`
is 77.

### 5.8 The renderer in the bank's top window; pins, bookmarks and pages on disk (2026-09-15)

**The room.** Step 7's first three features want the family's disk
writer (`m65_cbmdos.c`, `m65_f011.c`: 2.7 KB of code and 800 bytes of
buffers), and with it the client's data ended 5.1 KB past `$D000`. The
renderer left the client. It lives in the bank's top window now
(`$E000-$F7FF` of bank 1, the window the SSH client's terminal parser
uses, ssh 5.7) as a second image, RENDER, which `boot.c` loads to
`$1E000`; one bank entry (`$2045`) turns the raw body in attic RAM
into the rows and the link table, once per page, by DMA. It has no
buffers of its own: the bank's map leaves bank 0's `$0000-$1FFF` where
it is, so the renderer's line is the client's scratch line at `$1A00`
and its input block the engine's receive buffer at `$1400`, both idle
during a render, and a row goes out through the bytes after the screen
translation buffer at `$1560`. `docmem.h` is the one place both sides
take the addresses from. The window's objects (`render.o`,
`gemtext.o`) are compiled apart, without LTO, so `crypto.ld` can name
them.

The bank then had its own shortfall: 47 bytes to spare (5.6), and the
entry that reads the argument block and calls the renderer was 313
bytes of ordinary `.text`. The entry moved into `render.c`, and after
it the trampoline's register cells and the zero-page swap buffers
(`jumptable.S`'s `.noinit`, 312 bytes, reached by absolute addresses
that work as well at `$E000`): the bank has 331 bytes below its stack
now and the window 259. Two traps in the script: the assembler's
object is a temporary with a suffix, so the pattern is
`*jumptable*.o`, and a pattern that matches nothing fails silently —
the first build with `*jumptable.o` linked, 19 bytes under the stack,
with the swap still in `ram`; the map says where things went. And a
first try put the compact ChaCha20 in the window too, whose state is
`.bss`: 392 bytes over.

The client was still 940 bytes short of `check_headroom`'s kilobyte.
Found: the P-256 self-test keys behind `CK_SELFTEST` like the entry
they call (and the dead multiplier test out); the client's two 32-bit
divisions, a percentage and a record count, rewritten, which drops
`__udivsi3`, 360 bytes; the failure text's number and string copies as
two helpers instead of three inlined copies. 38,689 bytes, 1,072 for
the soft stack.

**Two faults on the screen.** *`sizeof` of a pointer.* The scratch
line became a fixed address (`#define doc_scratch ((char *)0x1A00)`),
and `copy(typed, ..., sizeof typed)` copied one character: the address
prompt offered "g", and RETURN fetched it. The size is `DOC_SCRATCH`,
and the macro's comment says so. *The bookmark list through the
scratch line.* `draw_marks` read each bookmark into the scratch line
while `marks.c` stages the far text in that same line: an overlapping
copy, four characters over and over ("GEMIGEMIGEMI"). The list is built
in `next_url`, idle on the address screen.

**On disk.** GEMHOSTS is the pin table's records as they are in memory
(100 bytes each, loaded straight into `$1D000`, written back when a
key is pinned, before the page is read). GEMMARKS is the FTP client's
form: a magic line `GEMM1` and one URL per line, in bank 1's `$11800`,
eight at most; M in the pager toggles the page, a number at the
address prompt opens one, D and the number deletes it. S writes the
raw body as a SEQ file, the name suggested from the URL's last segment
(`FAQ-GMI`; the host for a root). On the machine: a fetch pinned the
key and M bookmarked the page; after a reset the bookmark was listed,
its number fetched the page "verified" without "key pinned", D1
removed it; the disk pulled off the card held the three files with
the expected bytes (the record, the magic line, the 1,184-byte body).

**What was measured.** The front page, its key pinned: 12 s from the
address to the page. 5.6's 22 s was measured before the records were
decrypted in place (5.7's obvious step: `tls_in()` takes the receive
buffer non-const and the pieces no longer pass through the bank's
stage twice) and before the renderer moved; how the ten seconds divide
between the two was not measured apart. The FAQ page, 165 KB: 26 s
from "receiving" to the page, about six kilobytes a second against
5.7's one.

Left of step 7: a page cache for back (the front page is refetched in
12 s), the test server's adversaries on the machine, RSA's time, and
saving a non-text body (status 20 with another type still says "not
text").

### 5.9 Back without the handshake: the page cache, and the bytes for it (2026-09-15)

**The cache.** Four slots of 1 MB in attic RAM from `$8400000`, each a
page's URL, its length, where its body starts, how it was rendered
and its status text, then the raw body from `+$1000` (`cache.c`). A
page goes in when it is left by a link, the address prompt or H
(`history_push`), if it was a page at all: a failure's message is not
kept, so going back to it fetches again. RUN/STOP pops the history
and asks the cache first; a hit puts the body back and renders it,
which is DMA and the bank's renderer, no network. A slot is reused
when its URL comes round again, otherwise the oldest goes. The
history became a ring of sixteen at the same time, which is smaller
code than shifting fifteen URLs down. Only back reads the cache: a
link followed forward is fetched, as before, so a page is never older
than the moment it was last left.

On the machine: the front page, then the FAQ (26 s), then RUN/STOP:
the front page again in 0 s, "verified, key pinned" as its status row
had said. A link, and back again: 0 s. Back once more, with nothing
behind: the address prompt.

**The bytes.** The cache cost about 700 bytes of code, and the client
was 48 bytes above the build's floor. Found, in the order they were
tried: the two copies of the port formatter and the dozen four-argument
`put()` calls in `url_resolve` as two helpers (264 bytes; the 88 checks
unchanged); `message_page` appending its parts instead of joining them
in a 160-byte local; the history as a ring; six small buffers into the
low RAM the family leaves to clients (`lowram.h`: a screen row being
built, the note, the failure text, a row's text for the pager, the
file name typed — `$1E30-$1F90`, the gopher client's verified-free
`$1C00-$1FAF`, below the exit stub — and the pager's row record onto
the renderer's at `$1560`, which is idle between renders); and the
one that paid: the TLS engine's state, 774 bytes, overlaid on
`next_url`, which is dead from the moment its URL has been copied to
the page's own (`go()` now copies before the fetch, not after) until
the fetch is over (`fetch.c`: `#define t (*(tls *)next_url)`, the
bank's aliasing style). 39,291 bytes, 1,652 for the soft stack.

Two things tried and put back: a percentage without a 32-bit divide
as a loop of 32-bit adds was bigger than two 16-bit divisions (the
status row now scales both numbers by 8 past 655 rows shown, near
enough); and `ui_read_line` building its row in place, without
`ui_line`, grew by 127 bytes — the line goes through `ui_line` again,
with its own 81-byte buffer. And the three 16-bit division helpers
(571 bytes) cannot be dropped from the client: the platform's disk
modules divide and take remainders on their own.

Left of step 7: the test server's adversaries on the machine, RSA's
time on the machine, saving a non-text body.

### 5.10 The test server's cases on the machine: RSA refused, then verified in 11 s (2026-09-15)

The test server on the Mac (`tools/gemini_test_server.py`), five
copies of it: the P-256 certificate on 1965, the RSA-2048 one on 1966,
and the three adversaries on 1967 to 1969. Separate ports because a
pin is per host and port: the RSA key on 1965 would have been refused
as a changed key, correctly.

**RSA.** The first RSA verification ever tried on the machine: "the
server's signature is wrong (tls.c:216) why 4", in 5 s — the
arithmetic ran to its end and disagreed, where the host verifies the
same certificate. The arithmetic was innocent. The bank reads the
certificate through `rdbuf`, "the stage's first 64 bytes" by its
comment, but `rdbuf` was defined as the stage itself, and
`sizeof rdbuf` was 256; the key's offsets (`vkey`) sit at stage + 130.
A P-256 key is 65 bytes and never reached them; the RSA modulus is
256 bytes, one DMA of 256 into the stage, over the key, after which
the exponent was read from wherever the modulus's bytes pointed. The
piece is capped at 64 (`RDBUF_CAP`) and RSA-2048 verifies: "verified,
key pinned", 11 s from the address to the page, the same as P-256
(the exponentiation with e = 65537 is seventeen 128-limb Montgomery
products on the math unit's rows, about 5 s). RSA-4096, which two of
the surveyed servers use (5.1), is four times that per product and
not yet timed on the machine.

**The cases** (all from a fresh disk, so every host was "key pinned"):
`/input` asks, the answer goes as the query, the page shows it;
`/secret` the same, "not echoed" said on the status row (the line
editor echoes regardless: a password field is not built); `/redirect`
lands on the index in 22 s, two handshakes; `/loop` gives "too many
redirects" after six handshakes, 65 s; `/gone` "51 not found: Not
found"; `/slow` "44 slow down: try again later: Slow down"; `/big`
(180 KB) streams into attic RAM in 30 s and pages; `/binary` "not
text: application/octet-stream"; `/nocrlf` (a header without its end)
and `/silent` (nothing after the request) "no answer from the server"
after the 10 s idle timer, 19 s; the `silent` adversary the same; the
`close` adversary (the socket shut after the handshake) "the server
sent nothing", 11 s; the `slow` adversary (a byte a second) delivers
a 25-byte page in 25 s, the idle timer content between bytes.

**Two things seen on the way.** `/latin` (charset=iso-8859-1) showed
"# Caf." and "M.ller": `charset_ok` accepted the charset and the fold
read the bytes as UTF-8 anyway. The Gemini layer now says
`is_latin1`, the render entry's byte carries `RENDER_LATIN1` beside
`RENDER_PLAIN` (`docmem.h`), and the fold maps a byte past 0x7F as
the Latin-1 character: "# Cafe", "Muller, Angstrom, senor.". And the
input prompt ran into the answer ("Type somethinghello world"): the
meta gets ": " appended before the line editor, in the room the
response keeps after it.

Step 7 is done but for saving a non-text body. The bank has 331 bytes
below its stack; the client 1,498 for its soft stack.

### 5.11 A non-text body saved; the RSA-4096 servers and their request timer (2026-09-15)

**Saving what is not text.** A status 20 with a type other than text
used to become a message page, which cleared the body. The body is
kept now: the page shown is one line appended after it ("not text:
application/octet-stream — S saves it to disk as it came"), rendered
from that offset, and S writes the body from `body_off` to where the
line begins (`save_body` takes an end now; `pager_show` carries both).
Such a page is not cached. On the machine, `/binary` (4,096 bytes,
0x00 to 0xFF sixteen times) saved as BINARY and read back from the
disk byte for byte. The client has 1,231 bytes for its soft stack.

**RSA-4096.** skyjake.fi, one of the two RSA-4096 servers in the
survey (5.1), from the machine: "the server sent nothing" after 26 s.
The handshake completed and the signature verified; the server had
closed before the request arrived. The host client got a `--delay`
option (seconds between the handshake and the request) and skyjake.fi
answers with a delay of 7 s and closes, with close_notify, at 10 s:
its request timer is under ten seconds. On the machine, by the status
row: "the handshake: keys" 8 to 10 s, two X25519 scalar
multiplications (the key share and the shared secret, 3.5 s each,
5.6) and the certificate; "the server's signature" 5 to 9 s for
RSA-2048 and 11 s for P-256. The server's timer runs from its
Finished, which it sends on the ClientHello: the shared secret, the
certificate and the verification all count against it, so an
RSA-2048 server with skyjake.fi's timer would be borderline too, and
RSA-4096, four times the work, near 20 s, is twice over. (The
measuring perturbs: a screen dump through the JTAG stalls the CPU,
and a loop that dumped without pause made every phase five times
longer and timed the test server out; the family's one-second polling
costs about a half.) The verification is the 16-bit rows on the math unit
(`mp_m65.S`, 5.6): seventeen Montgomery products of 256 limbs, two
rows of 256 limbs per limb of the multiplier, about 180 cycles per
limb, near 10 s, and R² by 8,192 modular doublings in compiled C, a
few seconds more. The 256-bit path (`mp256_m65.S`) is three times as
fast per bit, being 32-bit limbs in the Q register; a row of that
kind for any length is the way to those two servers, and is not
written. Sending the request before the signature is verified would
meet any timer and is not done: a request can carry a query, and a
query can be an answer to status 11.

### 5.12 RSA-4096 in the server's timer: the 32-bit row of any length, and a Z-register regression (2026-09-15)

**The row.** The 16-bit Montgomery row (`mp_m65.S`, 5.6) spent about
180 cycles a limb, the product a small part of it and the carries and
byte moves the rest. `mp256_m65.S` was three times faster per bit by
working in 32-bit limbs in the Q register (A/X/Y/Z as one word), but
it was hard-wired to eight limbs for P-256. `mp32_m65.S` is that idea
for any length: a row `out[k] = in[k] + a * p[k] + carry` over 32-bit
limbs, the three arrays' addresses patched into the instructions that
touch them and stepped by four each limb (the Q ops clobber X, Y and
Z, so nothing indexes), cnt up to 255. `mp.c`'s `mont32` (CIOS) drives
two rows a limb over it for a modulus of an even number of 16-bit
limbs — every RSA modulus, which `rsa.c` now requires (`nlen & 3`
refused) — and the reduction row writes its dropped low limb into a
spare 32-bit limb kept below the scratch. The same CIOS in C over
16-bit limbs stays for the host, and `test_crypto` checks the 32-bit
driver against it on random moduli of 256 to 4096 bits, product,
reduction and squaring-in-place: the machine then adds only the row.
The 16-bit row is retired.

**Measured, 50 frames a second.** The row: about $13 frames (~0.25 s)
per 65,536 limb-steps, the same as `fe_mul_m65`, whose product it
shares the math unit with; patching the addresses costs a frame or two
over a fixed loop, the I/O nothing (both benchmarked and dropped).
RSA-2048 verifies in 82 frames (1.6 s), RSA-4096 in 275 (5.5 s),
against skyjake.fi's request timer of under ten seconds (5.11).
P-256, two scalar multiplications over the 256-bit path, takes about
400 frames (8 s): RSA-4096 is now the faster of the two. The bank
reports the frames of the shared secret and the signature back to the
client, which shows them beside the page ("(k 125, s 275)").

**R² by squarings, not doublings.** `mp_init` built R² by
doubling one modulo m 16n times: 8,192 modular doublings in compiled C
for RSA-4096, seconds before the first product. R mod m is R - m (m's
top bit set), under 2m; doubled d times and then squared s times in
Montgomery form it is R 2^(d 2^s), and 16n has four factors of two, so
256 doublings and four squarings reach R². The doublings are a
two-hundredth of a product each, so this is a few products' time.

**A return register that broke the transfer.** The frame count was
first handed back in the trampoline's Y and Z return registers. Z is
the family's forbidden one: llvm-mos assumes it zero, and a store of a
zero-page byte is compiled as an indexed store through Z (PLATFORM.md
trap 2). A non-zero Z on the return from the verify entry corrupted
the client a few records into every page: geminiprotocol.net's FAQ,
which had loaded whole before, cut short at "a malformed record
(tls.c:373) rec 11", the record's version byte reading as garbage
because the byte stream had drifted. The count goes back in the
parameter block by DMA now, no register but A and X touched, and Z
stays zero; the FAQ and every P-256 page load and scroll whole again.
The bug had been invisible until RSA-4096 got a transfer to reach at
all.

**One server's transfer, at first.** With the handshake fast enough,
bbs.geminispace.org (RSA-4096) verified and pinned but its transfer cut
short at "rec 11", the version byte different each run. It was not the
arithmetic and not mega-net: 5.13 has the diagnosis and the fix.

### 5.13 The record after the page: a hook that wrote over the receive buffer (2026-09-15)

**The symptom.** bbs.geminispace.org, reachable at last (5.12):
"verified, key pinned; cut short: a malformed record (tls.c:373) rec
11", the header's version byte different each run (10, 117, 159), the
page showing a heading and 10%. The host client fetched the same page
whole; the 165 KB FAQ streamed whole on the machine; the sniffer
(`recsniff.py`, a Python TLS session over a memory BIO, the raw record
headers read off the wire) showed bbs sending its handshake, two
session tickets, the whole page as one 10 KB application record, and
close_notify.

**The method: log what the engine frames, then what it was given.** A
throwaway probe (`-DTLS_RECLOG`, since removed) wrote each record's
index, type and length as `record_start()` saw it to attic RAM at
`$8500000`, the running total of bytes fed to `tls_in()` at `$8500100`,
and the last two chunks raw, as `net_recv()` delivered them, at
`$8500200`; `mon.py` read them after the failure. One session:

    rec  1: 22 (handshake)   90        rec  6: 23  537
    rec  2: 20 (CCS)          1        rec  7: 23   53
    rec  3: 23   55                    rec  8: 23  266   (a session ticket)
    rec  4: 23   72                    rec  9: 23  266   (a session ticket)
    rec  5: 23 1423                    rec 10: 23 10313  (the page)
    rec 11: type 0x64 ('d'), length 0x6974 ('i','t')     -- garbage

Ten headers and their lengths put record 11 at byte 13,126; the total
delivered was 13,150, which is 13,126 plus exactly one close_notify
record (5 + 19). So not a byte lost or doubled. Record 10 had
authenticated (a lost byte fails the tag: this was `TLS_E_RECORD` at
11, not `TLS_E_TAG` at 10), so the stream was exact through the page.
And the last chunk, 102 bytes, raw as delivered, held `17 03 03 00 13`
— a perfect close_notify header — at offset 78, where the arithmetic
put it. mega-net delivered the stream correctly. The garbage header
was ASCII, page text: something inside the client wrote plaintext over
`in` after the tag had been collected and before `tls_in()` read the
next header.

**The fault.** `on_record_end()` in `fetch.c`, on the first
application record, parses the Gemini status line by reading the raw
document back from attic RAM — into `in`, the live receive buffer, 256
bytes at a time. `tls_in()` is still walking that buffer: the record
that just ended may be followed in the same chunk by the next record's
header. For geminiprotocol.net and the test server the status line is
a small early record of its own and nothing follows it in the chunk.
For bbs the handshake and the tickets (records 3 to 9) end with keep
false and return before the parse, so the first application record is
the whole page, and close_notify shares its last chunk: the parse
wrote the page's first 256 bytes over the header at offset 78. The
page was in fact complete; only the record after it was unreadable.
A latent fault from the first pages (5.5), reachable only through a
server whose status line, body and close arrive as one record and one
chunk — and reachable at all only once RSA-4096 fit the timer.

**The fix.** The status line is parsed through the pager's row-text
buffer at `$1F30` (`LOW_ROW_TEXT`, idle during a fetch), 64 bytes at a
time, never through `in`; `gem_feed()` was already a streaming parser.
bbs.geminispace.org: "verified, key pinned", the whole page, paged to
its end; the FAQ and skyjake.fi as before. The rule that comes out of
it: a hook called from inside `tls_in()` may read the buffer it is
handed and must not write the buffer `tls_in()` is walking.

**Two things noticed on the way, not faults.** The frame counts were
first returned in the trampoline's Y and Z registers (5.12): the Z
half was this session's other lesson. And mega-net's DMA ring variants
(`ring_read_x`, `ring_write_x`, the ABI's path) have no host coverage
— `test_tcp.c` exercises the CPU variants only. They read correctly
here, byte for byte, but the gap is worth a case in mega-net's suite.

### 5.14 The self-test build fits again; a host case for mega-net's DMA rings (2026-09-15)

The `CK_SELFTEST` client had fallen to 813 bytes of stack headroom,
under the build's floor, on the keys and strings its self-test adds
(5.12). It leaves the bookmark screen out now (`draw_marks` and the
number and D handling at the prompt, under `#ifndef CK_SELFTEST`), as
the bank of that build leaves RSA out: a build for timing the
arithmetic on the machine, not for browsing. 1,425 bytes.

5.13's method read mega-net's DMA ring paths byte for byte and found
them right, and found that nothing on the host ever had: `test_tcp.c`
exercised `ring_read` and `ring_write`, the CPU variants, while the
ABI's `TCP_RECV` and `TCP_SEND` go through `ring_read_x` and
`ring_write_x`. mega-net's suite now drains 3,000 then 2,000 bytes
through `mn_tcp_recv_x` into a spare 4 KB of the host pool, the second
read crossing the 4 KB ring's end (the head asserted at 904 after),
and queues 700 bytes through `mn_tcp_send_x` from the pool across the
send ring's end at 3,072 after a plain send has moved its tail to
2,800 (the tail asserted, so the wrap is known to have happened).

### 5.15 Three things the user saw, and 345 bytes for them (2026-09-15)

*"verified (k 125, s 369) 81%"*: the frame counts of 5.12, the shared
secret's and the signature's, left on the status row in the form the
record needed. They are one number now, "verified in 10 s", the frames
at fifty a second as whole seconds, and the pin note follows it. *The
keys row ended in "M m"*: 93 columns on a 79-column row. "cursor
scroll" needs no telling and "RUN/STOP" is "STOP" on this keyboard as
on the C64's; the row is 79 columns exactly, "Q quit" included. *Back
through the links*: K had done it since 5.7 and the row never said;
shift-TAB does it too. Not as first written: the key was read as TAB
with a shift bit in `$D611`, which never matched, because this
keyboard delivers shift-TAB as a code of its own, `$0F` (bit 0 of
`$D611` set beside it), found by a throwaway build that wrote every
unhandled key's code on the status row for the user to press against
— the driver cannot type a shifted key. `$0F` is a case of K's now.

**The bytes.** Three small edits cost 345 bytes of program and put the
client under the build's floor, and no one of them was the cause: the
linker map showed all of it in `main`, into which `pager_show` and
`fetch` are inlined, and building with each file reverted in turn
showed the seconds about 105, the note's reordering about 48 and the
TAB line about 183 — each several times its source, which on this
compiler is register pressure spilling across a large inlined
function, not the lines themselves. What helped was shape, not
content: shift-TAB decided inside the TAB case rather than by
rewriting the key before the switch; the seconds by a subtracting loop
(a division by a constant is lowered to a multiply and shifts here,
larger than the call to the divider already linked); the note built in
the branch structure it had. Then the line editor's 81-byte row moved
into the failure text's bytes (`LOW_FAIL_TEXT`: no prompt is ever
typed during a fetch, and the failure is in the note before one is).
1,057 bytes for the soft stack.

### 5.16 The first press of B goes to black (2026-09-15)

The machine boots blue, and the background key's first press gave the
next colour up, yellow, where a first press wants dark far more often.
In all four clients (this one, the FTP, SSH and gopher clients, whose
copies of the routine are the same lines) the first press now sets
black unless the background is black already, the text colour skipped
as before, and the rotation goes on from there: 6, 0, 2, 3 on the
machine, the 1 skipped for the white text. The flag and its branch
cost the client 44 bytes and put it under the build's floor again;
the pin record and the random seed's sample buffer, live only at boot
and around a verify, moved onto the scratch line: 1,167 bytes of stack.

### 5.17 GEMINI first on the disk (2026-09-15)

Shift-RUN/STOP runs the first program on the mounted disk, and on
this one that was MEGANET: the build wrote the three images first so
that their sectors stayed put while the bank was being debugged (5.6),
which nothing depends on now. The client is written first, as on the
other clients' disks, and `RUN "*"` — what the key does — reaches the
address prompt.
