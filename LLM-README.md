# mega-gemini

A Gemini client for the [MEGA65](https://mega65.org), written in C for
llvm-mos, running in native MEGA65 mode on [mega-net](../mega-net):
TLS 1.3 with the server's key pinned on first use, gemtext on the
80-column screen.

**Status: working.** The client fetches pages from live Gemini
servers on the MEGA65 with the server's signature verified — P-256,
RSA-2048 and RSA-4096, the last in about 5.5 seconds on a
Montgomery multiplier that runs on the CPU's 32-bit math registers
(REQUIREMENTS.md 5.12). It follows links and goes back (from a cache
of the last four pages, at once); a page from geminiprotocol.net takes
about 12 seconds (5.6, 5.8, 5.10). The pinned keys and the bookmarks are kept on the boot disk
(GEMHOSTS, GEMMARKS), and a page can be saved. Not yet: saving a
non-text file, client certificates.

## Using it

`bin/GEMINI.D81` holds the client, the TLS bank, its renderer and
mega-net. Mount it and press shift-RUN/STOP (GEMINI is the first
program on the disk), or `RUN "GEMINI"`, and type an address
(`geminiprotocol.net`, or a full `gemini://` URL). The status row says
what the handshake found: "verified" when the server's signature
checked, "UNCHECKED" when its scheme is one this client cannot verify
(P-384 today), with the seconds the handshake's arithmetic took, and
"key pinned" the first time a server is seen. The pins
are written to GEMHOSTS on the boot disk, so a fresh copy of the disk
starts with none. A server whose key has changed since it was pinned
is refused with a warning.

| Key | Does |
|---|---|
| cursor up/down | scroll a row |
| space or right, left | a page down, up |
| TAB or L; shift-TAB or K | the next link; the previous |
| RETURN | follow the selected link |
| RUN/STOP | back |
| A | type an address; the bookmarks are listed there, a number opens one, D and the number deletes it |
| M | bookmark this page, or remove it (eight at most, in GEMMARKS on the boot disk) |
| S | save the page as a SEQ file on the boot disk, the name suggested from the address |
| H or HELP | the home page (geminiprotocol.net) |
| F, B | text colour; background and border (the first press of B: black) |
| Q | leave for BASIC's READY, the disk still mounted |

A status 10 or 11 asks you a line and sends it as the query; redirects
are followed (five at most); other statuses are shown in words.
Documents other than text are not saved yet.

## Building

Needs [llvm-mos](https://llvm-mos.org), CMake, `c1541` from VICE, Python 3,
and two sibling checkouts: `../mega-net` and
`../mega65-libc` (github.com/MEGA65/mega65-libc).

```
python3 build.py test         the host suites (gemtext, Gemini, crypto, signatures, TLS)
python3 build.py              the TLS bank, the client and bin/GEMINI.D81
python3 build.py hostclient   build/host/tls_host URL: a page fetched on the host through the same TLS code
```

`tools/gemini_test_server.py` serves a test site with the awkward
cases (inputs, redirects, a redirect loop, a big page, binary, a server
that never answers); `build.py certs` makes its certificates.

## License

0BSD, see `LICENSE`. mega-net is a separate project under the same
license; mega65-libc is under its own. The `m65_*` platform modules are
shared with the gopher, FTP, SSH and NTP clients; the cryptographic
primitives and the bank's trampoline are the SSH client's.
