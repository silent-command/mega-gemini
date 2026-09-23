/* The TLS bank: a raw, headerless image in bank 1 at physical $12000,
 * executed with bank 1 mapped over CPU $2000-$BFFF (and its top 8 KB,
 * $1E000-$1FFFF, over $E000-$FFFF for the interrupt vectors in force
 * during a call). The SSH client's bank, without its terminal window
 * (ssh REQUIREMENTS.md 5.4, 5.7; mega-net 5.7, 5.10, 5.11).
 *
 * $2000-$BDFF is code and data; $BE00-$BFFF the bank's own soft stack;
 * $E000-$F7FF the renderer (RENDER, a second file, loaded to $1E000).
 * The vectors at $FFF0 are written by INIT into the colour-RAM mirror
 * past the screen's 2000 cells, where they survive (ssh 5.7). Physical $1C000-$1DFFF, between the stack and the
 * window, is the client's line index (see the project notes). */
MEMORY {
    ram (rw) : ORIGIN = 0x2000, LENGTH = 0x9E00
    hi (rwx) : ORIGIN = 0xE000, LENGTH = 0x1800
}

/* Zero page $68-$FF, swapped with the caller's on every call, as
 * mega-net does with $90-$FF: each saves what it finds and puts it
 * back, so the bank nests inside the client and mega-net's POLL nests
 * inside the bank. Eight bytes more than the SSH client's $70: the
 * multiplier's 16-bit row once walked three zero-page pointers (5.6);
 * the 32-bit row that replaced it patches addresses instead (5.12). */
__rc0 = 0x68;
INCLUDE imag-regs.ld
MEMORY { zp : ORIGIN = __rc31 + 1, LENGTH = 0x100 - (__rc31 + 1) }

REGION_ALIAS("c_readonly", ram)
REGION_ALIAS("c_writeable", ram)

__stack = 0xC000;

SECTIONS {
    .jumptable : { KEEP(*(.jumptable)) } > ram
    /* The renderer and the gemtext parser in the top window ($1E000-
     * $1F7FF; $1F800 up is the colour-RAM mirror, ssh 5.7), code and
     * data: the window is the second image, RENDER. The objects are
     * compiled without LTO so they can be named here. */
    .text.hi : { *render.o(.text .text.* .rodata .rodata.*) *gemtext.o(.text .text.* .rodata .rodata.*) } > hi
    .bss.hi (NOLOAD) : { *render.o(.bss .bss.*) *render.o(.noinit .noinit.*) *gemtext.o(.noinit .noinit.*) *jumptable*.o(.noinit .noinit.*) } > hi
    INCLUDE c.ld
}

/* The whole first region, then the second trimmed: build.py splits the
 * file at 0x9E00 into CRYPTO and RENDER. */
OUTPUT_FORMAT { FULL(ram) TRIM(hi) }
