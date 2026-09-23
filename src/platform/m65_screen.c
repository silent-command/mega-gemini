#include "mega65/memory.h"
#include "m65_screen.h"
#include "m65_font.h"
#include "m65_scratch.h"

static unsigned char start_border = 6;
static unsigned char start_bg = 6;
static unsigned char start_text = 1;
/* Set once m65_screen_init() has inherited the machine's colours; from
 * then on this program is the authority, not the hardware registers. */
static unsigned char colours_known = 0;
/* 25 unless the machine was showing 50 when the program started.
 * Read once: m65_screen_init runs again after every disk write, and the
 * height is set by the V400 bit, which this module writes, while the
 * display-rows register it is read from is the ROM's. Re-reading would
 * risk dropping a 50-row session back to 25 mid-run. */
static unsigned char rows = 25;
static unsigned char rows_known = 0;

unsigned char m65_screen_rows(void)
{
  return rows;
}

/* The border and the background out to the hardware. The text colour
 * is this module's own, written by its fills: the clear below, every
 * row put, and the cycle. */
static void apply_colours(void)
{
  POKE(0xd021, start_bg);
  POKE(0xd020, start_border);
}

/* Without conio, since irc step 3. This module stopped printing through
 * cputs in irc 5.24, and what conioinit() still did for it was six
 * pokes and a key-buffer flush -- while linking it cost 765 bytes of
 * escape-code table (`escapeCode`) that nothing here ever read, and a
 * clrscr() that took its size from conio's own idea of the screen. The
 * pokes are here, named; the table is gone. */
void m65_screen_init(void)
{
  POKE(0xd02f, 0x47); POKE(0xd02f, 0x53);          /* the VIC-IV registers in view */
  POKE(0xd05d, PEEK(0xd05d) & 0x7f);               /* hot registers off: the screen is laid out by hand below, and stays put */
  while (PEEK(0xd610)) POKE(0xd610, 0);            /* whatever was typed before the program */

  /* The screen stays where the ROM put it: a native program loads at
   * $2001, so the default screen sits below it. mega-net keeps its socket
   * buffers at $50000-$5E8FF (its README's memory table); anything
   * relocated must avoid them. */

  /* The height the machine was in, kept rather than forced: the ROM's
   * 80x50 (ESC 5) leaves the display-rows register at 49, which is what
   * the SSH client reads too (ssh 5.23). The screen moves to $10000
   * because 50 rows needs 4000 cells and $0800 cannot hold them without
   * running over the trampoline at $1600; see m65_screen.h. */
  if (!rows_known) { rows = (PEEK(0xd07b) == 49) ? 50 : 25; rows_known = 1; }
  POKE(0xd060, (unsigned char)(M65_SCREEN_RAM & 0xff));
  POKE(0xd061, (unsigned char)((M65_SCREEN_RAM >> 8) & 0xff));
  POKE(0xd062, (unsigned char)((M65_SCREEN_RAM >> 16) & 0xff));
  POKE(0xd063, (unsigned char)((PEEK(0xd063) & 0x0f) | ((M65_SCREEN_RAM >> 24) << 4)));
  /* 80 columns (H640) and, for 50 rows, V400 -- the two pokes 5.7 found
   * a program needs, the ROM's display-rows register being the third
   * and already the ROM's */
  POKE(0xd031, (PEEK(0xd031) | 0x80 | (rows == 50 ? 0x08 : 0)) & (rows == 50 ? 0xff : 0xf7));
  POKE(0xd04c, 0x50);                              /* the H640 horizontal position, as conio set it (its "vic-iii positioning bug") */
  m65_font_install();                              /* the lowercase font with \ ^ ` { } ~ drawn in (ssh 5.25) */

  /* with the hot registers off, flipping H640 does not recalculate the
   * row width: set it by hand */
  POKE(0xd058, 80);
  POKE(0xd059, 0);
  POKE(0xd05e, 80);

  /* Establish the colours once.
   *
   * This function is called again after every disk write, which tears the
   * 80-column mode down, so anything decided here must not be re-decided
   * later -- doing so discarded whatever the user had chosen with F.
   *
   * Border and background ARE inherited: the program has never set them,
   * and PEEK from inside the program reads them accurately (blue on blue,
   * matching what the ROM leaves).
   *
   * The text colour is NOT inherited. This used to read $0286, on the
   * assumption that the MEGA65 ROM keeps the current text colour there.
   * It does not. Measured at the BASIC 65 prompt: the screen plainly
   * shows white text, while $0286 reads 14 (light blue) -- and other
   * values at other times, which is why the client started light grey or
   * light blue depending on what had run before. White is what the
   * machine itself displays, so start there. */
  if (!colours_known) {
    start_border = PEEK(0xd020) & 0x0f;
    start_bg = PEEK(0xd021) & 0x0f;
    start_text = 1;                                /* white: what the machine itself shows at its prompt */
    /* Never start invisible, however odd the inherited background is. */
    if (start_text == start_bg)
      start_text = (unsigned char)((start_text + 1) & 0x0f);
    colours_known = 1;
  }

  apply_colours();
  lfill(M65_SCREEN_RAM, 0x20, (unsigned int)rows * 80);
  lfill(M65_COLOUR_RAM, start_text, (unsigned int)rows * 80);
}

unsigned char m65_screen_text_colour(void)
{
  return start_text;
}

void m65_screen_cycle_text_colour(void)
{
  start_text = (unsigned char)((start_text + 1) & 0x0f);
  /* Skip the background colour, or the text would vanish. */
  if (start_text == start_bg)
    start_text = (unsigned char)((start_text + 1) & 0x0f);
  apply_colours();
  /* And every cell already on the screen, or the change shows only on
   * what is drawn next: conio writes colour as it writes characters, so
   * a client that keeps text on screen (a chat, a page, a listing) would
   * see one row change and the rest stay (mega-irc 5.20). In 80x50 this
   * writes through cells 2000-2047, which are also a mapped bank's
   * interrupt vectors at $1FFFA; a bank rewrites those on every entry
   * (mega-irc 5.15) and this runs between calls, never inside one. */
  lfill(M65_COLOUR_RAM, start_text, (unsigned int)rows * 80);
}

/* Advance background and border together, keeping them identical.
 *
 * The border is set from the background rather than tracked separately:
 * the point is that the two always match, so the screen reads as one
 * surface. Skips the current foreground for the same reason the
 * foreground cycle skips the background -- otherwise text disappears. */
void m65_screen_cycle_background(void)
{
  /* The first press goes to black unless the background is black already
   * (the machine boots blue, and a first press wants dark far more often
   * than the next colour up, yellow); the rotation continues from there. */
  static unsigned char pressed;
  if (!pressed && start_bg != 0) start_bg = 0;
  else start_bg = (unsigned char)((start_bg + 1) & 0x0f);
  pressed = 1;
  if (start_bg == start_text)
    start_bg = (unsigned char)((start_bg + 1) & 0x0f);
  start_border = start_bg; /* they are kept identical; see above */
  apply_colours();
}

/* Map one ASCII byte to a screen code, substituting anything we cannot
 * safely display.
 *
 * Text off the network is arbitrary bytes, not ASCII: real gopherpedia
 * articles carry UTF-8 (so bytes >= 0x80) and stray control codes. These
 * used to be passed straight through to screen memory, which corrupted
 * the display and hung the client when a text file was opened. Anything
 * outside the printable ASCII range is now shown as '.' -- a wrong glyph
 * is a cosmetic problem, an unfiltered byte is a crash. */

/* Fold UTF-8 text down to one displayable byte per character.
 *
 * Gopherpedia serves UTF-8, so an accented letter is two bytes. The
 * byte-wise sanitiser turned each of those into '.', which is why
 * "Muhren" appeared as "M..hren" -- two dots for one character. Decoding
 * first means one substitution per character, and letters that have an
 * obvious unaccented form are shown as that letter rather than as a dot.
 *
 * Folding happens before storage so stored line lengths match what is
 * displayed, which keeps truncation and paging honest.
 *
 * Returns the number of bytes written (excluding the terminator). */
static char fold_codepoint(unsigned int cp)
{
  /* Latin-1 letters -> their unaccented ASCII base. */
  if (cp >= 0xc0 && cp <= 0xc5) return 0x41; /* A grave..ring */
  if (cp == 0xc6) return 0x41;               /* AE */
  if (cp == 0xc7) return 0x43;               /* C cedilla */
  if (cp >= 0xc8 && cp <= 0xcb) return 0x45; /* E */
  if (cp >= 0xcc && cp <= 0xcf) return 0x49; /* I */
  if (cp == 0xd1) return 0x4e;               /* N tilde */
  if ((cp >= 0xd2 && cp <= 0xd6) || cp == 0xd8) return 0x4f; /* O */
  if (cp >= 0xd9 && cp <= 0xdc) return 0x55; /* U */
  if (cp == 0xdd) return 0x59;               /* Y acute */
  if (cp == 0xdf) return 0x73;               /* sharp s -> s */
  if (cp >= 0xe0 && cp <= 0xe5) return 0x61; /* a */
  if (cp == 0xe6) return 0x61;               /* ae */
  if (cp == 0xe7) return 0x63;               /* c cedilla */
  if (cp >= 0xe8 && cp <= 0xeb) return 0x65; /* e */
  if (cp >= 0xec && cp <= 0xef) return 0x69; /* i */
  if (cp == 0xf1) return 0x6e;               /* n tilde */
  if ((cp >= 0xf2 && cp <= 0xf6) || cp == 0xf8) return 0x6f; /* o */
  if (cp >= 0xf9 && cp <= 0xfc) return 0x75; /* u */
  if (cp == 0xfd || cp == 0xff) return 0x79; /* y */

  /* Punctuation that turns up constantly in article text. */
  if (cp == 0xa0) return 0x20;                     /* nbsp */
  if (cp == 0x2018 || cp == 0x2019) return 0x27;   /* curly quotes -> ' */
  if (cp == 0x201c || cp == 0x201d) return 0x22;   /* curly quotes -> " */
  if (cp == 0x2013 || cp == 0x2014) return 0x2d;   /* en/em dash -> - */
  if (cp == 0x2026) return 0x2e;                   /* ellipsis -> . */
  if (cp == 0x2022) return 0x2a;                   /* bullet -> * */

  return 0x2e; /* anything else we cannot draw */
}

unsigned char m65_fold_utf8(char *dst, const char *src, unsigned char dstmax)
{
  unsigned char n = 0;
  unsigned char b, need, i;
  unsigned int cp;

  while (*src && n < dstmax) {
    b = (unsigned char)*src++;

    if (b < 0x80) {
      /* plain ASCII; keep printable, replace control codes (incl. tabs) */
      dst[n++] = (b >= 0x20) ? (char)b : 0x20;
      continue;
    }

    if ((b & 0xe0) == 0xc0) { cp = b & 0x1f; need = 1; }
    else if ((b & 0xf0) == 0xe0) { cp = b & 0x0f; need = 2; }
    else if ((b & 0xf8) == 0xf0) { cp = b & 0x07; need = 3; }
    else { dst[n++] = 0x2e; continue; } /* stray continuation byte */

    for (i = 0; i < need; i++) {
      if ((*src & 0xc0) != 0x80) break; /* truncated sequence */
      cp = (cp << 6) | (unsigned char)(*src++ & 0x3f);
    }
    if (i != need) { dst[n++] = 0x2e; continue; }

    dst[n++] = fold_codepoint(cp);
  }

  dst[n] = 0;
  return n;
}

char m65_ascii_to_screencode(char c)
{
  unsigned char u = (unsigned char)c;

  if (u >= 0x41 && u <= 0x5a) /* 'A'-'Z' */
    return (char)u;
  if (u >= 0x61 && u <= 0x7a) /* 'a'-'z' -> screen codes 1-26 */
    return (char)(u - 96);
  if (u >= 0x20 && u <= 0x3f) /* space, digits, common punctuation */
    return (char)u;
  /* Punctuation above 'Z' is NOT screen code = ASCII. In this charset
   * $40/$5b/$5d are the graphics glyphs horizontal-line, '+' and '|', so
   * passing ASCII straight through printed "[DIR]" as "+DIR|" on every
   * menu line and an email address as "mega65<line>use...". Confirmed by
   * PNG capture from hardware, not by the ASCII screenshot round-trip,
   * which maps these back and hides the fault. */
  if (u == 0x40) /* '@' */
    return (char)0x00;
  if (u == 0x5b) /* '[' */
    return (char)0x1b;
  if (u == 0x5d) /* ']' */
    return (char)0x1d;
  if (u == 0x5f) /* '_': no true underscore exists; $64 is a low bar */
    return (char)0x64;
  if (u == 0x5e) /* '^': a caret of its own now (ssh 5.25) */
    return (char)M65_CODE_CARET;
  if (u == 0x7c) /* '|' -> the vertical bar at $5d (what ']' used to hit) */
    return (char)0x5d;
  /* '\\', '`', '{', '}' and '~' have no glyph in the ROM's set; the font
   * in RAM draws them, and the caret, at these codes (m65_font.c). */
  if (u == 0x5c) return (char)M65_CODE_BACKSLASH;
  if (u == 0x60) return (char)M65_CODE_BACKTICK;
  if (u == 0x7b) return (char)M65_CODE_LBRACE;
  if (u == 0x7d) return (char)M65_CODE_RBRACE;
  if (u == 0x7e) return (char)M65_CODE_TILDE;
  return 0x2e; /* '.' for control codes, high-bit bytes, everything else */
}

/* Translated in place through a scratch buffer -- 81 bytes covers a full
 * 80-column line plus terminator, which is the widest thing we ever draw. */
/* Fixed low RAM, not .bss; see m65_scratch.h. */
#define xlate_buf SCR_XLATE

/* Returns the translated length. A length is needed rather than a
 * terminator because '@' translates to screen code $00, which cputs()
 * would read as the end of the string -- an email address on the startup
 * screen would have printed as "mega65". */
static unsigned char xlate(const char *s)
{
  unsigned char i = 0;

  while (s[i] && i < SCR_XLATE_LEN - 1) {
    xlate_buf[i] = m65_ascii_to_screencode(s[i]);
    i++;
  }
  xlate_buf[i] = 0;
  return i;
}

/* Puts xlate_buf[0..n) on the screen at (x, y), cells and colour, by two
 * DMA transfers of a known length.
 *
 * This went through conio's cputs() until the IRC client ran out of room
 * (irc 5.24). cputs() does the same two transfers, but it stops at a NUL,
 * so '@' -- screen code $00 -- had to be split around with a cputc() for
 * each one; and it carries an escape-sequence parser this family never
 * sends an escape to, whose 765-byte buffer sat in every client's .bss.
 * Writing the cells directly drops the splitting and the buffer both.
 *
 * Length, never a terminator: that is what made the '@' safe. A zero
 * length is refused because a zero-length DMAgic transfer means 65536
 * bytes, which is the 64KB scribble the old comment below describes. */
static unsigned char cur_x, cur_y;           /* where m65_puts carries on from */

static void put_xlated(unsigned char x, unsigned char y, unsigned char n)
{
  unsigned long at;

  if (n == 0 || y >= rows || x >= 80)
    return;
  if (n > (unsigned char)(80 - x))
    n = (unsigned char)(80 - x);             /* clipped at the right edge, never wrapped into the next row */
  at = (unsigned long)y * 80 + x;
  lcopy((long)(unsigned int)xlate_buf, (long)(M65_SCREEN_RAM + at), n);
  lfill(M65_COLOUR_RAM + at, start_text, n);
  cur_x = (unsigned char)(x + n);
  cur_y = y;
}

/* Never hand conio an empty string.
 *
 * cputs()/cputsxy() do lcopy(src, dst, len) and lfill(colour, len) with
 * len = strlen(s). A zero length means a zero-length DMAgic transfer,
 * which the hardware treats as 65536 bytes -- so drawing one blank line
 * scribbles 64KB over memory. That is the bug behind the corrupted screen
 * and hung client when opening a text file: real articles contain blank
 * lines, while menu rows always begin with a non-empty "[DIR] "-style
 * marker, which is exactly why menus were never affected and the
 * synthetic test files (no blank lines) never reproduced it. */
void m65_puts(const char *s)
{
  put_xlated(cur_x, cur_y, xlate(s));
}

/* gotoxy() + cputs() rather than cputsxy().
 *
 * mega65-libc's cputsxy() crashes under llvm-mos in native MEGA65 mode --
 * isolated on hardware by a bisect where the only difference between a
 * working and a dead program was positioned vs cursor-based output. This
 * cost real debugging time because the failure looked like a hang deep in
 * the network bring-up: the client happened to use cursor-based output for
 * its early status lines and positioned output only later, so the crash
 * surfaced at a point unrelated to its cause. */
void m65_putsxy(unsigned char x, unsigned char y, const char *s)
{
  put_xlated(x, y, xlate(s));
}
