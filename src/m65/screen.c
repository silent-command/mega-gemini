/* The 80x25 screen for this client, written directly: the FTP client's
 * module (src/platform/m65_screen.c) with the console library taken
 * out, as the SSH client did, because its output routines and their
 * 765-byte escape buffer were the room this program needed (5.5). The
 * screen stays at $0800, colour RAM at $FF80000; the VIC-IV registers
 * are set by hand (ssh REQUIREMENTS.md 5.23, 5.27). The UTF-8 folding
 * and the screen-code map are the FTP client's, verbatim. */
#include "mega65/memory.h"
#include "m65_screen.h"
#include "m65_font.h"
#include "m65_scratch.h"

#define SCREEN 0x0800UL
#define COLOUR_RAM 0xff80000UL
#define COLS 80

static unsigned char start_border = 6;
static unsigned char start_bg = 6;
static unsigned char start_text = 1;
static unsigned char colours_known = 0;
static unsigned char reverse = 0;

static void apply_colours(void)
{
  POKE(0xd021, start_bg);
  POKE(0xd020, start_border);
}

void m65_screen_init(void)
{
  /* the VIC-IV personality; the hot registers off, so the classic
   * registers stop recomputing the ones set below; the keyboard queue emptied */
  POKE(0xd02f, 0x47); POKE(0xd02f, 0x53);
  POKE(0xd05d, PEEK(0xd05d) & 0x7f);
  while (PEEK(0xd610)) POKE(0xd610, 0);
  /* 80 columns (H640), 25 rows, the screen at $0800 */
  POKE(0xd031, (PEEK(0xd031) | 0x80) & 0xf7); POKE(0xd04c, 0x50);
  POKE(0xd07b, 24);
  POKE(0xd060, 0x00); POKE(0xd061, 0x08); POKE(0xd062, 0x00);
  POKE(0xd063, PEEK(0xd063) & 0xf0);
  m65_font_install();                              /* the lowercase font with \ ^ ` { } ~ drawn in (ssh 5.25) */
  POKE(0xd058, 80); POKE(0xd059, 0); POKE(0xd05e, 80);   /* the row width, by hand */
  if (!colours_known) {
    start_border = PEEK(0xd020) & 0x0f;
    start_bg = PEEK(0xd021) & 0x0f;
    start_text = 1;                                /* white, what the machine itself shows */
    if (start_text == start_bg) start_text = (unsigned char)((start_text + 1) & 0x0f);
    colours_known = 1;
  }
  apply_colours();
  lfill(SCREEN, 0x20, 2000); lfill(COLOUR_RAM, start_text, 2000);
}

unsigned char m65_screen_text_colour(void) { return start_text; }

void m65_screen_cycle_text_colour(void)
{
  start_text = (unsigned char)((start_text + 1) & 0x0f);
  if (start_text == start_bg) start_text = (unsigned char)((start_text + 1) & 0x0f);
  lfill(COLOUR_RAM, start_text, 2000);             /* every cell: nothing here keeps a copy of its text */
}

void m65_screen_cycle_background(void)
{
  /* The first press goes to black unless the background is black already
   * (the machine boots blue, and a first press wants dark far more often
   * than the next colour up, yellow); the rotation continues from there. */
  static unsigned char pressed;
  if (!pressed && start_bg != 0) start_bg = 0;
  else start_bg = (unsigned char)((start_bg + 1) & 0x0f);
  pressed = 1;
  if (start_bg == start_text) start_bg = (unsigned char)((start_bg + 1) & 0x0f);
  start_border = start_bg;
  apply_colours();
}

void m65_screen_reverse(unsigned char on) { reverse = on; }

/* Map one ASCII byte to a screen code, substituting anything we cannot
 * safely display.
 *
 * Text off the network is arbitrary bytes, not ASCII: real gopherpedia
 * articles carry UTF-8 (so bytes >= 0x80) and stray control codes. These
 * used to be passed straight through to screen memory, which corrupted
 * the display and hung the client when a text file was opened. Anything
 * outside the printable ASCII range is now shown as '.' -- a wrong glyph
 * is a cosmetic problem, an unfiltered byte is a crash. */

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

/* Translated through a scratch buffer, then one DMA to the screen. */
#define xlate_buf ((char *)0x1500)   /* 81 bytes at $1500, low RAM (SCR_XLATE, $1C00, is under the send buffer now: 5.8) */

static unsigned char xlate(const char *s)
{
  unsigned char i = 0;
  while (s[i] && i < SCR_XLATE_LEN - 1) {
    xlate_buf[i] = (char)(m65_ascii_to_screencode(s[i]) | (reverse ? 0x80 : 0));
    i++;
  }
  return i;
}

void m65_putsxy(unsigned char x, unsigned char y, const char *s)
{
  unsigned char n = xlate(s);
  if (n == 0) return;                              /* a zero-length DMA would copy 64 KB */
  lcopy((unsigned long)(unsigned int)xlate_buf, SCREEN + (unsigned long)y * COLS + x, n);
}

void m65_puts(const char *s) { m65_putsxy(0, 0, s); }
