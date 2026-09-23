/* 80-column screen setup for the gopher client. See REQUIREMENTS.md
 * section 7 for the full story on why each of these steps exists --
 * skipping any of them causes either screen corruption (bad screen RAM
 * placement), a visual 40-column wrap despite being in 80-column pixel
 * mode (missing row-width register pokes), or interleaved garbled text
 * (mixing stdio printf()/puts() with conio cputc()/cputs()).
 *
 * RULE: once m65_screen_init() has run, never call stdio's printf()
 * or puts() again. For dynamic text, sprintf() into a local buffer then
 * display with cprintf() (cast to const unsigned char*) -- cputs()
 * doesn't interpret '\n', only cprintf()/_cprintf() does. */
#ifndef M65_SCREEN_H
#define M65_SCREEN_H

void m65_screen_init(void);

/* Where the screen lives. Not $0800: at 50 rows the screen is 4000
 * cells, and 4000 from $0800 runs to $179F, over mega-net's trampoline
 * at $1600. So it sits in bank 1 at $10000, ending at $10F9F, just
 * below the font at $11000 (ssh 5.23 found this first). conio reads the
 * base out of the VIC registers rather than assuming one, so its own
 * output follows wherever this points. */
#define M65_SCREEN_RAM 0x10000UL

/* 25 or 50: the rows the machine was showing when the program started.
 * The layout follows the machine rather than forcing a height. */
unsigned char m65_screen_rows(void);


#endif

/* Literal-safe text output.
 *
 * CC65's charmap rewrites C string literals into screen codes at compile
 * time, so under CC65 a literal can go straight to cputs(). llvm-mos does
 * no such rewriting -- literals stay plain ASCII and render as garbage for
 * lowercase (uppercase happens to survive, which makes this easy to miss).
 * These wrappers translate at runtime where the toolchain doesn't, so
 * callers can pass ordinary C strings in either build.
 *
 * Network-sourced text is raw ASCII in BOTH builds and is translated by
 * its own caller; that asymmetry between literals and network data is the
 * root of R-5, R-6 and the title-bar bug. */
void m65_puts(const char *s);
void m65_putsxy(unsigned char x, unsigned char y, const char *s);
char m65_ascii_to_screencode(char c);

/* Colour handling: border and background are inherited from whatever the
 * user had set before running (the program never writes $d020/$d021), and
 * the text colour is taken from the ROM's current-colour byte at $0286
 * rather than forced to white. */
unsigned char m65_screen_text_colour(void);
void m65_screen_cycle_text_colour(void);

/* Advances background and border together, keeping them identical. */
void m65_screen_cycle_background(void);

/* Reverse video for what is drawn from now on (the client's screen.c). */
void m65_screen_reverse(unsigned char on);

/* Folds UTF-8 into one displayable byte per character (see the long note
 * in m65_screen.c). dst must hold dstmax+1 bytes. */
unsigned char m65_fold_utf8(char *dst, const char *src, unsigned char dstmax);
