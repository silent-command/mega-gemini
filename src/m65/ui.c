#include "mega65/memory.h"
#include "m65_screen.h"
#include "netutil.h"
#include "ui.h"
#include "lowram.h"

void (*ui_idle)(void);
unsigned char ui_last_mods;

#define row_buf LOW_ROW_BUF                  /* 81 bytes, low RAM (5.9) */
static unsigned char last_frame;

unsigned char ui_key(void)
{
  unsigned char k = PEEK(0xd610);
  if (k) { ui_last_mods = PEEK(0xd611); POKE(0xd610, 0); }   /* the modifiers, then the pop */
  return k;
}

unsigned char ui_wait_key(void)
{
  unsigned char k;
  for (;;) {
    k = ui_key();
    if (k) return k;
    net_poll();
    if (PEEK(0xd7fa) != last_frame) {
      last_frame = PEEK(0xd7fa);
      if (ui_idle) ui_idle();
    }
  }
}

/* Builds a+b padded with spaces to 79 columns: an 80th character would
 * wrap onto the next row and overwrite it. */
static void build_row(const char *a, const char *b)
{
  unsigned char n = 0;
  if (a) while (*a && n < 79) row_buf[n++] = *a++;
  if (b) while (*b && n < 79) row_buf[n++] = *b++;
  while (n < 79) row_buf[n++] = ' ';
  row_buf[n] = 0;
}

void ui_line(unsigned char row, const char *a, const char *b)
{
  build_row(a, b);
  m65_putsxy(0, row, row_buf);
}

void ui_line_rev(unsigned char row, const char *a, const char *b)
{
  build_row(a, b);
  m65_screen_reverse(1);
  m65_putsxy(0, row, row_buf);
  m65_screen_reverse(0);
}

void ui_status(const char *a, const char *b)
{
  ui_line(UI_ROW_STATUS, a, b);
}

void ui_clear_rows(unsigned char from, unsigned char to)
{
  while (from <= to) { ui_line(from, 0, 0); from++; }
}

unsigned char ui_read_line(unsigned char row, const char *prompt, char *out, unsigned int maxlen)
{
#define shown LOW_FAIL_TEXT                 /* the failure text's 80 bytes: never a prompt during a fetch, and the text is in the note before any prompt (5.15) */
  unsigned int len, from;
  unsigned char key, n;
  unsigned char fresh = 1;                      /* the default is still untouched */
  const char *p;

  out[maxlen] = 0;
  for (len = 0; out[len]; len++) ;
  for (;;) {
    n = 0;
    for (p = prompt; *p && n < 78; p++) shown[n++] = *p;
    from = len + n > 77 ? len + n - 77 : 0;      /* a long line shows its tail */
    for (p = out + from; *p && n < 77; p++) shown[n++] = *p;
    shown[n++] = '_';
    shown[n] = 0;
    ui_line(row, shown, 0);

    key = ui_wait_key();
    if (key == KEY_RETURN) return 1;
    if (key == KEY_STOP) return 0;
    if (key == KEY_DEL) { fresh = 0; if (len) out[--len] = 0; continue; }
    if (key >= 0x20 && key < 0x7f) {
      if (fresh) { len = 0; fresh = 0; }         /* typing replaces the offered default */
      if (len < maxlen) { out[len++] = (char)key; out[len] = 0; }
    }
  }
}

static unsigned char spin_frame;

void ui_spin(void)
{
  static const char glyphs[4] = { '.', 'o', 'O', 'o' };
  char s[2];
  if (++spin_frame & 7) return;
  s[0] = glyphs[(spin_frame >> 3) & 3];
  s[1] = 0;
  m65_putsxy(79, UI_ROW_TITLE, s);
}

void ui_spin_clear(void)
{
  m65_putsxy(79, UI_ROW_TITLE, " ");
}

void ui_put_ulong(char *p, unsigned long v)
{
  char t[11];
  unsigned char n = 0;
  do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  while (n) *p++ = t[--n];
  *p = 0;
}
