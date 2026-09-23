#include "mega65/memory.h"
#include "m65_screen.h"
#include "ui.h"
#include "doc.h"
#include "rnd.h"
#include "pager.h"
#include "marks.h"
#include "save.h"
#include "m65_boot.h"
#include "lowram.h"

#define ROW_FIRST 1
#define ROWS_ON_SCREEN 22
#define ROW_STATUS 23

uint16_t pager_link;
static uint16_t top;                /* the document row on screen row 1 */
static uint16_t sel;                /* the selected link, or 0xffff */
#define text LOW_ROW_TEXT            /* DOC_ROW_TEXT + 1 bytes, low RAM (5.9) */

static void draw_row(uint16_t doc_row_i, uint8_t screen_row)
{
  uint8_t kind;
  uint16_t link;
  doc_row(doc_row_i, &kind, &link, text);
  if (kind == ROW_LINK && link == sel) ui_line_rev(screen_row, text, 0);
  else ui_line(screen_row, text, 0);
}

static void draw_page(void)
{
  uint8_t r;
  uint16_t n = doc_rows();
  for (r = 0; r < ROWS_ON_SCREEN; r++) {
    if (top + r < n) draw_row((uint16_t)(top + r), (uint8_t)(ROW_FIRST + r));
    else ui_line((uint8_t)(ROW_FIRST + r), 0, 0);
  }
}

static void draw_info(const char *note)
{
  char t[80];
  uint8_t n = 0;
  const char *p;
  uint16_t rows = doc_rows(), shown = top + ROWS_ON_SCREEN < rows ? (uint16_t)(top + ROWS_ON_SCREEN) : rows, pct;
  /* shown * 100 / rows in 16 bits (a 32-bit divide is 360 bytes of
   * client): past 655 rows shown, both scaled by 8, near enough for a
   * status row */
  if (!rows) pct = 100;
  else if (shown <= 655) pct = (uint16_t)(shown * 100 / rows);
  else pct = (uint16_t)((shown >> 3) * 100 / (rows >> 3));
  if (note) { for (p = note; *p && n < 60; p++) t[n++] = *p; t[n++] = ' '; t[n++] = ' '; }
  t[n++] = (char)('0' + pct / 100 % 10); if (pct < 100) n--; t[n++] = (char)('0' + pct / 10 % 10); if (pct < 10) n--; t[n++] = (char)('0' + pct % 10); t[n++] = '%';
  if (doc_truncated()) { p = "  (cut)"; while (*p) t[n++] = *p++; }
  t[n] = 0;
  ui_line(ROW_STATUS, t, 0);
}

static void scroll_to(uint16_t row)
{
  uint16_t n = doc_rows();
  if (row + ROWS_ON_SCREEN > n) row = n > ROWS_ON_SCREEN ? (uint16_t)(n - ROWS_ON_SCREEN) : 0;
  top = row;
}

/* The selected link brought into view. */
static void show_selected(void)
{
  uint16_t r;
  if (sel == 0xffff) return;
  r = doc_link_row(sel);
  if (r < top) scroll_to(r);
  else if (r >= top + ROWS_ON_SCREEN) scroll_to((uint16_t)(r - ROWS_ON_SCREEN + 1));
}

/* The first link at or after document row `from`, else 0xffff. */
static uint16_t first_link_from(uint16_t from)
{
  uint16_t i, n = doc_links();
  for (i = 0; i < n; i++) if (doc_link_row(i) >= from) return i;
  return 0xffff;
}

#define KEYS_TEXT "space page  TAB link  RETURN open  STOP back  A address  M mark  S save  Q quit"   /* 79 columns, the row's width: shift-TAB and K go back a link, the README says (5.15) */

/* After a disk write: the screen mode again, and the page. */
static void redraw_all(const char *title, const char *note)
{
  m65_screen_init();
  ui_line(UI_ROW_TITLE, title, 0);
  ui_line(UI_ROW_KEYS, KEYS_TEXT, 0);
  draw_page();
  draw_info(note);
}

static void save_page(const char *title, uint32_t body_off, uint32_t body_end)
{
  char *name = LOW_NAME;                        /* 17 bytes, low RAM (5.9) */
  const char *err;
  save_suggest(title, name);
  ui_status("the SEQ file's name on the boot drive; STOP cancels", 0);
  if (!ui_read_line(ROW_STATUS, "Save as: ", name, 16) || !name[0]) { ui_line(ROW_STATUS, 0, 0); return; }
  ui_status("writing...", 0);
  if (save_body(name, 0, boot_drive, body_off, body_end, &err)) { redraw_all(title, 0); ui_status("saved as ", name); }
  else { redraw_all(title, 0); ui_status("not saved: ", err); }
}

uint8_t pager_show(const char *title, const char *note, uint32_t body_off, uint32_t body_end)
{
  uint8_t k;
  uint16_t rows = doc_rows(), links = doc_links();

  top = 0;
  sel = links ? 0 : 0xffff;
  ui_line(UI_ROW_TITLE, title, 0);
  ui_line(UI_ROW_KEYS, KEYS_TEXT, 0);
  draw_page();
  draw_info(note);
  for (;;) {
    k = ui_wait_key();
    rnd_stir(k);
    if (k >= 0xc1 && k <= 0xda && (ui_last_mods & MOD_MEGA)) k = (uint8_t)(k & 0x7f);
    switch (k) {
    case KEY_DOWN: if (top + ROWS_ON_SCREEN < rows) top++; break;
    case KEY_UP: if (top) top--; break;
    case ' ': case KEY_RIGHT: if (top + ROWS_ON_SCREEN < rows) scroll_to((uint16_t)(top + ROWS_ON_SCREEN)); break;
    case KEY_LEFT: top = top > ROWS_ON_SCREEN ? (uint16_t)(top - ROWS_ON_SCREEN) : 0; break;
    case KEY_HOME: top = 0; sel = links ? 0 : 0xffff; break;
    case KEY_TAB: case 'l': case 'L':
      if (!links) break;
      if (sel == 0xffff || sel + 1 >= links) sel = first_link_from(top);   /* from the top of the view, or wrap */
      else sel++;
      if (sel == 0xffff) sel = 0;
      show_selected();
      break;
    case KEY_SHIFT_TAB: case 'k': case 'K':       /* shift-TAB: $0F on this keyboard (5.15) */
      if (!links) break;
      sel = (sel == 0xffff || sel == 0) ? (uint16_t)(links - 1) : (uint16_t)(sel - 1);
      show_selected();
      break;
    case KEY_RETURN:
      if (sel == 0xffff) break;
      pager_link = sel;
      return PAGER_FOLLOW;
    case KEY_STOP: return PAGER_BACK;
    case 'a': case 'A': return PAGER_ADDRESS;
    case 'h': case 'H': case KEY_HELP: return PAGER_HOME;
    case 'q': case 'Q': return PAGER_QUIT;
    case 'f': case 'F': m65_screen_cycle_text_colour(); ui_line(UI_ROW_TITLE, title, 0); ui_line(UI_ROW_KEYS, KEYS_TEXT, 0); break;
    case 'b': case 'B': m65_screen_cycle_background(); break;
    case 'm': case 'M': {
      /* toggle, as the gopher and FTP clients' M: this page in, or out if it is there */
      unsigned char at = marks_find(title);
      if (at != MARKS_NONE) { unsigned char ok = marks_remove(at); redraw_all(title, note); ui_status(ok ? "bookmark removed" : "could not write GEMMARKS", 0); }
      else if (marks_count >= MARKS_MAX) ui_status("bookmark list full: D and a number at the address prompt deletes one", 0);
      else { unsigned char ok = marks_add(title); redraw_all(title, note); ui_status(ok ? "bookmarked; a number on the address screen opens it" : "could not write GEMMARKS", 0); }
      continue;
    }
    case 's': case 'S': save_page(title, body_off, body_end); continue;
    default: continue;
    }
    draw_page();
    draw_info(note);
  }
}
