#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "url.h"
#include "marks.h"

#define MARKS_FILE "GEMMARKS"
#define MARKS_MAGIC "GEMM1"
#define MARKS_FAR 0x11800UL               /* bank 1, above the font copy at $11000 */
#define MARKS_CAP 2048

unsigned char marks_count;
static unsigned int text_len;
static unsigned char marks_drive;
extern char *const doc_line;              /* the scratch line: one line of the text at a time */

/* Copies the line at `at` into `out` (up to cap - 1 characters) and
 * returns the offset just past its newline, or 0xffff at the end. */
static unsigned int read_line(unsigned int at, char *out, unsigned int cap)
{
  unsigned int chunk = text_len - at, i, n = 0;
  if (at >= text_len) return 0xffff;
  if (chunk > URL_MAX + 1) chunk = URL_MAX + 1;
  lcopy(MARKS_FAR + at, (unsigned long)(unsigned int)doc_line, chunk);
  for (i = 0; i < chunk && doc_line[i] != '\n'; i++)
    if (n < cap - 1) out[n++] = doc_line[i];
  out[n] = 0;
  return at + i + 1;                                /* past the newline, or past the end */
}

/* The offset of entry i's line, or 0xffff. */
static unsigned int entry_at(unsigned char i)
{
  unsigned int at;
  unsigned char k;
  char t[2];
  at = read_line(0, t, sizeof t);                   /* the magic line */
  for (k = 0; k < i && at != 0xffff; k++) at = read_line(at, t, sizeof t);
  return at;
}

static void count_entries(void)
{
  unsigned int at = 0;
  unsigned char lines = 0;
  char t[2];
  marks_count = 0;
  while ((at = read_line(at, t, sizeof t)) != 0xffff) lines++;
  if (lines) marks_count = (unsigned char)(lines - 1);
  if (marks_count > MARKS_MAX) marks_count = MARKS_MAX;
}

void marks_load(unsigned char drive)
{
  char magic[8];
  marks_drive = drive;
  text_len = (unsigned int)cbmdos_load(MARKS_FILE, drive, MARKS_FAR, MARKS_CAP);
  marks_count = 0;
  if (!text_len) return;
  read_line(0, magic, sizeof magic);
  { const char *m = MARKS_MAGIC; unsigned char i; for (i = 0; m[i] || magic[i]; i++) if (m[i] != magic[i]) { text_len = 0; return; } }   /* not ours: ignored, not guessed */
  count_entries();
}

unsigned char marks_get(unsigned char i, char *out)
{
  unsigned int at;
  if (i >= marks_count) return 0;
  at = entry_at(i);
  if (at == 0xffff) return 0;
  read_line(at, out, URL_MAX + 1);
  return 1;
}

unsigned char marks_find(const char *url)
{
  unsigned char i;
  unsigned int at;
  for (i = 0; i < marks_count; i++) {
    const char *p = url; unsigned int k;
    at = entry_at(i);
    if (at == 0xffff) break;
    /* compare in place against the far text, through the scratch line */
    { unsigned int chunk = text_len - at; if (chunk > URL_MAX + 1) chunk = URL_MAX + 1;
      lcopy(MARKS_FAR + at, (unsigned long)(unsigned int)doc_line, chunk);
      for (k = 0; k < chunk && doc_line[k] != '\n' && *p && doc_line[k] == *p; k++, p++) ;
      if (!*p && (k == chunk || doc_line[k] == '\n')) return i; }
  }
  return MARKS_NONE;
}

static unsigned char write_file(void)
{
  unsigned int i;
  cbmdos_delete(MARKS_FILE, marks_drive);           /* absent the first time; fine */
  if (cbmdos_create(MARKS_FILE, marks_drive) != CBMDOS_OK) return 0;
  for (i = 0; i < text_len; i++)
    if (cbmdos_put(lpeek(MARKS_FAR + i)) != CBMDOS_OK) { cbmdos_close(); return 0; }
  return cbmdos_close() == CBMDOS_OK;
}

/* Appends one line of the far text. */
static unsigned char put_line(const char *s)
{
  unsigned int n = 0;
  while (s[n]) n++;
  if (text_len + n + 1 > MARKS_CAP) return 0;
  if (n) lcopy((unsigned long)(unsigned int)s, MARKS_FAR + text_len, n);
  lpoke(MARKS_FAR + text_len + n, '\n');
  text_len += n + 1;
  return 1;
}

unsigned char marks_add(const char *url)
{
  unsigned int was = text_len;
  if (marks_count >= MARKS_MAX) return 0;
  if (!text_len && !put_line(MARKS_MAGIC)) return 0;
  if (!put_line(url)) { text_len = was; return 0; }
  marks_count++;
  if (write_file()) return 1;
  text_len = was; count_entries();
  return 0;
}

unsigned char marks_remove(unsigned char i)
{
  unsigned int from, to, tail;
  if (i >= marks_count) return 0;
  from = entry_at(i);
  to = entry_at((unsigned char)(i + 1));
  if (from == 0xffff) return 0;
  if (to == 0xffff) to = text_len;
  tail = text_len - to;
  if (tail) lcopy(MARKS_FAR + to, MARKS_FAR + from, tail);   /* forwards: the destination is below the source */
  text_len -= to - from;
  marks_count--;
  return write_file();
}
