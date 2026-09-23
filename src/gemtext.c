#include "gemtext.h"

static uint8_t ws(char c) { return (uint8_t)(c == ' ' || c == '\t'); }

/* Trims leading whitespace off [p, end). */
static const char *skip_ws(const char *p, const char *end)
{
  while (p < end && ws(*p)) p++;
  return p;
}

void gt_classify(gt_state *st, const char *line, uint16_t len, gt_line *out)
{
  const char *end = line + len, *p, *q;

  if (len && line[len - 1] == '\r') { len--; end--; }
  out->kind = GT_TEXT;
  out->text = line; out->text_len = len;
  out->url = 0; out->url_len = 0;

  if (len >= 3 && line[0] == '`' && line[1] == '`' && line[2] == '`') {
    st->pre = (uint8_t)!st->pre;                   /* alt text after the fence is ignored */
    out->kind = GT_TOGGLE; out->text_len = 0;
    return;
  }
  if (st->pre) { out->kind = GT_PRE; return; }

  if (len >= 2 && line[0] == '=' && line[1] == '>') {
    p = skip_ws(line + 2, end);
    for (q = p; q < end && !ws(*q); q++) ;
    out->kind = GT_LINK;
    out->url = p; out->url_len = (uint16_t)(q - p);
    q = skip_ws(q, end);
    if (q < end) { out->text = q; out->text_len = (uint16_t)(end - q); }
    else { out->text = p; out->text_len = out->url_len; }   /* no label: the URL is the label */
    return;
  }
  if (len >= 1 && line[0] == '#') {
    uint8_t n = 1;
    if (len >= 2 && line[1] == '#') { n = 2; if (len >= 3 && line[2] == '#') n = 3; }
    if (len >= n + 1 && line[n] == '#') return;    /* four or more: text */
    out->kind = (uint8_t)(GT_H1 + n - 1);
    p = skip_ws(line + n, end);
    out->text = p; out->text_len = (uint16_t)(end - p);
    return;
  }
  if (len >= 2 && line[0] == '*' && line[1] == ' ') {
    out->kind = GT_LIST;
    p = skip_ws(line + 2, end);
    out->text = p; out->text_len = (uint16_t)(end - p);
    return;
  }
  if (len >= 1 && line[0] == '>') {
    out->kind = GT_QUOTE;
    p = skip_ws(line + 1, end);
    out->text = p; out->text_len = (uint16_t)(end - p);
    return;
  }
}

uint16_t gt_wrap(const char *text, uint16_t len, uint16_t *pos, uint8_t width)
{
  uint16_t start = *pos, n, brk = 0, i;

  if (start >= len) return 0;
  if (len - start <= width) {
    n = (uint16_t)(len - start);
    *pos = len;
  } else {
    for (i = 0; i <= width; i++)                   /* the space at width itself still fits the break */
      if (text[start + i] == ' ') brk = i;
    n = brk ? brk : width;                         /* no space: cut the word */
    *pos = (uint16_t)(start + n);
    while (*pos < len && text[*pos] == ' ') (*pos)++;
  }
  while (n && text[start + n - 1] == ' ') n--;     /* no trailing spaces on a row */
  return n;
}
