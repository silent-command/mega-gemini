#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "doc.h"
#include "save.h"

void save_suggest(const char *url, char *out)
{
  const char *p = url, *seg = url;
  uint8_t n = 0;
  for (; *p; p++) if (*p == '/' && p[1] && p[1] != '?') seg = p + 1;   /* the last segment */
  if (*seg == '/' ) seg++;
  for (p = seg; *p && *p != '?' && *p != '#' && n < 16; p++) {
    char c = *p;
    if (c >= 'a' && c <= 'z') c = (char)(c - 32);
    if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) out[n++] = c;
    else if (c == '/') break;
    else out[n++] = '-';
  }
  if (!n) { out[0] = 'P'; out[1] = 'A'; out[2] = 'G'; out[3] = 'E'; n = 4; }
  out[n] = 0;
}

uint8_t save_body(const char *name, uint8_t prg, unsigned char drive, uint32_t from, uint32_t to, const char **err)
{
  uint32_t at = from, len = to;
  uint16_t take, i;
  unsigned char r;
  uint8_t *buf = (uint8_t *)doc_scratch;           /* dead outside a render or a fetch */
  cbmdos_delete(name, drive);
  r = cbmdos_create_as(name, drive, prg ? CBMDOS_TYPE_PRG : CBMDOS_TYPE_SEQ);
  if (r != CBMDOS_OK) { *err = r == CBMDOS_ERR_PROT ? "the disk is write protected" : r == CBMDOS_ERR_DIRFULL ? "the directory is full" : "could not create the file"; return 0; }
  while (at < len) {
    take = len - at < 256 ? (uint16_t)(len - at) : 256;
    doc_raw_read(at, buf, take);
    for (i = 0; i < take; i++)
      if (cbmdos_put(buf[i]) != CBMDOS_OK) { cbmdos_close(); *err = "the disk is full"; return 0; }
    at += take;
  }
  if (cbmdos_close() != CBMDOS_OK) { *err = "the file could not be closed"; return 0; }
  *err = 0;
  return 1;
}
