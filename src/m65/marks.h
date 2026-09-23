/* Bookmarks: URLs, one per line, in GEMMARKS on the boot disk, eight
 * at most; the text kept in bank 1 above the font ($11800), as the FTP
 * client keeps its bookmarks (its 5.10). M in the pager toggles the
 * page being read; the address screen lists them by number. */
#ifndef MARKS_H
#define MARKS_H

#define MARKS_MAX 8
#define MARKS_NONE 0xff

extern unsigned char marks_count;

void marks_load(unsigned char drive);
/* The i-th URL into out (URL_MAX + 1 bytes); 0 if there is none. */
unsigned char marks_get(unsigned char i, char *out);
unsigned char marks_find(const char *url);         /* the index, or MARKS_NONE */
unsigned char marks_add(const char *url);          /* 1 if added and written */
unsigned char marks_remove(unsigned char i);       /* 1 if removed and written */

#endif
