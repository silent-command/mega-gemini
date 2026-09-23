/* The three images from the boot disk: MEGANET to bank 4 through the
 * platform's loader, then CRYPTO (the TLS bank) to $12000 and its
 * trampoline to $1700, as the SSH client's ck_boot does; then the
 * bank's INIT. Three tries each: the F011 read path is not perfect. */
#include "mega65/memory.h"
#include "m65_boot.h"
#include "m65_cbmdos.h"
#include "ck_payload.h"
#include "m65_tlskit.h"
#include "boot.h"

#define CK_BASE 0x12000UL
#define CK_RENDER 0x1E000UL
#define CK_TR 0x1700UL

unsigned char boot_bank(const char **err)
{
  unsigned char attempt;
  lcopy((long)(unsigned int)ck_tramp_bin, (long)CK_TR, CK_TRAMP_SIZE);
  /* the map the trampoline restores after each call: this program's, with
   * the KERNAL out of $E000 (m65_own_vectors), not the trampoline's
   * built-in default, which maps it back and hands the next ethernet
   * interrupt to the KERNAL's handler (ssh ckit.c; mega-net 5.18) */
  lpoke(CK_TR + 0x0A, 0x00); lpoke(CK_TR + 0x0B, 0xE0); lpoke(CK_TR + 0x0C, 0x00); lpoke(CK_TR + 0x0D, 0x00);
  for (attempt = 0; attempt < 3; attempt++)
    if (cbmdos_load("CRYPTO", boot_drive, CK_BASE, CK_BIN_SIZE) == CK_BIN_SIZE) break;
  if (attempt == 3) { *err = "CRYPTO not found on the boot disk (or wrong size)"; return 0; }
  if (lpeek(CK_BASE) != 0x4c) { *err = "the TLS bank did not land at $12000"; return 0; }
  for (attempt = 0; attempt < 3; attempt++)
    if (cbmdos_load("RENDER", boot_drive, CK_RENDER, CK_RENDER_SIZE) == CK_RENDER_SIZE) break;
  if (attempt == 3) { *err = "RENDER not found on the boot disk (or wrong size)"; return 0; }
  if (lpeek(CK_TR + 0x0E) != 0x08) { *err = "the bank's trampoline did not land"; return 0; }
  if (!m65_tlskit_init()) { *err = "the TLS bank's INIT failed"; return 0; }
  *err = 0;
  return 1;
}
