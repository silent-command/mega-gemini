#ifndef BOOT_H
#define BOOT_H
/* Loads CRYPTO from the drive MEGANET came from, and runs its INIT.
 * After m65_boot_load(). Returns 0 with a message. */
unsigned char boot_bank(const char **err);
#endif
