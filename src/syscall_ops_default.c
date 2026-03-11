/*
 * syscall_ops_default.c - Production system call implementation.
 *
 * Maps each syscall_ops function pointer to the corresponding POSIX or C
 * library function. Separating the concrete implementation from the abstract
 * interface (syscall_ops.h) lets production code link against real system
 * calls while test code links against mock implementations.
 *
 * When adding a new system call dependency:
 *   1. Add the function pointer to struct syscall_ops in syscall_ops.h.
 *   2. Add the mapping here in syscall_ops_default.
 *   3. Update test mocks as needed.
 */

#include <crypt.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "syscall_ops.h"

/*
 * syscall_ops_default - Global production syscall implementation.
 *
 * Uses C99 designated initializers so additions, removals, and reorderings
 * are independent: the field name at each site makes the mapping
 * self-documenting and any typo is a compile error.
 *
 * Declared const so the structure is placed in .rodata (write-protected) and
 * safe to share across threads without synchronization. Defined here (not in
 * the header) to avoid multiple-definition errors across translation units.
 */
const struct syscall_ops syscall_ops_default = {
    /* File operations. */
    .open = open,
    .close = close,
    .fstat = fstat,
    .stat = stat,
    .fdopen = fdopen,
    .fclose = fclose,
    .fgets = fgets,

    /* Directory operations. */
    .mkdir = mkdir,

    /* Atomic file write operations. */
    .mkostemp = mkostemp,
    .fchmod = fchmod,
    .fsync = fsync,
    .rename = rename,
    .unlink = unlink,
    .write = write,

    /* User database operations. */
    .getpwnam_r = getpwnam_r,
    .getpwuid_r = getpwuid_r,

    /* Entropy generation. */
    .getrandom = getrandom,

    /* Cryptographic operations. */
    .crypt_gensalt_ra = crypt_gensalt_ra,
    .crypt_checksalt = crypt_checksalt,
    .crypt_r = crypt_r,

    /* Memory management. */
    .calloc = calloc,
};
