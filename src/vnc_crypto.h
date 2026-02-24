/*
 * vnc_crypto.h - Cryptographic buffer size constants.
 *
 * Separated from vnc_path.h to keep path and crypto concerns distinct.
 */

#ifndef VNC_CRYPTO_H
#define VNC_CRYPTO_H

#include <crypt.h> /* CRYPT_OUTPUT_SIZE and CRYPT_GENSALT_OUTPUT_SIZE */
#include <limits.h>

/*
 * VNC_HASH_BUF_SIZE - Buffer large enough for any crypt(3) output string.
 * VNC_SALT_BUF_SIZE - Buffer large enough for any crypt(3) salt.
 */
enum {
  VNC_HASH_BUF_SIZE = CRYPT_OUTPUT_SIZE,
  VNC_SALT_BUF_SIZE = CRYPT_GENSALT_OUTPUT_SIZE,
};

_Static_assert(VNC_HASH_BUF_SIZE > 0, "hash buffer size is 0");
_Static_assert(VNC_HASH_BUF_SIZE <= INT_MAX,
               "hash buffer exceeds fgets limit!");
_Static_assert(VNC_SALT_BUF_SIZE <= INT_MAX,
               "salt buffer exceeds fgets limit!");
_Static_assert(VNC_SALT_BUF_SIZE > 0, "salt buffer size is 0");

#endif /* VNC_CRYPTO_H */
