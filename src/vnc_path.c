/*
 * vnc_path.c - VNC password file path construction.
 */

#include "vnc_path.h"

#include <errno.h>
#include <stdio.h>

#include "autoconf.h"

/* snprintf only returns < 0  on encoding errors; this format string contains
 * no wide-char conversions. The check is retained as a defensive guard.
 *
 * The `n < 0` sub-expression of each `if (n < 0 || ...)` guard below is
 * structurally unreachable: snprintf with a "%s/%s" or "%s/%s/%s" format and
 * plain char* arguments cannot produce a negative return value on any
 * POSIX-conforming platform. The check is retained as defence-in-depth.
 * LCOV_EXCL_BR is used to suppress the missed-branch report for that arm only;
 * the `(size_t)n >= buflen` arm is exercised by callers that pass a 1-byte
 * buffer.
 */

/*
 * build_vnc_dir_path - Construct the VNC configuration directory path.
 * @home_dir: Absolute path to the user's home directory.
 * @buf:      Output buffer for the constructed path.
 * @buflen:   Size of @buf in bytes.
 *
 * Returns 0 on success, -1 on error (EINVAL: bad args; ERANGE: truncated).
 */
int build_vnc_dir_path(const char *home_dir, char *buf, size_t buflen) {
  int n;

  if (home_dir == NULL || home_dir[0] == '\0' || buf == NULL || buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(buf, buflen, "%s/%s", home_dir, VNC_PASSWD_DIR);
  /* LCOV_EXCL_BR_START - n < 0 unreachable: no wide-char conversions */
  if (n < 0 || (size_t)n >= buflen) {
    /* LCOV_EXCL_BR_STOP */
    errno = ERANGE;
    return -1;
  }

  return 0;
}

/*
 * build_vnc_passwd_path - Construct the VNC password file path.
 * @home_dir: Absolute path to the user's home directory.
 * @buf:      Output buffer for the constructed path.
 * @buflen:   Size of @buf in bytes.
 *
 * Function is too short to be worth wrapping around build_vnc_dir_path
 *
 * Returns 0 on success, -1 on error (EINVAL: bad args; ERANGE: truncated).
 */
int build_vnc_passwd_path(const char *home_dir, char *buf, size_t buflen) {
  int n;

  if (home_dir == NULL || home_dir[0] == '\0' || buf == NULL || buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(buf, buflen, "%s/%s/%s", home_dir, VNC_PASSWD_DIR,
               VNC_PASSWD_FILENAME);
  /* LCOV_EXCL_BR_START - n < 0 unreachable: no wide-char conversions */
  if (n < 0 || (size_t)n >= buflen) {
    /* LCOV_EXCL_BR_STOP */
    errno = ERANGE;
    return -1;
  }

  return 0;
}
