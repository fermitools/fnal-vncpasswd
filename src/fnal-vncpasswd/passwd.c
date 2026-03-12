/*
 * fnal-vncpasswd/passwd.c - VNC password file operations.
 *
 * Implements password hashing, directory creation, and atomic file write.
 * Every path that touches sensitive material (passwords, hashes, salts) calls
 * explicit_bzero() before returning, successful or not.
 */

#include "passwd.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/restorecon.h>
#include <selinux/selinux.h>
#include <stdarg.h>

static int noop_selinux_log(int type, const char *fmt, ...) {
  (void)type;
  (void)fmt;
  return 0;
}
#endif

#include "syscall_ops.h"
#include "vnc_path.h"

/*
 * Forward declarations.
 *
 * nonnull is safe here because these functions are file-scope only; each
 * public entry point validates its pointer arguments before delegating.
 */

static int crypt_and_copy(const struct syscall_ops *ops,
                          char salt[static CRYPT_GENSALT_OUTPUT_SIZE],
                          const char *password, char *hash_buf, size_t hash_len)
    __attribute__((warn_unused_result)) __attribute__((nonnull(1, 2, 3, 4)));

static const char *select_prefix(const struct syscall_ops *ops)
    __attribute__((warn_unused_result)) __attribute__((nonnull(1)));

static int generate_salt(const struct syscall_ops *ops, char *salt_buf,
                         size_t salt_len) __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 2)));

static int make_one_dir(const struct syscall_ops *ops, const char *path)
    __attribute__((warn_unused_result)) __attribute__((nonnull(1, 2)));

/*
 * Algorithm preference list for select_prefix().
 *
 * Ordered from most to least preferred. libxcrypt will reject any algorithm
 * unavailable in the current configuration (e.g. yescrypt under FIPS).
 * crypt_checksalt(3) requires a full example salt rather than just the prefix,
 * so select_prefix() generates a probe salt for each entry to test with.
 *
 * NULL as a prefix means "use the libxcrypt compiled-in default" (yescrypt on
 * RHEL 9+). It appears first so that operator build-time policy takes priority
 * when it is also acceptable to crypt_checksalt(3).
 *
 * SALT_PREFIXES_COUNT must equal the number of entries in salt_prefixes[].
 * A count-based bound is used instead of a NULL sentinel because NULL is a
 * valid prefix value; a NULL-terminated loop would silently skip the last
 * real entry.
 *
 * The list is stable: libxcrypt has not added a new algorithm in years and has
 * no plans to do so. A future RHEL dropping an entry causes select_prefix() to
 * skip it harmlessly via a NULL return from crypt_gensalt_ra().
 */
static const char * const salt_prefixes[] = {
    NULL,   /* libxcrypt compiled-in default */
    "$y$",  /* yescrypt */
    "$2b$", /* bcrypt */
    "$6$",  /* sha512crypt */
    "$5$",  /* sha256crypt */
};
#define SALT_PREFIXES_COUNT (sizeof(salt_prefixes) / sizeof(salt_prefixes[0]))
_Static_assert(SALT_PREFIXES_COUNT > 0, "salt_prefixes must not be empty");

/* Password file path resolution */

/*
 * get_passwd_path - Build the VNC password file path for a given UID.
 * @ops:    Syscall operations.
 * @uid:    UID to look up; callers pass getuid().
 * @buf:    Output buffer for the constructed path.
 * @buflen: Size of @buf. PATH_MAX is always sufficient.
 */

int get_passwd_path(const struct syscall_ops *ops, uid_t uid, char *buf,
                    size_t buflen) {
  char vnc_dir[PATH_MAX] = {0};
  struct passwd pw = {0};
  struct passwd *pwresult = NULL;

  if (ops == NULL || buf == NULL || buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  long pw_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

  // LCOV_EXCL_START
  /*
    sysconf(_SC_GETPW_R_SIZE_MAX) returning <= 0 or overflowing size_t cannot
   * be triggered in a normal test environment; it would indicate a severely
   * broken libc or kernel.
   */
  if (pw_bufsize <= 0 || (unsigned long)pw_bufsize > (SIZE_MAX / 2)) {
    errno = ERANGE;
    return -1;
  }
  // LCOV_EXCL_STOP

  char *pwbuf = ops->calloc(1, (size_t)pw_bufsize);
  if (pwbuf == NULL) {
    errno = ENOMEM;
    return -1;
  }

  int rc = ops->getpwuid_r(uid, &pw, pwbuf, (size_t)pw_bufsize, &pwresult);
  if (rc != 0 || pwresult == NULL) {
    free(pwbuf);
    errno = (rc != 0) ? rc : ENOENT;
    return -1;
  }

  /*
   * pw.pw_dir points into pwbuf. Both build_vnc_dir_path() and
   * ensure_vnc_dir() must complete before we free pwbuf.
   */
  // LCOV_EXCL_START - tested extensivly elsewhere
  if (build_vnc_dir_path(pw.pw_dir, vnc_dir, sizeof(vnc_dir)) < 0 ||
      ensure_vnc_dir(ops, vnc_dir) < 0) {
    free(pwbuf);
    return -1;
  }
  // LCOV_EXCL_STOP

  rc = build_vnc_passwd_path(pw.pw_dir, buf, buflen);
  free(pwbuf);
  return rc;
}

/* Password hashing */

/*
 * select_prefix - Return the best crypt algorithm prefix available at runtime.
 * @ops: Syscall operations.
 *
 * libxcrypt provides no API to enumerate supported or FIPS-approved algorithms;
 * crypt_checksalt(3) is the only runtime probe. We iterate salt_prefixes[] from
 * strongest to weakest, generate a candidate salt for each entry, and accept the
 * first one crypt_checksalt(3) approves. This handles FIPS and non-FIPS systems
 * without build-time conditionals or /proc inspection.
 *
 * If crypt_gensalt_ra() returns NULL for a given prefix (unsupported algorithm),
 * that entry is skipped without calling crypt_checksalt(3). If all probes fail
 * or are rejected, "$6$" (sha512crypt) is returned as a last-resort fallback
 * because it is the strongest FIPS-approved algorithm present across all target
 * RHEL versions.
 *
 * Entropy is sourced internally by libxcrypt (rbytes=NULL, nrbytes=0).
 * Passing caller-supplied entropy triggers a validation bug in libxcrypt
 * < 4.4.26 (RHEL 8/9 ship 4.4.18).
 *
 * Returns a string literal prefix, never NULL.
 */
static const char *select_prefix(const struct syscall_ops *ops) {
  for (size_t i = 0; i < SALT_PREFIXES_COUNT; i++) {
    char *probe = ops->crypt_gensalt_ra(salt_prefixes[i], 0, NULL, 0);
    if (probe == NULL) {
      continue;
    }
    int ok = ops->crypt_checksalt(probe);
    explicit_bzero(probe, strlen(probe));
    free(probe);
    if (ok == 0) {
      return salt_prefixes[i];
    }
  }
  return "$6$"; /* last-resort fallback */
}

/*
 * generate_salt - Fill a salt buffer using the best available algorithm.
 * @ops:      Syscall operations.
 * @salt_buf: Output buffer; CRYPT_GENSALT_OUTPUT_SIZE bytes is sufficient.
 * @salt_len: Size of @salt_buf.
 *
 * Delegates algorithm selection to select_prefix(), which probes libxcrypt
 * at runtime via crypt_checksalt(3).
 *
 * Returns 0 on success, -1 on error (errno set).
 */
static int generate_salt(const struct syscall_ops *ops, char *salt_buf,
                         size_t salt_len) {
  char *salt = NULL;
  size_t slen = 0;

  salt = ops->crypt_gensalt_ra(select_prefix(ops), 0, NULL, 0);
  if (salt == NULL) {
    errno = EINVAL;
    return -1;
  }

  slen = strlen(salt);

  // LCOV_EXCL_START
  /*
   * Should never happen: CRYPT_GENSALT_OUTPUT_SIZE is guaranteed large enough
   * for any algorithm libxcrypt supports. Treat as a hard error rather than
   * silently truncating a salt string.
   */
  if (slen >= salt_len) {
    explicit_bzero(salt, slen + 1);
    free(salt);
    errno = ERANGE;
    return -1;
  }
  // LCOV_EXCL_STOP

  memcpy(salt_buf, salt, slen + 1);
  explicit_bzero(salt, slen + 1);
  free(salt);
  return 0;
}

/*
 * crypt_and_copy - Hash @password with @salt, copy result to @hash_buf.
 * @ops:      Syscall operations.
 * @salt:     Salt string from generate_salt().
 * @password: Plaintext password.
 * @hash_buf: Output buffer; VNC_HASH_BUF_SIZE bytes is sufficient.
 * @hash_len: Size of @hash_buf.
 *
 * crypt_r(3) signals failure in two ways:
 *   - Returns NULL: hard error (unsupported algorithm, internal fault).
 *   - Returns a string starting with '*': invalid setting or bad salt.
 * Both produce an unusable hash that must never be written to disk.
 *
 * @hash_buf is zeroed on any error path to prevent a partial or garbage hash
 * from persisting in the caller's stack frame.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
static int crypt_and_copy(const struct syscall_ops *ops,
                          char salt[static CRYPT_GENSALT_OUTPUT_SIZE],
                          const char *password, char *hash_buf,
                          size_t hash_len) {
  struct crypt_data cd = {0};
  char *result = NULL;
  int n = 0;

  result = ops->crypt_r(password, salt, &cd);
  if (result == NULL || result[0] == '*') {
    explicit_bzero(&cd, sizeof(cd));
    errno = EINVAL;
    return -1;
  }

  n = snprintf(hash_buf, hash_len, "%s", result);

  /* result points into cd.output and is not used after this point. */
  explicit_bzero(&cd, sizeof(cd));

  /* LCOV_EXCL_BR_START - n < 0 unreachable: no wide-char conversions */
  if (n < 0 || (size_t)n >= hash_len) {
    /* LCOV_EXCL_BR_STOP */
    /*
     * snprintf wrote a truncated hash; zero it to prevent the partial value
     * from being mistaken for a valid hash by the caller.
     */
    explicit_bzero(hash_buf, hash_len);
    errno = ERANGE;
    return -1;
  }

  return 0;
}

/*
 * hash_password - Hash a plaintext password using crypt_r(3).
 * @ops:      Syscall operations.
 * @password: Plaintext password (NUL-terminated, non-empty).
 * @hash_buf: Output buffer; VNC_HASH_BUF_SIZE bytes is always sufficient.
 * @hash_len: Size of @hash_buf.
 */
int hash_password(const struct syscall_ops *ops, const char *password,
                  char *hash_buf, size_t hash_len) {
  char salt[CRYPT_GENSALT_OUTPUT_SIZE] = {0};

  if (ops == NULL || password == NULL || hash_buf == NULL ||
      password[0] == '\0' || hash_len == 0) {
    errno = EINVAL;
    return -1;
  }

  if (generate_salt(ops, salt, sizeof(salt)) < 0) {
    explicit_bzero(salt, sizeof(salt));
    return -1;
  }

  int rc = crypt_and_copy(ops, salt, password, hash_buf, hash_len);
  explicit_bzero(salt, sizeof(salt));
  return rc;
}

/* Directory management */

/*
 * make_one_dir - Create a single directory component, tolerating EEXIST.
 * @ops:  Syscall operations.
 * @path: Path of the single component to create.
 *
 * If the path already exists as a directory or symlink, returns success.
 * Symlinks are accepted because stat(2) follows them: a symlink to a
 * directory returns S_IFDIR, and a dangling symlink returns S_IFLNK. Both
 * are valid managed-path configurations (e.g. ~/.config/vnc -> /net/vnc).
 * If it exists but is a non-symlink non-directory (regular file, socket,
 * etc.), returns -1 (errno = ENOTDIR). On EEXIST from mkdir(2), re-stats
 * to confirm the racing creator also made a directory or symlink rather
 * than a regular file.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
static int make_one_dir(const struct syscall_ops *ops, const char *path) {
  struct stat st;

  if (ops->stat(path, &st) == 0) {
    if (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
      errno = ENOTDIR;
      return -1;
    }
    return 0; /* Already exists as a directory or symlink. */
  }

  if (errno != ENOENT) {
    return -1;
  }

  if (ops->mkdir(path, 0700) == 0) {
    return 0;
  }

  /*
   * EEXIST: another process created something here between our stat() and
   * mkdir(). Re-stat to verify it is actually a directory or symlink.
   */
  if (errno != EEXIST) {
    fprintf(stderr, "fnal-vncpasswd: mkdir %s: %s\n", path, strerror(errno));
    return -1;
  }

  if (ops->stat(path, &st) < 0) {
    return -1;
  }

  if (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  return 0;
}

/*
 * ensure_vnc_dir - Create the VNC configuration directory if absent.
 * @ops:  Syscall operations.
 * @path: Absolute path to create (e.g. /home/user/.config/vnc).
 */
int ensure_vnc_dir(const struct syscall_ops *ops, const char *path) {
  char tmp[PATH_MAX] = {0};
  char *p = NULL;
  size_t plen = 0;
  int n = 0;

  if (ops == NULL || path == NULL || path[0] != '/') {
    errno = EINVAL;
    return -1;
  }

  /*
   * Reject paths containing ".." as defence-in-depth. VNC paths are assembled
   * from pw_dir (system password database) and VNC_PASSWD_DIR (build-time
   * constant); neither should contain ".." under normal operation. We don't
   * use realpath(3) here because the path may not exist yet.
   *
   * Checks cover all positions where ".." can appear as a complete path
   * component: internal (/../) and trailing (/..). The leading '/' is already
   * ensured above.
   */
  plen = strlen(path);
  if (strstr(path, "/../") != NULL ||
      (plen >= 3 && strcmp(path + plen - 3, "/..") == 0)) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(tmp, sizeof(tmp), "%s", path);
  /* LCOV_EXCL_BR_START - n < 0 unreachable: no wide-char conversions */
  if (n < 0 || (size_t)n >= sizeof(tmp)) {
    /* LCOV_EXCL_BR_STOP */
    errno = ERANGE;
    return -1;
  }

  /*
   * Walk each intermediate path component by temporarily replacing each '/'
   * separator with '\0', calling make_one_dir(), then restoring it.
   * Start from tmp+1 to skip the leading '/' of the absolute path.
   */
  for (p = tmp + 1; *p != '\0'; p++) {
    if (*p != '/') {
      continue;
    }

    *p = '\0';
    if (make_one_dir(ops, tmp) < 0) {
      return -1;
    }
    *p = '/';
  }

  /* Final component (no trailing '/' to strip). */
  return make_one_dir(ops, tmp);
}

/* Atomic password file write */

/*
 * atomic_write_passwd_file - Atomically replace the VNC password file.
 * @ops:  Syscall operations.
 * @path: Destination path for the password file.
 * @hash: crypt(3) hash string to write (NUL-terminated).
 */
int atomic_write_passwd_file(const struct syscall_ops *ops, const char *path,
                             const char *hash) {
  char tmp_path[PATH_MAX] = {0};
  char line[CRYPT_OUTPUT_SIZE + 2] = {0}; /* hash + '\n' + '\0' */
  int fd = -1;
  int saved_errno = 0;
  int n = 0;

  if (ops == NULL || path == NULL || hash == NULL) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", path);
  /* LCOV_EXCL_BR_START - n < 0 unreachable: no wide-char conversions */
  if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
    /* LCOV_EXCL_BR_STOP */
    errno = ERANGE;
    return -1;
  }

  n = snprintf(line, sizeof(line), "%s\n", hash);
  /* LCOV_EXCL_BR_START - n < 0 unreachable: no wide-char conversions */
  if (n < 0 || (size_t)n >= sizeof(line)) {
    /* LCOV_EXCL_BR_STOP */
    explicit_bzero(line, sizeof(line));
    errno = ERANGE;
    return -1;
  }

  size_t line_len = (size_t)n;

  /*
   * O_CLOEXEC prevents the fd from leaking into child processes if this
   * program forks after this point, which is especially important in a setuid
   * context where a compromised child could read the temp file before rename()
   * puts it in place.
   */
  fd = ops->mkostemp(tmp_path, O_CLOEXEC);
  if (fd < 0) {
    explicit_bzero(line, sizeof(line));
    return -1;
  }

  /*
   * Set permissions before writing any data. Writing first and then failing
   * fchmod would create a window where the file is world-readable.
   */
  if (ops->fchmod(fd, 0600) < 0) {
    saved_errno = errno;
    explicit_bzero(line, sizeof(line));
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  ssize_t written = ops->write(fd, line, line_len);
  explicit_bzero(line, sizeof(line)); /* Done with hash. */

  if (written < 0) {
    saved_errno = errno;
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  if ((size_t)written != line_len) {
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = EIO;
    return -1;
  }

  if (ops->fsync(fd) < 0) {
    saved_errno = errno;
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  if (ops->close(fd) < 0) {
    saved_errno = errno;
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  if (ops->rename(tmp_path, path) < 0) {
    saved_errno = errno;
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

#ifdef HAVE_SELINUX
  {
    /* quietly suppress all selinux messages for systems where selinux=0 */
    union selinux_callback cb_saved = selinux_get_callback(SELINUX_CB_LOG);
    union selinux_callback cb_suppress = { .func_log = noop_selinux_log };
    selinux_set_callback(SELINUX_CB_LOG, cb_suppress);
    (void)selinux_restorecon(path, SELINUX_RESTORECON_IGNORE_DIGEST); /* --force */
    selinux_set_callback(SELINUX_CB_LOG, cb_saved);
  }
#endif

  return 0;
}
