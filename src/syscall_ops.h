/*
 * syscall_ops.h - System call abstraction layer for dependency injection.
 *
 * Unit testing code that makes system calls is difficult because tests may
 * require root privileges, have filesystem side effects, depend on system
 * state, or consume real entropy. This layer solves those problems by:
 *
 *   1. Separating interface (what operations we need) from implementation.
 *   2. Allowing tests to inject mock implementations without syscall
 * privileges.
 *   3. Making dependencies explicit in function signatures.
 *
 * Production code uses syscall_ops_default (maps to actual system calls).
 * Test code creates custom ops structures with controlled behavior. Functions
 * receive ops as their first parameter, following the kernel convention.
 */

#ifndef SYSCALL_OPS_H
#define SYSCALL_OPS_H

#include <crypt.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * syscall_ops - Operations structure for system call abstraction.
 *
 * A function pointer table wrapping all external system dependencies,
 * following the Linux kernel pattern (e.g. struct file_operations). Passing
 * ops as the first parameter makes dependencies visible and allows the same
 * binary to use different implementations at runtime without global state.
 */
struct syscall_ops {
  /*
   * File operations.
   *
   * Password files must be validated for security (owner, permissions, not a
   * symlink).
   */
  int (*open)(const char *pathname, int flags, ...);
  int (*close)(int fd);
  int (*fstat)(int fd, struct stat *statbuf);
  int (*stat)(const char *pathname, struct stat *statbuf);
  FILE *(*fdopen)(int fd, const char *mode);
  int (*fclose)(FILE *stream);
  char *(*fgets)(char *str, int n, FILE *stream);

  /*
   * Directory operations.
   *
   * Creates ~/.config/vnc/ if absent.
   */
  int (*mkdir)(const char *pathname, mode_t mode);

  /*
   * Atomic file write operations.
   *
   * The password file must be written atomically to prevent partial writes.
   */
  int (*mkostemp)(char *tmpl, int flags);
  int (*fchmod)(int fd, mode_t mode);
  int (*fsync)(int fd);
  int (*rename)(const char *oldpath, const char *newpath);
  int (*unlink)(const char *pathname);
  ssize_t (*write)(int fd, const void *buf, size_t count);

  /*
   * User database operations.
   *
   * The PAM module keys lookup by username (getpwnam_r) because it is given
   * a username by the PAM stack. fnal-vncpasswd keys by UID (getpwuid_r)
   * because it acts on behalf of the calling process. The two differ in key,
   * error semantics, and privilege level; a shared wrapper would add
   * complexity for no gain.
   */
  int (*getpwnam_r)(const char *name, struct passwd *pwd, char *buf,
                    size_t buflen, struct passwd **result);
  int (*getpwuid_r)(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
                    struct passwd **result);

  /*
   * Entropy generation.
   *
   * Salt generation requires cryptographically secure random bytes. Tests
   * inject known bytes to verify salt construction. Never use rand() or
   * time()-seeded PRNGs for cryptographic salts. getrandom(2) reads from the
   * kernel CSPRNG (same source as /dev/urandom after boot entropy is
   * gathered).
   */
  ssize_t (*getrandom)(void *buf, size_t buflen, unsigned int flags);

  /*
   * Cryptographic operations.
   *
   * Password hashing and salt generation must be mockable for tests that
   * exercise error handling paths (e.g. crypt_r returning NULL).
   *
   * crypt_gensalt_ra handles algorithm-specific salt encoding automatically:
   *   - yescrypt ($y$): count is a cost factor (e.g. 5), encoded as params.
   *   - SHA-512  ($6$): count is rounds (e.g. 65536), prefixed "rounds=N$".
   *   - bcrypt   ($2b$): count is log2(rounds) (e.g. 12).
   * Passing NULL/0 selects the compiled-in preferred algorithm and cost,
   * but it does not account for FIPS blocking the preferred algorithm.
   *
   * crypt_gensalt_ra returns a heap-allocated string (caller must free).
   * crypt_checksalt verifies the salt is acceptable
   * crypt_r writes to the caller-provided crypt_data buffer (no allocation).
   */
  char *(*crypt_gensalt_ra)(const char *prefix, unsigned long count,
                            const char *rbytes, int nrbytes);
  int (*crypt_checksalt)(const char *setting);
  char *(*crypt_r)(const char *phrase, const char *setting,
                   struct crypt_data *data);

  /*
   * Memory management.
   *
   * Mockable so tests can exercise allocation-failure paths. free() is
   * intentionally absent: freeing memory is deterministic libc behavior with
   * no meaningful test variation.
   */
  void *(*calloc)(size_t nmemb, size_t size);
};

/*
 * syscall_ops_default - Production system call implementation.
 *
 * Global constant mapping each function pointer to the corresponding POSIX or
 * C library function. Use this in all production code paths.
 *
 * Declared extern (defined in syscall_ops_default.c) so a single instance is
 * shared across translation units. Declared const so it resides in .rodata
 * (write-protected) and is safe to share across threads without
 * synchronization.
 *
 * To override individual operations in tests:
 *   struct syscall_ops test_ops = syscall_ops_default;
 *   test_ops.crypt_r    = mock_crypt_r_null;
 *   test_ops.getrandom  = mock_getrandom_fail;
 */
extern const struct syscall_ops syscall_ops_default;

#endif /* SYSCALL_OPS_H */
