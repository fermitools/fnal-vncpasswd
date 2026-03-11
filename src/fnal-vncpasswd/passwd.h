/*
 * fnal-vncpasswd/passwd.h - VNC password file operations.
 *
 * Declares the testable core: password hashing, directory creation, and
 * atomic file write. Terminal I/O and argument parsing are private to main.c
 * and are not declared here.
 *
 * All functions accept a struct syscall_ops pointer so unit tests can inject
 * fakes without touching the filesystem or calling real crypt functions.
 * Passing NULL for ops is always an error (EINVAL).
 */

#ifndef FNAL_VNCPASSWD_PASSWD_H
#define FNAL_VNCPASSWD_PASSWD_H

#include <crypt.h>
#include <stddef.h>
#include <sys/types.h>

#include "syscall_ops.h"
#include "vnc_crypto.h"

/*
 * get_passwd_path - Build the VNC password file path for a given UID.
 * @ops:    Syscall operations.
 * @uid:    UID to look up; callers pass getuid().
 * @buf:    Output buffer for the constructed path.
 * @buflen: Size of @buf. PATH_MAX is always sufficient.
 *
 * Looks up the home directory for @uid via getpwuid_r(3), creates the VNC
 * configuration directory if absent, then constructs the full password file
 * path via build_vnc_passwd_path(). Directory creation uses the same @ops so
 * tests can intercept mkdir without a real filesystem.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int get_passwd_path(const struct syscall_ops *ops, uid_t uid, char *buf,
                    size_t buflen) __attribute__((warn_unused_result));

/*
 * hash_password - Hash a plaintext password using crypt_r(3).
 * @ops:      Syscall operations.
 * @password: Plaintext password (NUL-terminated, non-empty).
 * @hash_buf: Output buffer; VNC_HASH_BUF_SIZE bytes is always sufficient.
 * @hash_len: Size of @hash_buf.
 *
 * Algorithm selection:
 *   NULL is passed as the prefix to crypt_gensalt_ra(3), which the library
 *   documents as "use the compiled-in preferred algorithm" (yescrypt on
 *   RHEL 9+ / libxcrypt >= 4.4). count=0 requests the default cost for that
 *   algorithm.
 *
 * Entropy:
 *   bytes from getrandom(2) are gathered in a loop to handle the case
 *   where the syscall returns fewer bytes than requested before the kernel
 *   entropy pool is fully seeded.
 *
 * Sensitive data:
 *   The salt, crypt_data structure, and (on error) hash_buf are zeroed with
 *   explicit_bzero(3) before returning, successful or not.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int hash_password(const struct syscall_ops *ops, const char *password,
                  char *hash_buf, size_t hash_len)
    __attribute__((warn_unused_result));

/*
 * ensure_vnc_dir - Create the VNC configuration directory if absent.
 * @ops:  Syscall operations.
 * @path: Absolute path to create (e.g. /home/user/.config/vnc).
 *
 * Creates each missing path component with mode 0700, analogous to
 * `mkdir -p`. Silently accepts components that already exist as directories.
 *
 * Failure conditions:
 *   - Any component exists but is not a directory → ENOTDIR.
 *   - @path contains ".." as a path component → EINVAL.
 *     (realpath(3) is not used because the path may not exist yet.)
 *   - Any stat(2) or mkdir(2) fails for another reason -> that errno.
 *
 * TOCTOU: on EEXIST from mkdir(2), the function re-stats to confirm the
 * racing creator also made a directory rather than a symlink or regular file.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int ensure_vnc_dir(const struct syscall_ops *ops, const char *path)
    __attribute__((warn_unused_result));

/*
 * atomic_write_passwd_file - Atomically replace the VNC password file.
 * @ops:  Syscall operations.
 * @path: Destination path for the password file.
 * @hash: crypt(3) hash string to write (NUL-terminated).
 *
 * Write sequence:
 *   1. mkostemp(O_CLOEXEC) in the same directory as @path.
 *      (O_CLOEXEC prevents fd leaking into any forked child.)
 *   2. fchmod(0600) before any data is written.
 *      (mkostemp(3) uses 0600 on Linux but this is not POSIX-guaranteed.)
 *   3. write(hash + "\n"). A short-write of 0 bytes is treated as EIO.
 *   4. fsync(2).
 *   5. rename(2) — atomic on POSIX local filesystems.
 *   6. selinux_restorecon() — only when HAVE_SELINUX; always non-fatal.
 *
 * On any failure after mkostemp(), the temp file is unlinked and the
 * original errno is restored before returning.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int atomic_write_passwd_file(const struct syscall_ops *ops, const char *path,
                             const char *hash)
    __attribute__((warn_unused_result));

#endif /* FNAL_VNCPASSWD_PASSWD_H */
