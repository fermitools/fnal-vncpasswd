/*
 * fnal-vncpasswd/main.c - fnal-vncpasswd CLI tool.
 *
 * Sets the per-user VNC password for use with pam_fnal_vncpasswd.
 *
 * Usage:
 *   fnal-vncpasswd [-h|--help] [--version]
 *
 * Security:
 *   - Uses libxcrypt's compiled-in default algorithm (yescrypt on RHEL 9+).
 *   - Passes count=0 to crypt_gensalt_ra (libxcrypt algorithm defaults).
 *   - Writes the password file atomically via mkostemp + rename.
 *   - Sets file permissions 0600 before writing data.
 *   - Calls selinux_restorecon() after rename when built with SELinux.
 */

#include <bsd/readpassphrase.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/restorecon.h>
#endif

#include "autoconf.h"
#include "passwd.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/*
 * Forward declarations.
 *
 * nonnull is safe here because these functions are file-scope only; main()
 * only calls them with valid stack buffers.
 */

static void print_help(void) __attribute__((cold));
static int read_password(char *buf, size_t buflen)
    __attribute__((warn_unused_result)) __attribute__((nonnull(1)));

/* Help */

static void print_help(void) {
  char passwd_display_path[PATH_MAX] = {0};

  (void)printf("Usage: %s [OPTIONS]\n", PROJECT_NAME);
  (void)printf("Version: %s\n", VERSION);
  (void)printf("\n");
  (void)printf("Set the VNC password used by pam_fnal_vncpasswd.\n");
  if (build_vnc_passwd_path("~", passwd_display_path,
                            sizeof(passwd_display_path)) == 0) {
    (void)printf("\n");
    (void)printf("Password file path: %s\n", passwd_display_path);
  }
  (void)printf("\n");
  (void)printf("  -h, --help       Show this help\n");
  (void)printf("      --version    Show version\n");
  (void)printf("\n");
}

/* Terminal password reading */

/*
 * read_password - Read and confirm a new password interactively.
 * @buf:    Output buffer.
 * @buflen: Size of @buf. Must be at least VNC_MAX_PASSWORD_LENGTH bytes.
 *
 * Prompts twice via readpassphrase(3bsd) and verifies the entries match and
 * fall within [VNC_MIN_PASSWORD_LENGTH, VNC_MAX_PASSWORD_LENGTH].
 *
 * readpassphrase opens /dev/tty directly, suppresses echo, and restores the
 * terminal on SIGINT/SIGTERM/SIGHUP — no signal handling is required here.
 * RPP_REQUIRE_TTY causes it to fail if no controlling terminal is available
 * rather than silently reading from stdin.
 *
 * The large buffer size permits detection of passwords longer than our
 * permitted maximum while ensuring a \0 at the end of the string.
 *
 * Returns 0 on success, -1 on failure (message printed to stderr).
 */
static int read_password(char *buf, size_t buflen) {
  char confirm[VNC_MAX_PASSWORD_LENGTH + 2] = {0};
  size_t n1, n2;

  if (buflen < VNC_MAX_PASSWORD_LENGTH + 2) {
    (void)fprintf(stderr, "Password buffer too short.\n");
    errno = EINVAL;
    return -1;
  }

  if (readpassphrase("New VNC password: ", buf, buflen,
                     RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
    (void)fprintf(stderr, "Error reading password.\n");
    errno = EIO;
    return -1;
  }

  n1 = strlen(buf);

  if (n1 < (size_t)VNC_MIN_PASSWORD_LENGTH) {
    (void)fprintf(stderr, "Password too short (minimum %d characters).\n",
                  VNC_MIN_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if (n1 > (size_t)VNC_MAX_PASSWORD_LENGTH) {
    (void)fprintf(stderr, "Password too long (maximum %d characters).\n",
                  VNC_MAX_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if (readpassphrase("Confirm VNC password: ", confirm, sizeof(confirm),
                     RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
    explicit_bzero(buf, buflen);
    explicit_bzero(confirm, sizeof(confirm));
    (void)fprintf(stderr, "Error reading confirmation.\n");
    errno = EIO;
    return -1;
  }

  n2 = strlen(confirm);

  if (n1 != n2 || memcmp(buf, confirm, n1) != 0) {
    (void)fprintf(stderr, "Passwords do not match.\n");
    explicit_bzero(buf, buflen);
    explicit_bzero(confirm, sizeof(confirm));
    errno = EINVAL;
    return -1;
  }

  explicit_bzero(confirm, sizeof(confirm));
  return 0;
}

/* Main */

int main(int argc, char *argv[]) {
  int opt = 0;
  char passwd_path[PATH_MAX] = {0};
  char password[VNC_MAX_PASSWORD_LENGTH + 2] = {0};
  char hash[VNC_HASH_BUF_SIZE] = {0};

  static const struct option long_opts[] = {
      {"help", no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 1000},
      {NULL, 0, NULL, 0}};

  while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'h':
      print_help();
      exit(EXIT_SUCCESS);
    case 1000: /* --version */
      (void)printf("%s %s\n", PROJECT_NAME, VERSION);
      exit(EXIT_SUCCESS);
    default:
      print_help();
      exit(EXIT_FAILURE);
    }
  }

  if (get_passwd_path(&syscall_ops_default, getuid(), passwd_path,
                      sizeof(passwd_path)) < 0) {
    (void)fprintf(stderr, "Cannot determine password file path: %s\n",
                  strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (read_password(password, sizeof(password)) < 0) {
    explicit_bzero(password, sizeof(password));
    exit(EXIT_FAILURE);
  }

  if (hash_password(&syscall_ops_default, password, hash, sizeof(hash)) < 0) {
    (void)fprintf(stderr, "Failed to hash password: %s\n", strerror(errno));
    explicit_bzero(password, sizeof(password));
    explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  explicit_bzero(password, sizeof(password));

  if (atomic_write_passwd_file(&syscall_ops_default, passwd_path, hash) < 0) {
    (void)fprintf(stderr, "Failed to write %s: %s\n", passwd_path,
                  strerror(errno));
    explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  explicit_bzero(hash, sizeof(hash));

  (void)printf("VNC password updated successfully.\n");
  exit(EXIT_SUCCESS);
}
