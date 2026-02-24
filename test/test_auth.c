/**
 * test_auth.c - Unit tests for pam/auth.c
 *
 * Tests parse_pam_args() and authenticate_vnc_user() using injected
 * syscall_ops mocks. pam_syslog() is intercepted via --wrap so debug=true
 * paths can be verified; the real libpam is linked for pam_handle_t and
 * PAM_* constants.
 *
 * Session binding
 * ---------------
 * authenticate_vnc_user() calls getuid() directly (not through ops) and
 * compares the resolved pw_uid against it. Tests that exercise the post-
 * binding paths configure mock_getpwnam_r to return getuid() as pw_uid.
 * The uid-mismatch test uses getuid() + 1 (wrapping via uid_t arithmetic is
 * safe because the test runs under a normal user, not uid UINT_MAX).
 *
 * pamh
 * ----
 * authenticate_vnc_user() rejects NULL pamh. We supply a non-NULL dummy
 * pointer (&_dummy_pamh_storage); with debug=false it is never dereferenced,
 * and with debug=true calls are routed through __wrap_pam_syslog.
 */

/* clang-format off */
#include "auth.h"
#include "autoconf.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"
/* clang-format on */

#include <assert.h>
#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "test_framework.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Generic mock file descriptor; never touches the real kernel. */
enum { MOCK_FD = 42 };

/*
 * A representative hash string used for positive-match tests.
 * The exact algorithm prefix is irrelevant; crypt_r is mocked.
 */
#define TEST_HASH "$6$rounds=65536$testsalt$DEADBEEF"

/* ============================================================================
 * pam_syslog Interposer  (-Wl,--wrap=pam_syslog)
 *
 * Records the number of times pam_syslog() is called and the most-recently
 * seen priority so tests can assert:
 *   - debug=true paths emit at least one log call.
 *   - debug=false paths emit no log calls.
 *
 * Each test runs in a forked child, so _mock_pam_syslog_calls resets to 0
 * automatically at the fork boundary.
 * ============================================================================
 */

int _mock_pam_syslog_calls = 0;
int _mock_pam_syslog_last_pri = 0;

void __wrap_pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt,
                       ...);
void __wrap_pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt,
                       ...) {
  (void)pamh;
  (void)fmt;
  _mock_pam_syslog_calls++;
  _mock_pam_syslog_last_pri = priority;
}

/* ============================================================================
 * Mock State and Dummy PAM Handle
 * ============================================================================
 */

/*
 * authenticate_vnc_user() checks pamh != NULL before using it. With
 * debug=false, the pointer is never dereferenced.
 */
static int _dummy_pamh_storage;
#define DUMMY_PAMH ((pam_handle_t *)&_dummy_pamh_storage)

/*
 * We need a non-NULL FILE* that is never passed to real libc fread/fwrite.
 * Using a static int avoids heap allocation while remaining a valid non-NULL
 * pointer for our mock fgets/fclose.
 */
static int _fake_file_storage;
#define FAKE_FILE ((FILE *)&_fake_file_storage)

/* ============================================================================
 * Mock Implementations
 * ============================================================================
 */

/* --- getpwnam_r ------------------------------------------------------------
 */

static struct {
  int rc;          /* return value (0 = success) */
  int no_result;   /* set *result = NULL even if rc == 0 */
  int pw_dir_null; /* set pw->pw_dir = NULL to exercise the NULL arm */
  uid_t uid;       /* pw_uid to inject */
  char pw_dir[PATH_MAX];
  char pw_name[256];
} _cfg_getpwnam_r;

static int mock_getpwnam_r(const char *name, struct passwd *pw, char *buf,
                           size_t buflen, struct passwd **result) {
  (void)name;

  if (_cfg_getpwnam_r.rc != 0) {
    *result = NULL;
    return _cfg_getpwnam_r.rc;
  }

  if (_cfg_getpwnam_r.no_result) {
    *result = NULL;
    return 0;
  }

  /*
   * pw_dir is copied into the caller-supplied pwbuf so it remains valid for
   * the lifetime of the caller's stack frame, matching real getpwnam_r
   * behaviour. auth.c's pwbuf is 4096 bytes; pw_dir is PATH_MAX bytes, so
   * snprintf may truncate if PATH_MAX > 4096. Tests that depend on an exact
   * pw_dir length (cfg_overlong_home_dir) assert dir_len < 4096 to catch
   * this before it silently corrupts the test.
   */
  if (_cfg_getpwnam_r.pw_dir_null) {
    pw->pw_dir = NULL;
  } else {
    snprintf(buf, buflen, "%s", _cfg_getpwnam_r.pw_dir);
    pw->pw_dir = buf;
  }
  pw->pw_uid = _cfg_getpwnam_r.uid;
  pw->pw_name = _cfg_getpwnam_r.pw_name;
  *result = pw;
  return 0;
}

/* --- open ------------------------------------------------------------------
 */

static struct {
  int fail; /* 1 = return -1 / EACCES */
} _cfg_open;

static int mock_open(const char *path, int flags, ...) {
  (void)path;
  (void)flags;

  if (_cfg_open.fail) {
    errno = EACCES;
    return -1;
  }
  return MOCK_FD;
}

/* --- fstat -----------------------------------------------------------------
 */

static struct {
  int fail;
  uid_t st_uid;
  mode_t st_mode;
} _cfg_fstat;

static int mock_fstat(int fd, struct stat *st) {
  (void)fd;

  if (_cfg_fstat.fail) {
    errno = EIO;
    return -1;
  }
  memset(st, 0, sizeof(*st));
  st->st_uid = _cfg_fstat.st_uid;
  st->st_mode = _cfg_fstat.st_mode;
  return 0;
}

/* --- close -----------------------------------------------------------------
 */

static int mock_close(int fd) {
  (void)fd;
  return 0;
}

/* --- fdopen ----------------------------------------------------------------
 */

static struct {
  int fail;
} _cfg_fdopen;

static FILE *mock_fdopen(int fd, const char *mode) {
  (void)fd;
  (void)mode;

  if (_cfg_fdopen.fail) {
    errno = ENOMEM;
    return NULL;
  }
  return FAKE_FILE;
}

/* --- fgets -----------------------------------------------------------------
 */

static struct {
  int fail;                        /* 1 = return NULL (EOF/error) */
  char content[VNC_HASH_BUF_SIZE]; /* hash string to deliver */
  int call_count;
} _cfg_fgets;

static char *mock_fgets(char *str, int n, FILE *stream) {
  (void)stream;
  _cfg_fgets.call_count++;

  if (_cfg_fgets.fail) {
    return NULL;
  }

  snprintf(str, (size_t)n, "%s", _cfg_fgets.content);
  return str;
}

/* --- fclose ----------------------------------------------------------------
 */

static int mock_fclose(FILE *fp) {
  (void)fp;
  return 0;
}

/* --- crypt_r ---------------------------------------------------------------
 */

static struct {
  int fail;
  int star;
  char hash[CRYPT_OUTPUT_SIZE]; /* pre-computed expected hash */
} _cfg_crypt_r;

static char *mock_crypt_r(const char *phrase, const char *setting,
                          struct crypt_data *data) {
  (void)phrase;
  (void)setting;

  if (_cfg_crypt_r.fail) {
    return NULL;
  }

  if (_cfg_crypt_r.star) {
    memcpy(data->output, "*0", sizeof("*0"));
    return data->output;
  }

  snprintf(data->output, sizeof(data->output), "%s", _cfg_crypt_r.hash);
  return data->output;
}

/* ============================================================================
 * Fixture Helpers
 * ============================================================================
 */

/**
 * cfg_valid_stat - Configure mock_fstat to return a valid password file stat
 *
 * Regular file, owned by the current process uid, mode 0600. Matches all
 * conditions required by validate_passwd_file().
 */
static void cfg_valid_stat(void) {
  _cfg_fstat.fail = 0;
  _cfg_fstat.st_uid = getuid();
  _cfg_fstat.st_mode = S_IFREG | 0600;
}

/**
 * make_auth_ops - Build a syscall_ops struct wired to all mocks
 *
 * Resets every mock config struct to zero, then applies defaults suitable for
 * the happy path: getpwnam_r resolves to the current uid with home
 * "/home/user", fstat returns a valid 0600 regular file. Callers override
 * individual fields to inject specific failure conditions.
 *
 * Returns: Initialized syscall_ops structure
 */
static struct syscall_ops make_auth_ops(void) {
  struct syscall_ops ops = syscall_ops_default;
  ops.getpwnam_r = mock_getpwnam_r;
  ops.open = mock_open;
  ops.fstat = mock_fstat;
  ops.close = mock_close;
  ops.fdopen = mock_fdopen;
  ops.fgets = mock_fgets;
  ops.fclose = mock_fclose;
  ops.crypt_r = mock_crypt_r;

  /* Reset all config to known state. */
  memset(&_cfg_getpwnam_r, 0, sizeof(_cfg_getpwnam_r));
  memset(&_cfg_open, 0, sizeof(_cfg_open));
  memset(&_cfg_fstat, 0, sizeof(_cfg_fstat));
  memset(&_cfg_fdopen, 0, sizeof(_cfg_fdopen));
  memset(&_cfg_fgets, 0, sizeof(_cfg_fgets));
  memset(&_cfg_crypt_r, 0, sizeof(_cfg_crypt_r));

  /* Default: getpwnam_r resolves to current uid with a valid home dir. */
  _cfg_getpwnam_r.uid = getuid();
  snprintf(_cfg_getpwnam_r.pw_dir, PATH_MAX, "/home/user");
  snprintf(_cfg_getpwnam_r.pw_name, 256, "user");

  cfg_valid_stat();

  return ops;
}

/**
 * cfg_happy_crypt - Configure mocks for a successful password verification
 *
 * Sets mock_crypt_r to return TEST_HASH and mock_fgets to deliver TEST_HASH
 * followed by a trailing newline (as written by atomic_write_passwd_file).
 * The stripping loop in auth.c removes the newline before comparison, so
 * the hashes match and PAM_SUCCESS is returned.
 */
static void cfg_happy_crypt(void) {
  _cfg_crypt_r.fail = 0;
  _cfg_crypt_r.star = 0;
  snprintf(_cfg_crypt_r.hash, sizeof(_cfg_crypt_r.hash), "%s", TEST_HASH);
  snprintf(_cfg_fgets.content, sizeof(_cfg_fgets.content), "%s\n", TEST_HASH);
}

/**
 * cfg_overlong_home_dir - Configure mock_getpwnam_r with an overlong home dir
 *
 * build_vnc_passwd_path formats:
 *   home_dir "/" VNC_PASSWD_DIR "/" VNC_PASSWD_FILENAME
 * and returns -1 when snprintf's return value n satisfies n >= PATH_MAX
 * (the size of auth.c's passwd_path buffer).
 *
 * We measure the suffix length at runtime using the same macros so the test
 * remains correct if VNC_PASSWD_DIR or VNC_PASSWD_FILENAME change. Setting
 * dir_len = PATH_MAX - suffix_len produces a total formatted length of exactly
 * PATH_MAX, which satisfies (size_t)n >= buflen.
 *
 * Constraint: pw_dir must survive mock_getpwnam_r's
 *   snprintf(pwbuf, buflen, "%s", pw_dir)
 * where pwbuf is the 4096-byte buffer in open_and_read_passwd_hash. The
 * assert(dir_len < 4096) below catches any platform where PATH_MAX > 4096,
 * which would silently truncate pw_dir and prevent the overflow from reaching
 * build_vnc_passwd_path.
 */
static void cfg_overlong_home_dir(void) {
  char scratch[PATH_MAX * 2];
  size_t suffix_len;
  size_t dir_len;

  /*
   * Measure the suffix: "/" VNC_PASSWD_DIR "/" VNC_PASSWD_FILENAME.
   * snprintf returns int; cast is safe because the format produces no
   * encoding errors and the scratch buffer is large enough to avoid
   * truncation, so the return value is non-negative.
   */
  suffix_len = (size_t)snprintf(scratch, sizeof(scratch), "/%s/%s",
                                VNC_PASSWD_DIR, VNC_PASSWD_FILENAME);

  /*
   * dir_len + suffix_len == PATH_MAX, so snprintf returns PATH_MAX,
   * satisfying (size_t)n >= buflen (buflen == PATH_MAX).
   */
  dir_len = (size_t)PATH_MAX - suffix_len;

  /* Sanity: dir_len must hold a valid absolute path and fit in pwbuf. */
  assert(dir_len > 1);
  assert(dir_len < (size_t)PATH_MAX);
  assert(dir_len < 4096); /* pwbuf size in open_and_read_passwd_hash */

  memset(_cfg_getpwnam_r.pw_dir, 'a', dir_len);
  _cfg_getpwnam_r.pw_dir[0] = '/'; /* valid absolute path */
  _cfg_getpwnam_r.pw_dir[dir_len] = '\0';
}

/* ============================================================================
 * Tests: parse_pam_args
 * ============================================================================
 */

TEST(parse_pam_args_null_args_no_crash) {
  /* Passing NULL args must not crash (function returns early). */
  const char *argv[] = {"debug"};
  parse_pam_args(1, argv, NULL);
  /* Reaching here = pass. */
  TEST_ASSERT_EQ(1, 1, "no crash");
}

TEST(parse_pam_args_defaults) {
  struct pam_args args = make_pam_args();
  TEST_ASSERT_EQ(args.debug, 0, "debug default must be false");
}

TEST(parse_pam_args_empty) {
  struct pam_args args = make_pam_args();
  parse_pam_args(0, NULL, &args);
  TEST_ASSERT_EQ(args.debug, 0, "empty argc must leave debug false");
}

TEST(parse_pam_args_debug_flag) {
  struct pam_args args = make_pam_args();
  const char *argv[] = {"debug"};
  parse_pam_args(1, argv, &args);
  TEST_ASSERT_EQ(args.debug, 1, "debug argument must set debug=true");
}

TEST(parse_pam_args_unknown_arg_ignored) {
  struct pam_args args = make_pam_args();
  const char *argv[] = {"unknown_option", "another=value"};
  parse_pam_args(2, argv, &args);
  TEST_ASSERT_EQ(args.debug, 0, "unknown args must not set debug");
}

TEST(parse_pam_args_null_argv_entry_ignored) {
  struct pam_args args = make_pam_args();
  const char *argv[] = {NULL, "debug"};
  parse_pam_args(2, argv, &args);
  TEST_ASSERT_EQ(args.debug, 1, "NULL argv entry must be skipped");
}

TEST(parse_pam_args_debug_among_others) {
  struct pam_args args = make_pam_args();
  const char *argv[] = {"foo", "debug", "bar"};
  parse_pam_args(3, argv, &args);
  TEST_ASSERT_EQ(args.debug, 1, "debug in mixed args must be detected");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - Argument validation
 * ============================================================================
 */

TEST(auth_null_ops) {
  int rc;
  rc = authenticate_vnc_user(NULL, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "NULL ops must return PAM_AUTH_ERR");
}

TEST(auth_null_pamh) {
  struct syscall_ops ops = make_auth_ops();
  int rc;
  rc = authenticate_vnc_user(&ops, NULL, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "NULL pamh must return PAM_AUTH_ERR");
}

TEST(auth_null_username) {
  struct syscall_ops ops = make_auth_ops();
  int rc;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, NULL, "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "NULL username must return PAM_AUTH_ERR");
}

TEST(auth_null_password) {
  struct syscall_ops ops = make_auth_ops();
  int rc;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", NULL, false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "NULL password must return PAM_AUTH_ERR");
}

TEST(auth_empty_username) {
  struct syscall_ops ops = make_auth_ops();
  int rc;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "empty username must return PAM_AUTH_ERR");
}

TEST(auth_empty_password) {
  struct syscall_ops ops = make_auth_ops();
  int rc;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "empty password must return PAM_AUTH_ERR");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - User lookup
 * ============================================================================
 */

TEST(auth_user_not_found) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.no_result = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "nobody", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN,
                 "missing user must return PAM_USER_UNKNOWN");
}

TEST(auth_getpwnam_r_error) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.rc = ENOENT;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN,
                 "getpwnam_r error must return PAM_USER_UNKNOWN");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - Session binding
 * ============================================================================
 */

TEST(auth_uid_mismatch) {
  /*
   * Session binding: resolved uid must equal getuid(). Use getuid()+1 as a
   * different uid. uid_t wrapping at UINT_MAX is acceptable: if this process
   * somehow runs as uid UINT_MAX, the test is a false-positive no-op (the
   * only safe assumption without knowing the platform uid range).
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.uid = getuid() + 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "uid mismatch must return PAM_AUTH_ERR");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - Home directory validation
 * ============================================================================
 */

TEST(auth_home_dir_null) {
  /*
   * getpwnam_r resolves successfully but sets pw_dir = NULL.
   * Exercises the first arm of the three-way home-dir validity check:
   *   pw.pw_dir == NULL || pw.pw_dir[0] != '/' || (... && pw.pw_dir[1] ==
   * '\0')
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.pw_dir_null = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN,
                 "NULL pw_dir must return PAM_USER_UNKNOWN");
}

TEST(auth_home_dir_root_slash) {
  /* Home directory "/" is explicitly rejected. */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  snprintf(_cfg_getpwnam_r.pw_dir, PATH_MAX, "/");
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN,
                 "home dir '/' must return PAM_USER_UNKNOWN");
}

TEST(auth_home_dir_empty) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.pw_dir[0] = '\0';
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN,
                 "empty home dir must return PAM_USER_UNKNOWN");
}

TEST(auth_home_dir_relative) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  snprintf(_cfg_getpwnam_r.pw_dir, PATH_MAX, "home/user");
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN,
                 "relative home dir must return PAM_USER_UNKNOWN");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - Passwd path construction
 *
 * build_vnc_passwd_path() returns -1 (ERANGE) when the formatted path length
 * equals or exceeds PATH_MAX. cfg_overlong_home_dir() sizes pw_dir so the
 * total is exactly PATH_MAX bytes, which satisfies (size_t)n >= buflen inside
 * build_vnc_passwd_path. This is the only branch in open_and_read_passwd_hash
 * not reachable by manipulating the mocked syscalls.
 * ============================================================================
 */

TEST(auth_passwd_path_build_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_overlong_home_dir();
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR,
                 "overlong home dir must return PAM_AUTH_ERR");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - File validation
 * ============================================================================
 */

TEST(auth_passwd_file_open_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_open.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "open failure must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_passwd_file_fstat_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fstat.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "fstat failure must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_passwd_file_wrong_owner) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fstat.st_uid = getuid() + 1; /* owner != process uid */
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "wrong file owner must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_passwd_file_not_regular) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fstat.st_mode = S_IFDIR | 0600; /* directory, not regular file */
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "non-regular file must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_passwd_file_group_readable) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fstat.st_mode = S_IFREG | 0640; /* group-readable: rejected */
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "group-readable file must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_passwd_file_world_readable) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fstat.st_mode = S_IFREG | 0604; /* world-readable: rejected */
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "world-readable file must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_passwd_file_user_executable) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fstat.st_mode = S_IFREG | 0700; /* executable: rejected */
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "executable file must return PAM_AUTHINFO_UNAVAIL");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - Hash read
 * ============================================================================
 */

TEST(auth_fdopen_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fdopen.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "fdopen failure must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_fgets_returns_null) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fgets.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "fgets NULL must return PAM_AUTHINFO_UNAVAIL");
}

TEST(auth_hash_empty_after_strip) {
  /*
   * fgets delivers a line that is only whitespace. After stripping CR/LF/SP
   * the hash is empty; must fail as unavailable, not as auth error.
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  snprintf(_cfg_fgets.content, sizeof(_cfg_fgets.content), "   \n");
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL,
                 "whitespace-only hash must return PAM_AUTHINFO_UNAVAIL");
}

/* ============================================================================
 * Tests: authenticate_vnc_user - Password verification
 * ============================================================================
 */

TEST(auth_crypt_r_returns_null) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  _cfg_crypt_r.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "wrongpass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "crypt_r NULL must return PAM_AUTH_ERR");
}

TEST(auth_crypt_r_returns_star) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  _cfg_crypt_r.star = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "crypt_r '*' must return PAM_AUTH_ERR");
}

TEST(auth_password_mismatch) {
  /*
   * crypt_r returns a hash that differs from the stored hash.
   * vnc_const_memcmp will find them unequal.
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  /* Override crypt_r output to differ from what fgets delivered. */
  snprintf(_cfg_crypt_r.hash, sizeof(_cfg_crypt_r.hash),
           "$6$rounds=65536$testsalt$DIFFERENT");
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "wrongpass", false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "hash mismatch must return PAM_AUTH_ERR");
}

TEST(auth_password_match) {
  /*
   * crypt_r returns the same hash that fgets provided.
   * vnc_const_memcmp must return 0 (equal) -> PAM_SUCCESS.
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "secret", false);
  TEST_ASSERT_EQ(rc, PAM_SUCCESS, "matching hash must return PAM_SUCCESS");
}

TEST(auth_hash_trailing_newline_stripped) {
  /*
   * Verify that a stored hash with a trailing '\n' (as written by
   * atomic_write_passwd_file) is stripped before comparison. If stripping
   * is broken, the newline makes the hash differ from crypt_r's output.
   * cfg_happy_crypt already places the trailing '\n' in fgets content.
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "secret", false);
  TEST_ASSERT_EQ(rc, PAM_SUCCESS,
                 "trailing newline must be stripped before comparison");
}

TEST(auth_hash_trailing_cr_stripped) {
  /* Simulate DOS line endings ("\r\n"). Both characters must be stripped. */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  snprintf(_cfg_fgets.content, sizeof(_cfg_fgets.content), "%s\r\n", TEST_HASH);
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "secret", false);
  TEST_ASSERT_EQ(rc, PAM_SUCCESS,
                 "trailing CRLF must be stripped before comparison");
}

/* ============================================================================
 * Tests: debug=true path coverage
 *
 * Each test below mirrors a non-debug case but passes debug=true. The goals
 * are:
 *   1. Confirm the debug code path executes without crashing.
 *   2. Confirm pam_syslog() is called at least once (via the --wrap counter).
 *   3. Confirm debug=false produces zero pam_syslog calls (log hygiene).
 *
 * Return codes must be identical to the corresponding non-debug test.
 * ============================================================================
 */

TEST(debug_false_emits_no_log_on_success) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "secret", false);
  TEST_ASSERT_EQ(rc, PAM_SUCCESS, "must succeed");
  TEST_ASSERT_EQ(_mock_pam_syslog_calls, 0,
                 "debug=false must not call pam_syslog");
}

TEST(debug_true_emits_log_on_success) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "secret", true);
  TEST_ASSERT_EQ(rc, PAM_SUCCESS, "must succeed");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must call pam_syslog at least once");
}

TEST(debug_true_user_not_found) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.no_result = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "nobody", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN, "must return PAM_USER_UNKNOWN");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log on user-not-found path");
}

TEST(debug_true_uid_mismatch) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.uid = getuid() + 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "must return PAM_AUTH_ERR");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log session binding failure");
}

TEST(debug_true_home_dir_null) {
  /*
   * getpwnam_r returns pw_dir == NULL with debug=true.
   * Exercises the debug-logging sub-path for the NULL home-dir arm.
   */
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_getpwnam_r.pw_dir_null = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN, "must return PAM_USER_UNKNOWN");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log NULL home dir");
}

TEST(debug_true_home_dir_root) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  snprintf(_cfg_getpwnam_r.pw_dir, PATH_MAX, "/");
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_USER_UNKNOWN, "must return PAM_USER_UNKNOWN");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log invalid home dir");
}

TEST(debug_true_passwd_path_build_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_overlong_home_dir();
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR,
                 "overlong home dir (debug) must return PAM_AUTH_ERR");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log build_vnc_passwd_path failure");
}

TEST(debug_true_file_open_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_open.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL, "must return PAM_AUTHINFO_UNAVAIL");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log file validation failure");
}

TEST(debug_true_fgets_fails) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  _cfg_fgets.fail = 1;
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "pass", true);
  TEST_ASSERT_EQ(rc, PAM_AUTHINFO_UNAVAIL, "must return PAM_AUTHINFO_UNAVAIL");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log hash read failure");
}

TEST(debug_true_password_mismatch) {
  struct syscall_ops ops = make_auth_ops();
  int rc;

  cfg_happy_crypt();
  snprintf(_cfg_crypt_r.hash, sizeof(_cfg_crypt_r.hash),
           "$6$rounds=65536$testsalt$DIFFERENT");
  rc = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "wrongpass", true);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR, "must return PAM_AUTH_ERR");
  TEST_ASSERT_NOT_EQ(_mock_pam_syslog_calls, 0,
                     "debug=true must log verification failure");
}

TEST(debug_log_priority_is_debug) {
  /*
   * All pam_syslog calls in auth.c must use LOG_DEBUG, never LOG_ERR or
   * higher, to avoid flooding syslog in production with auth noise.
   */
  struct syscall_ops ops = make_auth_ops();
  int ret;

  cfg_happy_crypt();
  ret = authenticate_vnc_user(&ops, DUMMY_PAMH, "user", "secret", true);
  TEST_ASSERT_EQ(_mock_pam_syslog_last_pri, LOG_DEBUG,
                 "all debug log calls must use LOG_DEBUG priority");
  TEST_ASSERT_EQ(ret, 0, "should not error");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* parse_pam_args */
  RUN_TEST(parse_pam_args_null_args_no_crash);
  RUN_TEST(parse_pam_args_defaults);
  RUN_TEST(parse_pam_args_empty);
  RUN_TEST(parse_pam_args_debug_flag);
  RUN_TEST(parse_pam_args_unknown_arg_ignored);
  RUN_TEST(parse_pam_args_null_argv_entry_ignored);
  RUN_TEST(parse_pam_args_debug_among_others);

  /* authenticate_vnc_user: argument validation */
  RUN_TEST(auth_null_ops);
  RUN_TEST(auth_null_pamh);
  RUN_TEST(auth_null_username);
  RUN_TEST(auth_null_password);
  RUN_TEST(auth_empty_username);
  RUN_TEST(auth_empty_password);

  /* authenticate_vnc_user: user lookup */
  RUN_TEST(auth_user_not_found);
  RUN_TEST(auth_getpwnam_r_error);

  /* authenticate_vnc_user: session binding */
  RUN_TEST(auth_uid_mismatch);

  /* authenticate_vnc_user: home directory validation */
  RUN_TEST(auth_home_dir_null);
  RUN_TEST(auth_home_dir_root_slash);
  RUN_TEST(auth_home_dir_empty);
  RUN_TEST(auth_home_dir_relative);

  /* authenticate_vnc_user: passwd path construction */
  RUN_TEST(auth_passwd_path_build_fails);

  /* authenticate_vnc_user: file validation */
  RUN_TEST(auth_passwd_file_open_fails);
  RUN_TEST(auth_passwd_file_fstat_fails);
  RUN_TEST(auth_passwd_file_wrong_owner);
  RUN_TEST(auth_passwd_file_not_regular);
  RUN_TEST(auth_passwd_file_group_readable);
  RUN_TEST(auth_passwd_file_world_readable);
  RUN_TEST(auth_passwd_file_user_executable);

  /* authenticate_vnc_user: hash read */
  RUN_TEST(auth_fdopen_fails);
  RUN_TEST(auth_fgets_returns_null);
  RUN_TEST(auth_hash_empty_after_strip);

  /* authenticate_vnc_user: password verification */
  RUN_TEST(auth_crypt_r_returns_null);
  RUN_TEST(auth_crypt_r_returns_star);
  RUN_TEST(auth_password_mismatch);
  RUN_TEST(auth_password_match);
  RUN_TEST(auth_hash_trailing_newline_stripped);
  RUN_TEST(auth_hash_trailing_cr_stripped);

  /* debug=true path coverage */
  RUN_TEST(debug_false_emits_no_log_on_success);
  RUN_TEST(debug_true_emits_log_on_success);
  RUN_TEST(debug_true_user_not_found);
  RUN_TEST(debug_true_uid_mismatch);
  RUN_TEST(debug_true_home_dir_null);
  RUN_TEST(debug_true_home_dir_root);
  RUN_TEST(debug_true_passwd_path_build_fails);
  RUN_TEST(debug_true_file_open_fails);
  RUN_TEST(debug_true_fgets_fails);
  RUN_TEST(debug_true_password_mismatch);
  RUN_TEST(debug_log_priority_is_debug);

  result = TEST_EXECUTE();
  return result;
}
