/**
 * test_passwd.c - Unit tests for fnal-vncpasswd/passwd.c
 *
 * Tests hash_password(), ensure_vnc_dir(), atomic_write_passwd_file(), and
 * get_passwd_path() using injected syscall_ops mocks. No real filesystem
 * access or crypto calls are made; each test fork-isolates its mock state.
 *
 * Mock design
 * -----------
 * Each mock function reads from a file-static config struct set before the
 * test body runs. Fork isolation means each child starts with the parent's
 * configured state and mutations within a child are invisible to other tests.
 *
 * Convention: _cfg_<n> holds per-call configuration for mock_<n>().
 */

/* clang-format off */
#include "autoconf.h"
#include "passwd.h"
#include "syscall_ops.h"
/* clang-format on */

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_framework.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/*
 * Dummy fd returned by mock_mkostemp. Must not be 0/1/2 (standard fds) and
 * need not be a valid OS fd; mock_write and mock_close never touch the kernel.
 */
enum { MOCK_FD = 77 };

/*
 * Must equal SALT_PREFIXES_COUNT in passwd.c. Used to assert exact call counts
 * in select_prefix tests. Update both if the preference list changes.
 */
#define TEST_SALT_PREFIXES_COUNT 5

/* ============================================================================
 * Mock Implementations
 * ============================================================================
 */

/* --- calloc ----------------------------------------------------------------
 */

static struct {
  int fail; /* 0 = succeed, 1 = return NULL */
} _cfg_calloc;

static void *mock_calloc(size_t nmemb, size_t size) {
  if (_cfg_calloc.fail) {
    return NULL;
  }
  return calloc(nmemb, size);
}

/* --- getpwuid_r ------------------------------------------------------------
 */

static struct {
  int rc;        /* return code; 0 = success */
  int no_result; /* if nonzero, set *result = NULL despite rc == 0 */
  uid_t uid;
  char pw_dir[PATH_MAX];
} _cfg_getpwuid_r;

static int mock_getpwuid_r(uid_t uid, struct passwd *pw, char *buf,
                           size_t buflen, struct passwd **result) {
  int dir_written;
  char *name_start;
  size_t name_space;

  (void)uid;

  if (_cfg_getpwuid_r.rc != 0) {
    *result = NULL;
    return _cfg_getpwuid_r.rc;
  }

  if (_cfg_getpwuid_r.no_result) {
    *result = NULL;
    return 0;
  }

  /*
   * Both pw_dir and pw_name must point into buf so they remain valid after
   * the caller frees pwbuf. Pack them sequentially: pw_dir first, then
   * pw_name immediately after the NUL terminator.
   */
  dir_written = snprintf(buf, buflen, "%s", _cfg_getpwuid_r.pw_dir);
  pw->pw_dir = buf;
  pw->pw_uid = _cfg_getpwuid_r.uid;

  name_start = buf + dir_written + 1;
  name_space = buflen - (size_t)(dir_written + 1);
  snprintf(name_start, name_space, "testuser");
  pw->pw_name = name_start;

  *result = pw;
  return 0;
}

/* --- crypt_gensalt_ra ------------------------------------------------------
 *
 * call_count tracks every invocation across both select_prefix() probes and
 * the final generate_salt() call, enabling precise assertions on iteration
 * depth. fail_on_call injects a one-shot NULL return without disabling all
 * subsequent calls, allowing tests to verify that select_prefix() skips a
 * failed probe and continues to the next prefix.
 */

static struct {
  int fail;         /* 1 = always return NULL */
  int fail_on_call; /* N = return NULL on call N only (0 = disabled) */
  int call_count;   /* incremented on every invocation */
  char salt[CRYPT_GENSALT_OUTPUT_SIZE];
} _cfg_crypt_gensalt_ra;

static char *mock_crypt_gensalt_ra(const char *prefix, unsigned long count,
                                   const char *rbytes, int nrbytes) {
  (void)prefix;
  (void)count;
  (void)rbytes;
  (void)nrbytes;

  _cfg_crypt_gensalt_ra.call_count++;

  if (_cfg_crypt_gensalt_ra.fail) {
    return NULL;
  }

  if (_cfg_crypt_gensalt_ra.fail_on_call != 0 &&
      _cfg_crypt_gensalt_ra.call_count == _cfg_crypt_gensalt_ra.fail_on_call) {
    return NULL;
  }

  /* Return a heap copy; caller is responsible for free(). */
  return strdup(_cfg_crypt_gensalt_ra.salt);
}

/* --- crypt_checksalt -------------------------------------------------------
 *
 * call_count tracks every invocation so tests can verify that select_prefix()
 * calls crypt_checksalt() exactly once per successfully generated probe salt.
 * fail_on_call rejects a single specific call; always_fail rejects all calls,
 * driving select_prefix() to exhaust the preference list and use the fallback.
 */

static struct {
  int always_fail;  /* 1 = always return -1 */
  int fail_on_call; /* N = return -1 on call N only (0 = disabled) */
  int call_count;   /* incremented on every invocation */
} _cfg_crypt_checksalt;

static int mock_crypt_checksalt(const char *setting) {
  (void)setting;

  _cfg_crypt_checksalt.call_count++;

  if (_cfg_crypt_checksalt.always_fail) {
    return -1;
  }

  if (_cfg_crypt_checksalt.fail_on_call != 0 &&
      _cfg_crypt_checksalt.call_count == _cfg_crypt_checksalt.fail_on_call) {
    return -1;
  }

  return 0;
}

/* --- crypt_r ---------------------------------------------------------------
 */

static struct {
  int fail; /* 1 = return NULL */
  int star; /* 1 = return a string starting with '*' */
  char hash[CRYPT_OUTPUT_SIZE];
} _cfg_crypt_r;

static char *mock_crypt_r(const char *phrase, const char *setting,
                          struct crypt_data *data) {
  (void)phrase;
  (void)setting;

  if (_cfg_crypt_r.fail) {
    return NULL;
  }

  if (_cfg_crypt_r.star) {
    memcpy(data->output, "*invalid*", sizeof("*invalid*"));
    return data->output;
  }

  snprintf(data->output, sizeof(data->output), "%s", _cfg_crypt_r.hash);
  return data->output;
}

/* --- stat ------------------------------------------------------------------
 *
 * Mocks ops->stat, which follows symlinks. make_one_dir() uses stat(2) so
 * that symlinks pointing to directories are accepted: stat resolves the link
 * and returns S_IFDIR for the target. Only non-symlink, non-directory entries
 * (regular files, sockets, …) are rejected with ENOTDIR.
 */

static struct {
  int call_count;
  int errno_on_first;    /* errno set on call 1 (0 = don't override) */
  int errno_on_second;   /* errno set on call 2 */
  mode_t st_mode_first;  /* st_mode on successful first call */
  mode_t st_mode_second; /* st_mode on successful second call */
} _cfg_stat;

static int mock_stat(const char *path, struct stat *st) {
  int call;
  int err;

  (void)path;
  _cfg_stat.call_count++;

  call = _cfg_stat.call_count;
  err = (call == 1) ? _cfg_stat.errno_on_first : _cfg_stat.errno_on_second;

  if (err != 0) {
    errno = err;
    return -1;
  }

  memset(st, 0, sizeof(*st));
  st->st_mode =
      (call == 1) ? _cfg_stat.st_mode_first : _cfg_stat.st_mode_second;
  return 0;
}

/* --- mkdir -----------------------------------------------------------------
 */

static struct {
  int fail_errno; /* 0 = succeed; otherwise errno to set on failure */
} _cfg_mkdir;

static int mock_mkdir(const char *path, mode_t mode) {
  (void)path;
  (void)mode;

  if (_cfg_mkdir.fail_errno != 0) {
    errno = _cfg_mkdir.fail_errno;
    return -1;
  }
  return 0;
}

/* --- mkostemp --------------------------------------------------------------
 */

static struct {
  int fail;                     /* 1 = return -1 */
  int fd;                       /* fd to return on success */
  char captured_tmpl[PATH_MAX]; /* last template argument seen */
} _cfg_mkostemp;

static int mock_mkostemp(char *tmpl, int flags) {
  (void)flags;
  snprintf(_cfg_mkostemp.captured_tmpl, PATH_MAX, "%s", tmpl);

  if (_cfg_mkostemp.fail) {
    errno = EACCES;
    return -1;
  }
  return _cfg_mkostemp.fd;
}

/* --- fchmod ----------------------------------------------------------------
 */

static struct {
  int fail;
} _cfg_fchmod;

static int mock_fchmod(int fd, mode_t mode) {
  (void)fd;
  (void)mode;

  if (_cfg_fchmod.fail) {
    errno = EPERM;
    return -1;
  }
  return 0;
}

/* --- write -----------------------------------------------------------------
 */

static struct {
  int fail;        /* 1 = return -1 */
  int short_write; /* 1 = return count - 1 (partial write) */
  char captured[CRYPT_OUTPUT_SIZE + 4];
  size_t captured_len;
} _cfg_write;

static ssize_t mock_write(int fd, const void *buf, size_t count) {
  (void)fd;

  if (_cfg_write.fail) {
    errno = EIO;
    return -1;
  }

  /* Capture written content for inspection. */
  if (count < sizeof(_cfg_write.captured)) {
    memcpy(_cfg_write.captured, buf, count);
    _cfg_write.captured_len = count;
  }

  if (_cfg_write.short_write && count > 0) {
    return (ssize_t)(count - 1);
  }
  return (ssize_t)count;
}

/* --- fsync -----------------------------------------------------------------
 */

static struct {
  int fail;
} _cfg_fsync;

static int mock_fsync(int fd) {
  (void)fd;

  if (_cfg_fsync.fail) {
    errno = EIO;
    return -1;
  }
  return 0;
}

/* --- close -----------------------------------------------------------------
 */

static struct {
  int fail;
  int call_count;
} _cfg_close;

static int mock_close(int fd) {
  (void)fd;
  _cfg_close.call_count++;

  if (_cfg_close.fail) {
    errno = EIO;
    return -1;
  }
  return 0;
}

/* --- rename ----------------------------------------------------------------
 */

static struct {
  int fail;
  char captured_dst[PATH_MAX];
} _cfg_rename;

static int mock_rename(const char *oldpath, const char *newpath) {
  (void)oldpath;
  snprintf(_cfg_rename.captured_dst, PATH_MAX, "%s", newpath);

  if (_cfg_rename.fail) {
    errno = EROFS;
    return -1;
  }
  return 0;
}

/* --- unlink ----------------------------------------------------------------
 */

static struct {
  int call_count;
  char captured[PATH_MAX];
} _cfg_unlink;

static int mock_unlink(const char *path) {
  _cfg_unlink.call_count++;
  snprintf(_cfg_unlink.captured, PATH_MAX, "%s", path);
  return 0;
}

/* ============================================================================
 * Fixture Helpers
 * ============================================================================
 */

/**
 * make_happy_hash_ops - Creates syscall_ops wired for hash_password happy path.
 *
 * Wires crypt_gensalt_ra, crypt_checksalt, and crypt_r mocks. getrandom is
 * not wired because generate_salt() passes rbytes=NULL to crypt_gensalt_ra(),
 * letting libxcrypt source its own entropy; getrandom() is never called.
 *
 * Callers override individual config fields to inject specific failures.
 *
 * Returns: Initialized syscall_ops structure.
 */
static struct syscall_ops make_happy_hash_ops(void) {
  struct syscall_ops ops = syscall_ops_default;
  ops.crypt_gensalt_ra = mock_crypt_gensalt_ra;
  ops.crypt_checksalt = mock_crypt_checksalt;
  ops.crypt_r = mock_crypt_r;

  memset(&_cfg_crypt_gensalt_ra, 0, sizeof(_cfg_crypt_gensalt_ra));
  memset(&_cfg_crypt_checksalt, 0, sizeof(_cfg_crypt_checksalt));
  snprintf(_cfg_crypt_gensalt_ra.salt, sizeof(_cfg_crypt_gensalt_ra.salt),
           "$6$rounds=65536$testsalt");
  _cfg_crypt_r.fail = 0;
  _cfg_crypt_r.star = 0;
  snprintf(_cfg_crypt_r.hash, sizeof(_cfg_crypt_r.hash),
           "$6$rounds=65536$testsalt$AAABBBCCC");
  return ops;
}

/**
 * make_happy_atomic_ops - Creates syscall_ops wired for atomic_write happy
 * path.
 *
 * Initializes mkostemp, fchmod, write, fsync, close, rename, and unlink mocks
 * to succeed. Callers override individual fields to inject failures.
 *
 * Returns: Initialized syscall_ops structure.
 */
static struct syscall_ops make_happy_atomic_ops(void) {
  struct syscall_ops ops = syscall_ops_default;
  ops.mkostemp = mock_mkostemp;
  ops.fchmod = mock_fchmod;
  ops.write = mock_write;
  ops.fsync = mock_fsync;
  ops.close = mock_close;
  ops.rename = mock_rename;
  ops.unlink = mock_unlink;

  _cfg_mkostemp.fail = 0;
  _cfg_mkostemp.fd = MOCK_FD;
  _cfg_fchmod.fail = 0;
  _cfg_write.fail = 0;
  _cfg_write.short_write = 0;
  _cfg_fsync.fail = 0;
  _cfg_close.fail = 0;
  _cfg_close.call_count = 0;
  _cfg_rename.fail = 0;
  _cfg_unlink.call_count = 0;
  return ops;
}

/**
 * make_dir_ops - Creates syscall_ops wired for ensure_vnc_dir tests.
 *
 * Wires stat and mkdir mocks and resets their config to zero. Callers set
 * errno_on_first, st_mode_first, fail_errno, etc. to control behaviour.
 *
 * stat (not lstat) is mocked because make_one_dir() calls ops->stat so that
 * symlinks pointing to directories are followed and accepted.
 *
 * Returns: Initialized syscall_ops structure.
 */
static struct syscall_ops make_dir_ops(void) {
  struct syscall_ops ops = syscall_ops_default;
  ops.stat = mock_stat;
  ops.mkdir = mock_mkdir;

  memset(&_cfg_stat, 0, sizeof(_cfg_stat));
  memset(&_cfg_mkdir, 0, sizeof(_cfg_mkdir));
  return ops;
}

/**
 * make_passwd_path_ops - Creates syscall_ops wired for get_passwd_path tests.
 *
 * Default state: stat reports every component as an existing directory;
 * getpwuid_r resolves uid 1000 with home /home/user.
 *
 * Returns: Initialized syscall_ops structure.
 */
static struct syscall_ops make_passwd_path_ops(void) {
  struct syscall_ops ops = syscall_ops_default;
  ops.calloc = mock_calloc;
  ops.getpwuid_r = mock_getpwuid_r;
  ops.stat = mock_stat;
  ops.mkdir = mock_mkdir;

  memset(&_cfg_calloc, 0, sizeof(_cfg_calloc));
  memset(&_cfg_getpwuid_r, 0, sizeof(_cfg_getpwuid_r));
  memset(&_cfg_stat, 0, sizeof(_cfg_stat));
  memset(&_cfg_mkdir, 0, sizeof(_cfg_mkdir));

  /* Default: stat says dir already exists. */
  _cfg_stat.errno_on_first = 0;
  _cfg_stat.st_mode_first = S_IFDIR | 0700;
  _cfg_stat.errno_on_second = 0;
  _cfg_stat.st_mode_second = S_IFDIR | 0700;

  /* Default pw entry: uid 1000, home /home/user. */
  _cfg_getpwuid_r.rc = 0;
  _cfg_getpwuid_r.uid = 1000;
  snprintf(_cfg_getpwuid_r.pw_dir, PATH_MAX, "/home/user");
  return ops;
}

/* ============================================================================
 * Tests: hash_password - Argument validation
 * ============================================================================
 */

TEST(hash_password_null_ops) {
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(NULL, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "NULL ops must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL ops must set EINVAL");
}

TEST(hash_password_null_password) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(&ops, NULL, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "NULL password must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL password must set EINVAL");
}

TEST(hash_password_empty_password) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(&ops, "", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "empty password must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "empty password must set EINVAL");
}

TEST(hash_password_null_hash_buf) {
  struct syscall_ops ops = make_happy_hash_ops();
  int rc;

  rc = hash_password(&ops, "secret", NULL, VNC_HASH_BUF_SIZE);
  TEST_ASSERT_EQ(rc, -1, "NULL hash_buf must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL hash_buf must set EINVAL");
}

TEST(hash_password_zero_hash_len) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(&ops, "secret", buf, 0);
  TEST_ASSERT_EQ(rc, -1, "zero hash_len must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "zero hash_len must set EINVAL");
}

/* ============================================================================
 * Tests: hash_password - Syscall failure propagation
 * ============================================================================
 */

/*
 * hash_password_crypt_gensalt_fail - All crypt_gensalt_ra calls return NULL.
 *
 * With gensalt always failing, every probe in select_prefix() returns NULL and
 * is skipped without calling crypt_checksalt(). select_prefix() falls through
 * to the "$6$" fallback. generate_salt() then calls gensalt("$6$"), which also
 * returns NULL, and returns -1/EINVAL. crypt_checksalt must never be called.
 */
TEST(hash_password_crypt_gensalt_fail) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  _cfg_crypt_gensalt_ra.fail = 1;
  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "crypt_gensalt_ra failure must propagate as -1");
  TEST_ASSERT_EQ(errno, EINVAL, "crypt_gensalt_ra failure must set EINVAL");
  TEST_ASSERT_EQ(_cfg_crypt_checksalt.call_count, 0,
                 "checksalt must not be called when all probes return NULL");
}

TEST(hash_password_crypt_r_returns_null) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  _cfg_crypt_r.fail = 1;
  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "crypt_r NULL must propagate as -1");
  TEST_ASSERT_EQ(errno, EINVAL, "crypt_r failure must set EINVAL");
}

TEST(hash_password_crypt_r_returns_star) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  _cfg_crypt_r.star = 1;
  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "crypt_r '*' result must propagate as -1");
  TEST_ASSERT_EQ(errno, EINVAL, "crypt_r failure must set EINVAL");
}

/* ============================================================================
 * Tests: hash_password - Happy path and edge cases
 * ============================================================================
 */

TEST(hash_password_success) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "happy path must return 0");
  TEST_ASSERT_STR_EQ(buf, _cfg_crypt_r.hash,
                     "hash buf must contain crypt_r output");
}

/*
 * hash_password_hash_buf_too_small - Exercise the crypt_and_copy ERANGE path.
 *
 * crypt_and_copy() calls snprintf(hash_buf, hash_len, "%s", result).
 * With hash_len = 1, any non-empty crypt_r output causes n >= hash_len,
 * triggering the ERANGE branch. The function must zero hash_buf[0] before
 * returning so no partial hash leaks to the caller.
 */
TEST(hash_password_hash_buf_too_small) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(&ops, "secret", buf, 1);
  TEST_ASSERT_EQ(rc, -1, "hash_len=1 must return -1");
  TEST_ASSERT_EQ(errno, ERANGE, "hash_len=1 must set ERANGE");
  TEST_ASSERT_EQ((int)buf[0], 0, "hash_buf must be zeroed on ERANGE");
}

/* ============================================================================
 * Tests: select_prefix - Algorithm selection and fallback
 *
 * select_prefix() is static; it is exercised via hash_password(). Call counts
 * on crypt_gensalt_ra and crypt_checksalt precisely verify iteration depth
 * and short-circuit behaviour for each scenario.
 *
 * Call count arithmetic (N = TEST_SALT_PREFIXES_COUNT):
 *   - select_prefix() calls gensalt once per prefix entry it probes.
 *   - generate_salt() calls gensalt once more after select_prefix() returns.
 *   - crypt_checksalt() is called once per probe that returns a non-NULL salt.
 * ============================================================================
 */

/*
 * select_prefix_first_accepted - crypt_checksalt approves the first probe.
 *
 * gensalt call 1: probe for salt_prefixes[0]; checksalt call 1: accept.
 * select_prefix() returns salt_prefixes[0].
 * gensalt call 2: actual salt in generate_salt().
 */
TEST(select_prefix_first_accepted) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "happy path must return 0");
  TEST_ASSERT_EQ(_cfg_crypt_checksalt.call_count, 1,
                 "first prefix accepted: checksalt called exactly once");
  TEST_ASSERT_EQ(_cfg_crypt_gensalt_ra.call_count, 2,
                 "one probe plus one actual salt generation");
}

/*
 * select_prefix_second_accepted - checksalt rejects the first probe, accepts
 * the second.
 *
 * gensalt call 1: probe[0]; checksalt call 1: reject.
 * gensalt call 2: probe[1]; checksalt call 2: accept.
 * gensalt call 3: actual salt in generate_salt().
 */
TEST(select_prefix_second_accepted) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  _cfg_crypt_checksalt.fail_on_call = 1;
  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "second prefix accepted must return 0");
  TEST_ASSERT_EQ(_cfg_crypt_checksalt.call_count, 2,
                 "second prefix accepted: checksalt called exactly twice");
  TEST_ASSERT_EQ(_cfg_crypt_gensalt_ra.call_count, 3,
                 "two probes plus one actual salt generation");
}

/*
 * select_prefix_all_rejected_uses_fallback - checksalt rejects every probe.
 *
 * select_prefix() exhausts all TEST_SALT_PREFIXES_COUNT entries and returns
 * the "$6$" hardcoded fallback. hash_password() must still succeed because
 * gensalt and crypt_r succeed for that prefix.
 *
 * gensalt calls 1..N: one probe per prefix; checksalt calls 1..N: all reject.
 * gensalt call N+1: actual salt in generate_salt() using the "$6$" fallback.
 */
TEST(select_prefix_all_rejected_uses_fallback) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  _cfg_crypt_checksalt.always_fail = 1;
  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "fallback prefix must still produce a valid hash");
  TEST_ASSERT_EQ(_cfg_crypt_checksalt.call_count, TEST_SALT_PREFIXES_COUNT,
                 "checksalt called once per prefix in the preference list");
  TEST_ASSERT_EQ(_cfg_crypt_gensalt_ra.call_count, TEST_SALT_PREFIXES_COUNT + 1,
                 "one probe per prefix plus one actual salt generation");
}

/*
 * select_prefix_gensalt_probe_fails - crypt_gensalt_ra returns NULL for the
 * first probe. select_prefix() must skip that entry without calling
 * crypt_checksalt() and proceed to the second prefix.
 *
 * gensalt call 1: probe[0] returns NULL; checksalt: not called for this entry.
 * gensalt call 2: probe[1] succeeds; checksalt call 1: accept.
 * gensalt call 3: actual salt in generate_salt().
 */
TEST(select_prefix_gensalt_probe_fails) {
  struct syscall_ops ops = make_happy_hash_ops();
  char buf[VNC_HASH_BUF_SIZE];
  int rc;

  _cfg_crypt_gensalt_ra.fail_on_call = 1;
  rc = hash_password(&ops, "secret", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "NULL probe must be skipped, not propagated");
  TEST_ASSERT_EQ(_cfg_crypt_checksalt.call_count, 1,
                 "checksalt called once: only for the accepted second probe");
  TEST_ASSERT_EQ(_cfg_crypt_gensalt_ra.call_count, 3,
                 "first probe fails, second probe succeeds, one actual salt");
}

/* ============================================================================
 * Tests: ensure_vnc_dir - Argument validation
 * ============================================================================
 */

TEST(ensure_vnc_dir_null_ops) {
  int rc;

  rc = ensure_vnc_dir(NULL, "/home/user/.config/vnc");
  TEST_ASSERT_EQ(rc, -1, "NULL ops must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL ops must set EINVAL");
}

TEST(ensure_vnc_dir_null_path) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  rc = ensure_vnc_dir(&ops, NULL);
  TEST_ASSERT_EQ(rc, -1, "NULL path must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL path must set EINVAL");
}

TEST(ensure_vnc_dir_relative_path) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  rc = ensure_vnc_dir(&ops, "relative/path");
  TEST_ASSERT_EQ(rc, -1, "relative path must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "relative path must set EINVAL");
}

/* ============================================================================
 * Tests: ensure_vnc_dir - Path traversal rejection
 * ============================================================================
 */

TEST(ensure_vnc_dir_dotdot_internal) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  rc = ensure_vnc_dir(&ops, "/home/user/../../etc");
  TEST_ASSERT_EQ(rc, -1, "internal /../ must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "internal /../ must set EINVAL");
}

TEST(ensure_vnc_dir_dotdot_trailing) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  rc = ensure_vnc_dir(&ops, "/home/user/..");
  TEST_ASSERT_EQ(rc, -1, "trailing /.. must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "trailing /.. must set EINVAL");
}

/*
 * ensure_vnc_dir_dotdot_exactly_three - path is exactly "/..".
 *
 * plen == 3 satisfies plen >= 3. strcmp(path + 0, "/..") == 0 is true.
 * strstr also finds no "/../" (path is only 3 chars, sequence needs 4).
 * The trailing-/.. branch triggers; must return -1 / EINVAL.
 */
TEST(ensure_vnc_dir_dotdot_exactly_three) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  rc = ensure_vnc_dir(&ops, "/..");
  TEST_ASSERT_EQ(rc, -1, "path == /.. must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "path == /.. must set EINVAL");
}

/*
 * ensure_vnc_dir_dotdot_short_path - plen < 3 skips the trailing-/.. branch.
 *
 * A two-character absolute path ("/a") cannot end in "/.." (which is 3 chars),
 * so the RHS of the || is never evaluated. The condition is false; the path
 * passes the dotdot check and reaches snprintf. snprintf copies "/a" into tmp
 * without truncation; the loop body is never entered (no '/' after tmp+1);
 * make_one_dir is called for "/a". With stat returning ENOENT and mkdir
 * succeeding the function returns 0.
 */
TEST(ensure_vnc_dir_dotdot_short_path) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_mkdir.fail_errno = 0;
  rc = ensure_vnc_dir(&ops, "/a");
  TEST_ASSERT_EQ(rc, 0, "two-char path must not trigger dotdot check");
}

/*
 * ensure_vnc_dir_dotdot_in_component_name - "/.." must only be rejected when
 * it appears as a complete path component, not when ".." is embedded inside a
 * longer component name (e.g. "/home/..config/vnc").
 *
 * strstr(path, "/../") looks for the four-byte sequence "/../"; a component
 * named "..config" contains ".." but not "/../", so strstr returns NULL.
 * The trailing check looks for the path ending exactly in "/.."; "..config"
 * does not match. Both conditions are false; the path must be accepted.
 */
TEST(ensure_vnc_dir_dotdot_in_component_name) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_stat.errno_on_second = ENOENT;
  _cfg_mkdir.fail_errno = 0;
  rc = ensure_vnc_dir(&ops, "/home/..config");
  TEST_ASSERT_EQ(rc, 0, "dotdot embedded in name must not be rejected");
}

/* ============================================================================
 * Tests: ensure_vnc_dir - Directory creation and existence
 * ============================================================================
 */

TEST(ensure_vnc_dir_already_exists) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  /* stat says every component exists as a directory. */
  _cfg_stat.errno_on_first = 0;
  _cfg_stat.st_mode_first = S_IFDIR | 0700;
  _cfg_stat.errno_on_second = 0;
  _cfg_stat.st_mode_second = S_IFDIR | 0700;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, 0, "pre-existing dir must return 0");
}

TEST(ensure_vnc_dir_creates_missing) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  /* stat: ENOENT for every component; mkdir succeeds. */
  _cfg_stat.errno_on_first = ENOENT;
  _cfg_stat.errno_on_second = ENOENT;
  _cfg_mkdir.fail_errno = 0;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, 0, "missing dir must be created and return 0");
}

TEST(ensure_vnc_dir_exists_as_nondir) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  /*
   * stat returns S_IFREG: a regular file blocks the path. Symlinks are
   * accepted (stat follows them); only non-symlink, non-directory entries
   * must be rejected with ENOTDIR.
   */
  _cfg_stat.errno_on_first = 0;
  _cfg_stat.st_mode_first = S_IFREG | 0644;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, -1, "file where dir expected must return -1");
  TEST_ASSERT_EQ(errno, ENOTDIR, "file where dir expected must set ENOTDIR");
}

/*
 * ensure_vnc_dir_exists_as_symlink - stat returns S_IFLNK at an existing path.
 *
 * make_one_dir() calls stat(2), which follows symlinks; it only returns
 * S_IFLNK for dangling symlinks. Symlinks must be accepted regardless —
 * returning ENOTDIR here would break the common case of ~/.config/vnc being a
 * managed symlink. The test also guards against any future explicit S_IFLNK
 * rejection being added to make_one_dir().
 */
/*
 * ensure_vnc_dir_exists_as_symlink - stat returns S_IFLNK at an existing path.
 *
 * make_one_dir() calls stat(2), which follows symlinks; it only returns
 * S_IFLNK for dangling symlinks. Symlinks must be accepted regardless —
 * returning ENOTDIR here would break the common case of ~/.config/vnc being a
 * managed symlink. The test also guards against any future explicit S_IFLNK
 * rejection being added to make_one_dir().
 *
 * Path "/a/b" has two components so mock_stat is called twice: once for the
 * intermediate "/a" and once for the final "/a/b". Both calls must return
 * S_IFLNK so neither component triggers ENOTDIR.
 */
TEST(ensure_vnc_dir_exists_as_symlink) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = 0;
  _cfg_stat.st_mode_first = S_IFLNK | 0777;
  _cfg_stat.errno_on_second = 0;
  _cfg_stat.st_mode_second = S_IFLNK | 0777;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, 0, "symlink must be accepted, not rejected with ENOTDIR");
}

/*
 * ensure_vnc_dir_mkdir_eexist_then_symlink - TOCTOU race resolves to a symlink.
 *
 * stat -> ENOENT, mkdir -> EEXIST (racing creator), re-stat returns S_IFLNK.
 * make_one_dir must accept the symlink on the re-stat path for the same
 * reasons as ensure_vnc_dir_exists_as_symlink.
 */
TEST(ensure_vnc_dir_mkdir_eexist_then_symlink) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_stat.errno_on_second = 0;
  _cfg_stat.st_mode_second = S_IFLNK | 0777;
  _cfg_mkdir.fail_errno = EEXIST;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, 0, "EEXIST race resolved to symlink must return 0");
}

/*
 * ensure_vnc_dir_mkdir_eexist_then_dir - Simulate the TOCTOU path.
 *
 * stat says ENOENT, mkdir returns EEXIST (racing creator), re-stat
 * confirms it is a directory.
 */
TEST(ensure_vnc_dir_mkdir_eexist_then_dir) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT; /* initial stat: not found */
  _cfg_stat.errno_on_second = 0;     /* re-stat after EEXIST: found */
  _cfg_stat.st_mode_second = S_IFDIR | 0700;
  _cfg_mkdir.fail_errno = EEXIST;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, 0, "EEXIST race resolved to dir must return 0");
}

TEST(ensure_vnc_dir_mkdir_eexist_then_nondir) {
  /* Racing creator made a non-directory: must fail. */
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_stat.errno_on_second = 0;
  _cfg_stat.st_mode_second = S_IFREG | 0600;
  _cfg_mkdir.fail_errno = EEXIST;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, -1, "EEXIST race resolved to file must return -1");
  TEST_ASSERT_EQ(errno, ENOTDIR, "must set ENOTDIR");
}

/* ============================================================================
 * Tests: ensure_vnc_dir - Syscall failure propagation
 * ============================================================================
 */

TEST(ensure_vnc_dir_mkdir_fails_not_eexist) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_mkdir.fail_errno = EACCES;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, -1, "non-EEXIST mkdir failure must return -1");
  TEST_ASSERT_EQ(errno, EACCES, "errno must be propagated from mkdir");
}

/*
 * ensure_vnc_dir_mkdir_fails_emits_diagnostic - Verify that make_one_dir
 * writes to stderr when mkdir(2) fails for a reason other than EEXIST.
 *
 * Redirect stderr to a pipe before the call, restore it after, then check
 * that at least one byte was written. Content is not inspected; presence is
 * enough to confirm the fprintf path was reached.
 */
TEST(ensure_vnc_dir_mkdir_fails_emits_diagnostic) {
  struct syscall_ops ops = make_dir_ops();
  int pipefd[2];
  int saved_stderr;
  int rc;
  char buf[256];
  ssize_t n;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_mkdir.fail_errno = EACCES;

  TEST_ASSERT_EQ(pipe(pipefd), 0, "pipe() must succeed");

  saved_stderr = dup(STDERR_FILENO);
  TEST_ASSERT_EQ(dup2(pipefd[1], STDERR_FILENO), STDERR_FILENO,
                 "dup2() must redirect stderr");
  close(pipefd[1]);

  rc = ensure_vnc_dir(&ops, "/a/b");
  fflush(stderr);

  dup2(saved_stderr, STDERR_FILENO);
  close(saved_stderr);

  n = read(pipefd[0], buf, sizeof(buf));
  close(pipefd[0]);

  TEST_ASSERT_EQ(rc, -1, "failure must return -1");
  TEST_ASSERT_EQ(n > 0, 1, "stderr must contain at least one byte");
}

/*
 * ensure_vnc_dir_stat_fails_not_enoent - Exercise make_one_dir lines 283-284.
 *
 * When the initial stat() returns an error other than ENOENT, make_one_dir()
 * must propagate that error immediately without calling mkdir().
 */
TEST(ensure_vnc_dir_stat_fails_not_enoent) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = EACCES;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, -1, "stat EACCES must return -1");
  TEST_ASSERT_EQ(errno, EACCES, "stat EACCES errno must be preserved");
}

/*
 * ensure_vnc_dir_mkdir_eexist_restat_fails - Race path.
 *
 * stat -> ENOENT, mkdir -> EEXIST, re-stat -> EACCES.
 * make_one_dir must propagate the re-stat failure.
 */
TEST(ensure_vnc_dir_mkdir_eexist_restat_fails) {
  struct syscall_ops ops = make_dir_ops();
  int rc;

  _cfg_stat.errno_on_first = ENOENT;
  _cfg_stat.errno_on_second = EACCES;
  _cfg_mkdir.fail_errno = EEXIST;
  rc = ensure_vnc_dir(&ops, "/a/b");
  TEST_ASSERT_EQ(rc, -1, "re-stat failure after EEXIST must return -1");
  TEST_ASSERT_EQ(errno, EACCES, "re-stat errno must be preserved");
}

/* ============================================================================
 * Tests: ensure_vnc_dir - Buffer overflow protection
 * ============================================================================
 */

/*
 * ensure_vnc_dir_path_too_long - Exercise ensure_vnc_dir ERANGE path.
 *
 * The internal tmp[] buffer is PATH_MAX bytes. A path whose strlen equals
 * PATH_MAX causes snprintf to return PATH_MAX, satisfying (size_t)n >=
 * sizeof(tmp) and triggering ERANGE.
 */
TEST(ensure_vnc_dir_path_too_long) {
  struct syscall_ops ops = make_dir_ops();
  char long_path[PATH_MAX + 1];
  int rc;

  long_path[0] = '/';
  memset(long_path + 1, 'a', PATH_MAX - 1);
  long_path[PATH_MAX] = '\0'; /* strlen == PATH_MAX */
  rc = ensure_vnc_dir(&ops, long_path);
  TEST_ASSERT_EQ(rc, -1, "path of length PATH_MAX must return -1");
  TEST_ASSERT_EQ(errno, ERANGE, "path of length PATH_MAX must set ERANGE");
}

/* ============================================================================
 * Tests: atomic_write_passwd_file - Argument validation
 * ============================================================================
 */

TEST(atomic_write_null_ops) {
  int rc;

  rc = atomic_write_passwd_file(NULL, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "NULL ops must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL ops must set EINVAL");
}

TEST(atomic_write_null_path) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  rc = atomic_write_passwd_file(&ops, NULL, "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "NULL path must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL path must set EINVAL");
}

TEST(atomic_write_null_hash) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  rc = atomic_write_passwd_file(&ops, "/some/path", NULL);
  TEST_ASSERT_EQ(rc, -1, "NULL hash must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL hash must set EINVAL");
}

/* ============================================================================
 * Tests: atomic_write_passwd_file - Syscall failure and cleanup
 * ============================================================================
 */

TEST(atomic_write_mkostemp_fails) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_mkostemp.fail = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "mkostemp failure must return -1");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 0, "no unlink before mkostemp");
  TEST_ASSERT_EQ(errno, EACCES, "errno remains from caller");
}

TEST(atomic_write_fchmod_fails_unlinks_tmp) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_fchmod.fail = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "fchmod failure must return -1");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 1,
                 "tmp file must be unlinked on fchmod failure");
  TEST_ASSERT_EQ(errno, EPERM, "original fchmod errno must be restored");
}

TEST(atomic_write_write_fails_unlinks_tmp) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_write.fail = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "write failure must return -1");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 1,
                 "tmp file must be unlinked on write failure");
  TEST_ASSERT_EQ(errno, EIO, "errno remains from caller");
}

TEST(atomic_write_short_write_unlinks_tmp) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_write.short_write = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "short write must return -1");
  TEST_ASSERT_EQ(errno, EIO, "short write must set EIO");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 1,
                 "tmp file must be unlinked on short write");
}

TEST(atomic_write_fsync_fails_unlinks_tmp) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_fsync.fail = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "fsync failure must return -1");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 1,
                 "tmp file must be unlinked on fsync failure");
  TEST_ASSERT_EQ(errno, EIO, "errno remains from caller");
}

TEST(atomic_write_close_fails_unlinks_tmp) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_close.fail = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "close failure must return -1");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 1,
                 "tmp file must be unlinked on close failure");
  TEST_ASSERT_EQ(errno, EIO, "errno remains from caller");
}

TEST(atomic_write_rename_fails_unlinks_tmp) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  _cfg_rename.fail = 1;
  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "rename failure must return -1");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 1,
                 "tmp file must be unlinked on rename failure");
  TEST_ASSERT_EQ(errno, EROFS, "errno remains from caller");
}

/* ============================================================================
 * Tests: atomic_write_passwd_file - Happy path and content validation
 * ============================================================================
 */

TEST(atomic_write_success) {
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(rc, 0, "happy path must return 0");
  TEST_ASSERT_EQ(_cfg_unlink.call_count, 0, "no unlink on success");
  TEST_ASSERT_STR_EQ(_cfg_rename.captured_dst, "/some/path",
                     "rename destination must be the target path");
}

TEST(atomic_write_content_has_newline) {
  /* The written content must be hash + '\n'. */
  struct syscall_ops ops = make_happy_atomic_ops();
  const char *hash = "$6$rounds=65536$x$AABBCC";
  size_t expected_len;
  int rc;

  rc = atomic_write_passwd_file(&ops, "/some/path", hash);
  expected_len = strlen(hash) + 1; /* +1 for '\n' */
  TEST_ASSERT_EQ(_cfg_write.captured_len, expected_len,
                 "written length must be hash + newline");
  TEST_ASSERT_EQ((int)_cfg_write.captured[expected_len - 1], (int)'\n',
                 "last written byte must be newline");
  TEST_ASSERT_EQ(rc, 0, "happy path must return 0");
}

TEST(atomic_write_tmp_path_template) {
  /* Temp file must be named <path>.XXXXXX to stay in the same directory. */
  struct syscall_ops ops = make_happy_atomic_ops();
  int rc;

  rc = atomic_write_passwd_file(&ops, "/some/path", "$6$hash");
  TEST_ASSERT_EQ(
      strncmp(_cfg_mkostemp.captured_tmpl, "/some/path", strlen("/some/path")),
      0, "mkostemp template must start with target path");
  TEST_ASSERT_EQ(rc, 0, "happy path must return 0");
}

/* ============================================================================
 * Tests: atomic_write_passwd_file - Buffer overflow protection
 * ============================================================================
 */

/*
 * atomic_write_tmp_path_too_long - Exercise atomic_write_passwd_file
 * path-length check.
 *
 * tmp_path[] is PATH_MAX bytes; the template suffix ".XXXXXX" is 7 chars.
 * A path of strlen PATH_MAX - 7 produces a template of strlen PATH_MAX,
 * so snprintf returns PATH_MAX >= sizeof(tmp_path), triggering ERANGE.
 */
TEST(atomic_write_tmp_path_too_long) {
  struct syscall_ops ops = make_happy_atomic_ops();
  char long_path[PATH_MAX];
  int rc;

  long_path[0] = '/';
  memset(long_path + 1, 'a', PATH_MAX - 8); /* strlen = PATH_MAX - 7 */
  long_path[PATH_MAX - 7] = '\0';
  rc = atomic_write_passwd_file(&ops, long_path, "$6$hash");
  TEST_ASSERT_EQ(rc, -1, "path leaving no room for .XXXXXX must return -1");
  TEST_ASSERT_EQ(errno, ERANGE, "must set ERANGE");
}

/*
 * atomic_write_line_too_long - Exercise atomic_write_passwd_file line-buffer
 * overflow check.
 *
 * line[] is CRYPT_OUTPUT_SIZE + 2 bytes; the format is "%s\n", so snprintf
 * returns strlen(hash) + 1. A hash of length CRYPT_OUTPUT_SIZE + 1 makes
 * that value equal to CRYPT_OUTPUT_SIZE + 2 >= sizeof(line), triggering
 * ERANGE.
 */
TEST(atomic_write_line_too_long) {
  struct syscall_ops ops = make_happy_atomic_ops();
  char long_hash[CRYPT_OUTPUT_SIZE + 2];
  int rc;

  memset(long_hash, 'A', CRYPT_OUTPUT_SIZE + 1);
  long_hash[CRYPT_OUTPUT_SIZE + 1] = '\0';
  rc = atomic_write_passwd_file(&ops, "/some/path", long_hash);
  TEST_ASSERT_EQ(rc, -1, "hash too long for line buffer must return -1");
  TEST_ASSERT_EQ(errno, ERANGE, "must set ERANGE");
}

/* ============================================================================
 * Tests: get_passwd_path - Argument validation
 * ============================================================================
 */

TEST(get_passwd_path_null_ops) {
  char buf[PATH_MAX];
  int rc;

  rc = get_passwd_path(NULL, 1000, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "NULL ops must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL ops must set EINVAL");
}

TEST(get_passwd_path_null_buf) {
  struct syscall_ops ops = make_passwd_path_ops();
  int rc;

  rc = get_passwd_path(&ops, 1000, NULL, PATH_MAX);
  TEST_ASSERT_EQ(rc, -1, "NULL buf must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL buf must set EINVAL");
}

TEST(get_passwd_path_zero_buflen) {
  struct syscall_ops ops = make_passwd_path_ops();
  char buf[PATH_MAX];
  int rc;

  rc = get_passwd_path(&ops, 1000, buf, 0);
  TEST_ASSERT_EQ(rc, -1, "zero buflen must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "zero buflen must set EINVAL");
}

/* ============================================================================
 * Tests: get_passwd_path - Syscall failure propagation
 * ============================================================================
 */

TEST(get_passwd_path_calloc_fails) {
  struct syscall_ops ops = make_passwd_path_ops();
  char buf[PATH_MAX];
  int rc;

  _cfg_calloc.fail = 1;
  rc = get_passwd_path(&ops, 1000, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "calloc failure must return -1");
  TEST_ASSERT_EQ(errno, ENOMEM, "calloc failure must set ENOMEM");
}

TEST(get_passwd_path_getpwuid_r_fails) {
  struct syscall_ops ops = make_passwd_path_ops();
  char buf[PATH_MAX];
  int rc;

  _cfg_getpwuid_r.rc = ENOENT;
  rc = get_passwd_path(&ops, 1000, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "getpwuid_r error must return -1");
}

TEST(get_passwd_path_getpwuid_r_no_result) {
  struct syscall_ops ops = make_passwd_path_ops();
  char buf[PATH_MAX];
  int rc;

  _cfg_getpwuid_r.no_result = 1;
  rc = get_passwd_path(&ops, 1000, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "getpwuid_r NULL result must return -1");
  TEST_ASSERT_EQ(errno, ENOENT, "missing user must set ENOENT");
}

/*
 * get_passwd_path_ensure_dir_fails - Verify ensure_vnc_dir failure propagation
 * through get_passwd_path.
 *
 * getpwuid_r succeeds; stat on the first path component returns EACCES so
 * ensure_vnc_dir -> make_one_dir propagates the error back to get_passwd_path.
 */
TEST(get_passwd_path_ensure_dir_fails) {
  struct syscall_ops ops = make_passwd_path_ops();
  char buf[PATH_MAX];
  int rc;

  _cfg_stat.errno_on_first = EACCES;
  rc = get_passwd_path(&ops, 1000, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "ensure_dir EACCES must propagate as -1");
  TEST_ASSERT_EQ(errno, EACCES, "errno must be EACCES");
}

/* ============================================================================
 * Tests: get_passwd_path - Happy path
 * ============================================================================
 */

TEST(get_passwd_path_success) {
  struct syscall_ops ops = make_passwd_path_ops();
  char buf[PATH_MAX];
  char expected[PATH_MAX];
  int rc;

  snprintf(expected, sizeof(expected), "/home/user/%s/%s", VNC_PASSWD_DIR,
           VNC_PASSWD_FILENAME);
  rc = get_passwd_path(&ops, 1000, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "happy path must return 0");
  TEST_ASSERT_STR_EQ(buf, expected,
                     "path must point to per-user vnc passwd file");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* hash_password: argument validation */
  RUN_TEST(hash_password_null_ops);
  RUN_TEST(hash_password_null_password);
  RUN_TEST(hash_password_empty_password);
  RUN_TEST(hash_password_null_hash_buf);
  RUN_TEST(hash_password_zero_hash_len);

  /* hash_password: syscall failure propagation */
  RUN_TEST(hash_password_crypt_gensalt_fail);
  RUN_TEST(hash_password_crypt_r_returns_null);
  RUN_TEST(hash_password_crypt_r_returns_star);

  /* hash_password: happy path and edge cases */
  RUN_TEST(hash_password_success);
  RUN_TEST(hash_password_hash_buf_too_small);

  /* select_prefix: algorithm selection and fallback */
  RUN_TEST(select_prefix_first_accepted);
  RUN_TEST(select_prefix_second_accepted);
  RUN_TEST(select_prefix_all_rejected_uses_fallback);
  RUN_TEST(select_prefix_gensalt_probe_fails);

  /* ensure_vnc_dir: argument validation */
  RUN_TEST(ensure_vnc_dir_null_ops);
  RUN_TEST(ensure_vnc_dir_null_path);
  RUN_TEST(ensure_vnc_dir_relative_path);

  /* ensure_vnc_dir: path traversal rejection */
  RUN_TEST(ensure_vnc_dir_dotdot_internal);
  RUN_TEST(ensure_vnc_dir_dotdot_trailing);
  RUN_TEST(ensure_vnc_dir_dotdot_exactly_three);
  RUN_TEST(ensure_vnc_dir_dotdot_short_path);
  RUN_TEST(ensure_vnc_dir_dotdot_in_component_name);

  /* ensure_vnc_dir: directory creation and existence */
  RUN_TEST(ensure_vnc_dir_already_exists);
  RUN_TEST(ensure_vnc_dir_creates_missing);
  RUN_TEST(ensure_vnc_dir_exists_as_nondir);
  RUN_TEST(ensure_vnc_dir_exists_as_symlink);
  RUN_TEST(ensure_vnc_dir_mkdir_eexist_then_dir);
  RUN_TEST(ensure_vnc_dir_mkdir_eexist_then_symlink);
  RUN_TEST(ensure_vnc_dir_mkdir_eexist_then_nondir);

  /* ensure_vnc_dir: syscall failure propagation */
  RUN_TEST(ensure_vnc_dir_mkdir_fails_not_eexist);
  RUN_TEST(ensure_vnc_dir_mkdir_fails_emits_diagnostic);
  RUN_TEST(ensure_vnc_dir_stat_fails_not_enoent);
  RUN_TEST(ensure_vnc_dir_mkdir_eexist_restat_fails);

  /* ensure_vnc_dir: buffer overflow protection */
  RUN_TEST(ensure_vnc_dir_path_too_long);

  /* atomic_write_passwd_file: argument validation */
  RUN_TEST(atomic_write_null_ops);
  RUN_TEST(atomic_write_null_path);
  RUN_TEST(atomic_write_null_hash);

  /* atomic_write_passwd_file: syscall failure and cleanup */
  RUN_TEST(atomic_write_mkostemp_fails);
  RUN_TEST(atomic_write_fchmod_fails_unlinks_tmp);
  RUN_TEST(atomic_write_write_fails_unlinks_tmp);
  RUN_TEST(atomic_write_short_write_unlinks_tmp);
  RUN_TEST(atomic_write_fsync_fails_unlinks_tmp);
  RUN_TEST(atomic_write_close_fails_unlinks_tmp);
  RUN_TEST(atomic_write_rename_fails_unlinks_tmp);

  /* atomic_write_passwd_file: happy path and content validation */
  RUN_TEST(atomic_write_success);
  RUN_TEST(atomic_write_content_has_newline);
  RUN_TEST(atomic_write_tmp_path_template);

  /* atomic_write_passwd_file: buffer overflow protection */
  RUN_TEST(atomic_write_tmp_path_too_long);
  RUN_TEST(atomic_write_line_too_long);

  /* get_passwd_path: argument validation */
  RUN_TEST(get_passwd_path_null_ops);
  RUN_TEST(get_passwd_path_null_buf);
  RUN_TEST(get_passwd_path_zero_buflen);

  /* get_passwd_path: syscall failure propagation */
  RUN_TEST(get_passwd_path_calloc_fails);
  RUN_TEST(get_passwd_path_getpwuid_r_fails);
  RUN_TEST(get_passwd_path_getpwuid_r_no_result);
  RUN_TEST(get_passwd_path_ensure_dir_fails);

  /* get_passwd_path: happy path */
  RUN_TEST(get_passwd_path_success);

  result = TEST_EXECUTE();
  return result;
}
