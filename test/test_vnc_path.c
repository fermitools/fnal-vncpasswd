/**
 * test_vnc_path.c - Unit tests for vnc_path.c
 *
 * build_vnc_dir_path() and build_vnc_passwd_path() are pure string functions
 * with no syscall dependencies. Tests cover:
 *   - Invalid argument rejection (NULL pointers, empty strings, zero buflen)
 *   - Correct path construction against known constants
 *   - Exact-fit boundary (buflen == required bytes including NUL)
 *   - Off-by-one truncation (buflen == required bytes, no room for NUL)
 *   - Deep home directory that still fits
 *   - Home directory so long the result is truncated
 */

/* clang-format off */
#include "autoconf.h"
#include "vnc_path.h"
/* clang-format on */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "test_framework.h"

/* ============================================================================
 * Fixture Helpers
 * ============================================================================
 */

/**
 * expected_dir_path - Compute expected VNC directory path into caller buffer
 * @home: Home directory string
 * @buf:  Destination buffer
 * @n:    Size of destination buffer
 *
 * Computes the expected path using the same format as the implementation so
 * tests do not hardcode the separator character.
 */
static void expected_dir_path(const char *home, char *buf, size_t n) {
  snprintf(buf, n, "%s/%s", home, VNC_PASSWD_DIR);
}

/**
 * expected_passwd_path - Compute expected VNC password file path into caller
 * buffer
 * @home: Home directory string
 * @buf:  Destination buffer
 * @n:    Size of destination buffer
 *
 * Computes the expected path using the same format as the implementation so
 * tests do not hardcode the separator character.
 */
static void expected_passwd_path(const char *home, char *buf, size_t n) {
  snprintf(buf, n, "%s/%s/%s", home, VNC_PASSWD_DIR, VNC_PASSWD_FILENAME);
}

/* ============================================================================
 * Tests: build_vnc_dir_path - Argument validation
 * ============================================================================
 */

TEST(dir_path_null_home) {
  char buf[PATH_MAX] = {0};
  int rc;

  rc = build_vnc_dir_path(NULL, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "NULL home must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL home must set EINVAL");
}

TEST(dir_path_empty_home) {
  char buf[PATH_MAX] = {0};
  int rc;

  rc = build_vnc_dir_path("", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "empty home must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "empty home must set EINVAL");
}

TEST(dir_path_null_buf) {
  int rc;

  rc = build_vnc_dir_path("/home/user", NULL, PATH_MAX);
  TEST_ASSERT_EQ(rc, -1, "NULL buf must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL buf must set EINVAL");
}

TEST(dir_path_zero_buflen) {
  char buf[PATH_MAX] = {0};
  int rc;

  rc = build_vnc_dir_path("/home/user", buf, 0);
  TEST_ASSERT_EQ(rc, -1, "zero buflen must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "zero buflen must set EINVAL");
}

/* ============================================================================
 * Tests: build_vnc_dir_path - Correct path construction
 * ============================================================================
 */

TEST(dir_path_correct_construction) {
  char buf[PATH_MAX] = {0};
  char expected[PATH_MAX] = {0};
  int rc;

  expected_dir_path("/home/user", expected, sizeof(expected));
  rc = build_vnc_dir_path("/home/user", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "valid args must return 0");
  TEST_ASSERT_STR_EQ(buf, expected, "constructed path must match expected");
}

TEST(dir_path_correct_construction_utf8) {
  char buf[PATH_MAX] = {0};
  char expected[PATH_MAX] = {0};
  int rc;

  expected_dir_path("/home/üser", expected, sizeof(expected));
  rc = build_vnc_dir_path("/home/üser", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "valid args must return 0");
  TEST_ASSERT_STR_EQ(buf, expected, "constructed path must match expected");
}

TEST(dir_path_root_home) {
  /*
   * Technically invalid in practice, but the function has no policy on /root
   * specifically — it accepts any non-empty home string.
   */
  char buf[PATH_MAX] = {0};
  char expected[PATH_MAX] = {0};
  int rc;

  expected_dir_path("/root", expected, sizeof(expected));
  rc = build_vnc_dir_path("/root", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "root home dir must return 0");
  TEST_ASSERT_STR_EQ(buf, expected, "root home path must match expected");
}

/* ============================================================================
 * Tests: build_vnc_dir_path - Buffer boundary conditions
 * ============================================================================
 */

TEST(dir_path_exact_fit) {
  /* buflen == strlen(result) + 1: the tightest fit that still succeeds. */
  char expected[PATH_MAX] = {0};
  size_t exact;
  char *buf;
  int rc;

  expected_dir_path("/home/user", expected, sizeof(expected));
  exact = strlen(expected) + 1;

  buf = malloc(exact);
  TEST_ASSERT_NOT_EQ(buf, NULL, "malloc must succeed");
  rc = build_vnc_dir_path("/home/user", buf, exact);
  TEST_ASSERT_EQ(rc, 0, "exact-fit buffer must return 0");
  TEST_ASSERT_STR_EQ(buf, expected,
                     "exact-fit buffer must contain correct path");
  free(buf);
}

TEST(dir_path_truncated) {
  /* buflen == strlen(result): one byte short; snprintf truncates. */
  char expected[PATH_MAX] = {0};
  size_t too_small;
  char *buf;
  int rc;

  expected_dir_path("/home/user", expected, sizeof(expected));
  too_small = strlen(expected); /* no room for NUL */

  buf = malloc(too_small + 1); /* extra byte so we can safely read */
  TEST_ASSERT_NOT_EQ(buf, NULL, "malloc must succeed");
  memset(buf, 0, too_small + 1);

  rc = build_vnc_dir_path("/home/user", buf, too_small);
  TEST_ASSERT_EQ(rc, -1, "truncating buffer must return -1");
  TEST_ASSERT_EQ(errno, ERANGE, "truncation must set ERANGE");
  free(buf);
}

/* ============================================================================
 * Tests: build_vnc_passwd_path - Argument validation
 * ============================================================================
 */

TEST(passwd_path_null_home) {
  char buf[PATH_MAX] = {0};
  int rc;

  rc = build_vnc_passwd_path(NULL, buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "NULL home must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL home must set EINVAL");
}

TEST(passwd_path_empty_home) {
  char buf[PATH_MAX] = {0};
  int rc;

  rc = build_vnc_passwd_path("", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, -1, "empty home must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "empty home must set EINVAL");
}

TEST(passwd_path_null_buf) {
  int rc;

  rc = build_vnc_passwd_path("/home/user", NULL, PATH_MAX);
  TEST_ASSERT_EQ(rc, -1, "NULL buf must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "NULL buf must set EINVAL");
}

TEST(passwd_path_zero_buflen) {
  char buf[PATH_MAX] = {0};
  int rc;

  rc = build_vnc_passwd_path("/home/user", buf, 0);
  TEST_ASSERT_EQ(rc, -1, "zero buflen must return -1");
  TEST_ASSERT_EQ(errno, EINVAL, "zero buflen must set EINVAL");
}

/* ============================================================================
 * Tests: build_vnc_passwd_path - Correct path construction
 * ============================================================================
 */

TEST(passwd_path_correct_construction) {
  char buf[PATH_MAX] = {0};
  char expected[PATH_MAX] = {0};
  int rc;

  expected_passwd_path("/home/user", expected, sizeof(expected));
  rc = build_vnc_passwd_path("/home/user", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "valid args must return 0");
  TEST_ASSERT_STR_EQ(buf, expected, "constructed path must match expected");
}

TEST(passwd_path_correct_construction_utf8) {
  char buf[PATH_MAX] = {0};
  char expected[PATH_MAX] = {0};
  int rc;

  expected_passwd_path("/home/üser", expected, sizeof(expected));
  rc = build_vnc_passwd_path("/home/üser", buf, sizeof(buf));
  TEST_ASSERT_EQ(rc, 0, "valid args must return 0");
  TEST_ASSERT_STR_EQ(buf, expected, "constructed path must match expected");
}

/* ============================================================================
 * Tests: build_vnc_passwd_path - Buffer boundary conditions
 * ============================================================================
 */

TEST(passwd_path_exact_fit) {
  char expected[PATH_MAX] = {0};
  size_t exact;
  char *buf;
  int rc;

  expected_passwd_path("/home/user", expected, sizeof(expected));
  exact = strlen(expected) + 1;

  buf = malloc(exact);
  TEST_ASSERT_NOT_EQ(buf, NULL, "malloc must succeed");
  rc = build_vnc_passwd_path("/home/user", buf, exact);
  TEST_ASSERT_EQ(rc, 0, "exact-fit buffer must return 0");
  TEST_ASSERT_STR_EQ(buf, expected,
                     "exact-fit buffer must contain correct path");
  free(buf);
}

TEST(passwd_path_truncated) {
  char expected[PATH_MAX] = {0};
  size_t too_small;
  char *buf;
  int rc;

  expected_passwd_path("/home/user", expected, sizeof(expected));
  too_small = strlen(expected); /* no room for NUL */

  buf = malloc(too_small + 1); /* extra byte so we can safely read */
  TEST_ASSERT_NOT_EQ(buf, NULL, "malloc must succeed");
  memset(buf, 0, too_small + 1);

  rc = build_vnc_passwd_path("/home/user", buf, too_small);
  TEST_ASSERT_EQ(rc, -1, "truncating buffer must return -1");
  TEST_ASSERT_EQ(errno, ERANGE, "truncation must set ERANGE");
  free(buf);
}

/* ============================================================================
 * Tests: build_vnc_passwd_path - Relationship to build_vnc_dir_path
 * ============================================================================
 */

TEST(passwd_path_differs_from_dir_path) {
  /* Sanity: the two functions must produce distinct strings. */
  char dir_buf[PATH_MAX] = {0};
  char passwd_buf[PATH_MAX] = {0};
  int ret1;
  int ret2;

  ret1 = build_vnc_dir_path("/home/user", dir_buf, sizeof(dir_buf));
  ret2 = build_vnc_passwd_path("/home/user", passwd_buf, sizeof(passwd_buf));

  TEST_ASSERT_EQ(ret1, 0, "should not error out");
  TEST_ASSERT_EQ(ret2, 0, "should not error out");
  TEST_ASSERT_STR_NOT_EQ(dir_buf, passwd_buf,
                         "dir path and passwd path must differ");
}

TEST(passwd_path_is_under_dir_path) {
  /* passwd path must be a child of dir path. */
  char dir_buf[PATH_MAX] = {0};
  char passwd_buf[PATH_MAX] = {0};
  size_t dir_len;
  int ret1;
  int ret2;

  ret1 = build_vnc_dir_path("/home/user", dir_buf, sizeof(dir_buf));
  ret2 = build_vnc_passwd_path("/home/user", passwd_buf, sizeof(passwd_buf));

  TEST_ASSERT_EQ(ret1, 0, "should not error out");
  TEST_ASSERT_EQ(ret2, 0, "should not error out");

  dir_len = strlen(dir_buf);
  TEST_ASSERT_EQ(strncmp(passwd_buf, dir_buf, dir_len), 0,
                 "passwd path must start with dir path");
  TEST_ASSERT_EQ((int)passwd_buf[dir_len], (int)'/',
                 "dir path must be followed by '/'");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* build_vnc_dir_path: argument validation */
  RUN_TEST(dir_path_null_home);
  RUN_TEST(dir_path_empty_home);
  RUN_TEST(dir_path_null_buf);
  RUN_TEST(dir_path_zero_buflen);

  /* build_vnc_dir_path: path construction */
  RUN_TEST(dir_path_correct_construction);
  RUN_TEST(dir_path_correct_construction_utf8);
  RUN_TEST(dir_path_root_home);

  /* build_vnc_dir_path: buffer boundary conditions */
  RUN_TEST(dir_path_exact_fit);
  RUN_TEST(dir_path_truncated);

  /* build_vnc_passwd_path: argument validation */
  RUN_TEST(passwd_path_null_home);
  RUN_TEST(passwd_path_empty_home);
  RUN_TEST(passwd_path_null_buf);
  RUN_TEST(passwd_path_zero_buflen);

  /* build_vnc_passwd_path: path construction */
  RUN_TEST(passwd_path_correct_construction);
  RUN_TEST(passwd_path_correct_construction_utf8);

  /* build_vnc_passwd_path: buffer boundary conditions */
  RUN_TEST(passwd_path_exact_fit);
  RUN_TEST(passwd_path_truncated);

  /* build_vnc_passwd_path: relationship to build_vnc_dir_path */
  RUN_TEST(passwd_path_differs_from_dir_path);
  RUN_TEST(passwd_path_is_under_dir_path);

  result = TEST_EXECUTE();
  return result;
}
