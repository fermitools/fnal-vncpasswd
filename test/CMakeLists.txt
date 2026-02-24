# test/CMakeLists.txt - Unit test executables for pam-vncpasswd
#
# Design rationale
# ----------------
# Every test executable compiles its sources directly rather than linking a
# shared OBJECT library. This ensures coverage instrumentation is applied to
# every translation unit under test; objects compiled without --coverage produce
# no .gcno data and silently drop out of reports.
#
# Common TUs pulled into more than one test (vnc_path.c, syscall_ops_default.c)
# are listed explicitly per target. The small duplication is intentional: it
# keeps each binary self-contained and coverage correct.
include(CTest)

# ============================================================================
# Shared include paths
# ============================================================================
set(TEST_INCLUDES "${CMAKE_SOURCE_DIR}/src" "${CMAKE_BINARY_DIR}/src"
                  "${CMAKE_CURRENT_SOURCE_DIR}")

# Convenience list of src TUs shared by multiple tests.
set(VNC_COMMON_SRCS "${CMAKE_SOURCE_DIR}/src/vnc_path.c"
                    "${CMAKE_SOURCE_DIR}/src/syscall_ops_default.c")

# ============================================================================
# Coverage detection
# ============================================================================
set(HAVE_COVERAGE_TOOLS OFF)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

  find_program(LCOV_EXEC lcov)
  find_program(GENHTML_EXEC genhtml)

  if(LCOV_EXEC AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS
        -g --coverage -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS --coverage)

    message(STATUS "Coverage enabled: GCC + lcov")
  endif()

elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

  find_program(LLVM_PROFDATA_EXEC llvm-profdata)
  find_program(LLVM_COV_EXEC llvm-cov)

  if(LLVM_PROFDATA_EXEC
     AND LLVM_COV_EXEC
     AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS
        -g -fprofile-instr-generate -fcoverage-mapping
        -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS -fprofile-instr-generate)

    message(STATUS "Coverage enabled: Clang + llvm-cov")
  endif()

endif()

# Internal helper: apply coverage flags to a target if tools are present.
macro(add_coverage_flags target)
  if(HAVE_COVERAGE_TOOLS)
    target_compile_options(${target} PRIVATE ${COVERAGE_COMPILE_FLAGS})
    target_link_options(${target} PRIVATE ${COVERAGE_LINK_FLAGS})
  endif()
endmacro()

# ============================================================================
# test_vnc_path
# ============================================================================
# Tests build_vnc_dir_path() and build_vnc_passwd_path() from vnc_path.c.

add_executable(test_vnc_path test_vnc_path.c ${VNC_COMMON_SRCS})

target_include_directories(test_vnc_path PRIVATE ${TEST_INCLUDES})
target_link_libraries(test_vnc_path PUBLIC PkgConfig::LIBXCRYPT)
add_coverage_flags(test_vnc_path)

add_test(NAME test_vnc_path COMMAND test_vnc_path)

# ============================================================================
# test_passwd
# ============================================================================
# Tests hash_password(), ensure_vnc_dir(), atomic_write_passwd_file(), and
# get_passwd_path() from fnal-vncpasswd/passwd.c.

add_executable(
  test_passwd test_passwd.c "${CMAKE_SOURCE_DIR}/src/fnal-vncpasswd/passwd.c"
              ${VNC_COMMON_SRCS})

target_include_directories(
  test_passwd PRIVATE ${TEST_INCLUDES} "${CMAKE_SOURCE_DIR}/src/fnal-vncpasswd")
target_link_libraries(test_passwd PRIVATE PkgConfig::LIBXCRYPT)
add_coverage_flags(test_passwd)

add_test(NAME test_passwd COMMAND test_passwd)

# ============================================================================
# test_auth
# ============================================================================
# Tests parse_pam_args() and authenticate_vnc_user() from pam/auth.c.
#
# pam_syslog() is intercepted via -Wl,--wrap=pam_syslog so test_auth.c can
# define __wrap_pam_syslog and record calls. This lets debug=true paths be
# verified without depending on syslog infrastructure, while still linking the
# real libpam for pam_handle_t and PAM_* constants.

add_executable(test_auth test_auth.c "${CMAKE_SOURCE_DIR}/src/pam/auth.c"
                         ${VNC_COMMON_SRCS})

target_include_directories(
  test_auth PRIVATE ${TEST_INCLUDES} "${CMAKE_SOURCE_DIR}/src/pam"
                    "${PAM_INCLUDE_DIR}")
target_link_libraries(test_auth PRIVATE PkgConfig::LIBXCRYPT "${PAM_LIBRARY}"
                                        crypto_dep)
target_link_options(test_auth PRIVATE -Wl,--wrap=pam_syslog)
add_coverage_flags(test_auth)

add_test(NAME test_auth COMMAND test_auth)

# ============================================================================
# Coverage report targets
# ============================================================================
# UNIT_TEST_BINARIES is used by the Clang llvm-cov commands, which require an
# explicit list of instrumented binaries (unlike lcov which scans .gcda files).
# Populated here after all test targets are defined.

set(UNIT_TEST_BINARIES $<TARGET_FILE:test_vnc_path> $<TARGET_FILE:test_passwd>
                       $<TARGET_FILE:test_auth>)

add_custom_target(
  test_binaries
  DEPENDS test_vnc_path test_passwd test_auth
  COMMENT "Building every unit test binary")

if(BUILD_TESTING AND HAVE_COVERAGE_TOOLS)

  set(COVERAGE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/coverage)
  set_property(
    DIRECTORY
    APPEND
    PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_OUTPUT_DIR})

  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

    set(COVERAGE_INFO ${CMAKE_BINARY_DIR}/coverage.info)
    set(COVERAGE_INFO_CLEAN ${CMAKE_BINARY_DIR}/coverage.info.cleaned)
    set_property(
      DIRECTORY
      APPEND
      PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_INFO} ${COVERAGE_INFO_CLEAN})

    add_custom_target(
      coverage
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --zerocounters
      COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --capture --rc
              branch_coverage=1 --output-file ${COVERAGE_INFO}
      COMMAND
        ${LCOV_EXEC} --remove ${COVERAGE_INFO} '${CMAKE_SOURCE_DIR}/test/*' --rc
        branch_coverage=1 --output-file ${COVERAGE_INFO_CLEAN}
      COMMAND ${GENHTML_EXEC} --rc branch_coverage=1 -o ${COVERAGE_OUTPUT_DIR}
              ${COVERAGE_INFO_CLEAN}
      COMMAND ${LCOV_EXEC} --summary ${COVERAGE_INFO_CLEAN} --rc
              branch_coverage=1 --fail-under-lines 95
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating GCC coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

    set(PROFILE_DATA ${CMAKE_BINARY_DIR}/default.profdata)
    set_property(
      DIRECTORY
      APPEND
      PROPERTY ADDITIONAL_CLEAN_FILES ${PROFILE_DATA})

    add_custom_target(
      coverage
      COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=default.profraw
              ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LLVM_PROFDATA_EXEC} merge -sparse default.profraw -o
              ${PROFILE_DATA}
      COMMAND
        ${LLVM_COV_EXEC} show ${UNIT_TEST_BINARIES}
        -instr-profile=${PROFILE_DATA} -format=html
        -output-dir=${COVERAGE_OUTPUT_DIR}
      COMMAND ${LLVM_COV_EXEC} report ${UNIT_TEST_BINARIES}
              -instr-profile=${PROFILE_DATA} -show-region-summary=false
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating Clang coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  endif()

endif()
