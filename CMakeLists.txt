# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

cmake_minimum_required(VERSION 3.21)

project(fnal-vncpasswd C)

option(BUILD_PAM_MODULE "Build the PAM authentication module" ON)

# ##############################################################################
# Find our source code version string
# Determine the project version. Prefer the latest git tag; fall back to a
# placeholder when building from a source tree without tags (e.g. CI or an
# unpacked archive) so configuration still succeeds. An explicit -DVERSION, as
# the RPM spec passes via rpmbuild, always takes precedence.
if(NOT DEFINED VERSION OR VERSION STREQUAL "")
  execute_process(
    COMMAND git describe --tags --abbrev=0
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE _version_git
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE _version_result)

  if(_version_result EQUAL 0 AND NOT _version_git STREQUAL "")
    set(VERSION "${_version_git}")
    message(STATUS "Project version: ${VERSION} (from git tag)")
  else()
    message(
      WARNING
        "No git tag found; using placeholder version '0.0.0'. Tag a release to set a real version."
      )
    set(VERSION "0.0.0")
  endif()
endif()

# ##############################################################################
# Packaging (CPack)
include(FeatureSummary)

set_package_properties(fnal-vncpasswd PROPERTIES
  URL "https://github.com/fermitools/fnal-vncpasswd"
  DESCRIPTION "Per-user VNC password manager and PAM authentication module")

set(CPACK_PACKAGE_NAME "${CMAKE_PROJECT_NAME}")
set(CPACK_PACKAGE_CONTACT "fermilab <servicedesk@fnal.gov>")
set(CPACK_PACKAGE_DESCRIPTION "Per-user VNC password manager and PAM authentication module")
set(CPACK_PACKAGE_VERSION ${VERSION})

set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

include(CPack)

####
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
        "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE
    )
    message(STATUS "Build type not specified, defaulting to RelWithDebInfo")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# ##############################################################################
# Require out-of-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds are not allowed.\n"
      "Create a separate build directory and run cmake from there:\n"
      "  mkdir build && cd build && cmake ..\n"
      "Remove CMakeCache.txt and CMakeFiles/ if they were created here.")
endif()

# ##############################################################################
# CMake modules
include(GNUInstallDirs)

# ##############################################################################
# Compiler sanity checks and hardening flags, shared by every compiled target
include("${CMAKE_SOURCE_DIR}/cmake/Hardening.cmake")

# ##############################################################################
# Top Level System Variables, these are pretty much a public api

if(BUILD_PAM_MODULE)
  set(_default_pam_dir "${CMAKE_INSTALL_FULL_LIBDIR}/security")

  if(NOT DEFINED PAM_MODULE_DIR)
    set(PAM_MODULE_DIR
        "${_default_pam_dir}"
        CACHE PATH "Directory where the PAM module is installed")
  elseif(NOT PAM_MODULE_DIR STREQUAL _default_pam_dir)
    message(
      WARNING
        "PAM_MODULE_DIR (${PAM_MODULE_DIR}) differs from the platform default (${_default_pam_dir})"
    )
  endif()
endif()

if(NOT DEFINED VNC_PASSWD_DIR)
  set(VNC_PASSWD_DIR
      ".config/vnc"
      CACHE STRING "VNC password subdirectory under user home (XDG convention)")
endif()

if(NOT DEFINED VNC_PASSWD_FILENAME)
  set(VNC_PASSWD_FILENAME
      "fnal-vncpasswd"
      CACHE STRING "VNC password filename within VNC_PASSWD_DIR")
endif()

set(VNC_MAX_PASSWORD_LENGTH 8) # RFB protocol limit is 8, it should never change

# ##############################################################################
# Top Level Configuration Variables
if(NOT DEFINED VNC_MIN_PASSWORD_LENGTH)
  set(VNC_MIN_PASSWORD_LENGTH
      6
      CACHE STRING "Minimum password length enforced by fnal-vncpasswd")
endif()

# ##############################################################################
# Validate Configuration
if(NOT VNC_MIN_PASSWORD_LENGTH MATCHES "^[1-8]$")
  message(
    FATAL_ERROR
      "VNC_MIN_PASSWORD_LENGTH must be a single digit between 1 and 8 (got: '${VNC_MIN_PASSWORD_LENGTH}')"
  )
endif()

# ##############################################################################
# task focused cmake
enable_testing()
add_subdirectory(docs)
add_subdirectory(src)
add_subdirectory(test)

# ##############################################################################
# Print out state summary
message(STATUS "${CMAKE_PROJECT_NAME} - ${VERSION}")
message(STATUS "  BUILD_PAM_MODULE        = ${BUILD_PAM_MODULE}")
if(BUILD_PAM_MODULE)
  message(STATUS "  PAM_MODULE_DIR          = ${PAM_MODULE_DIR}")
endif()
message(STATUS "  VNC_PASSWD_DIR          = ~/${VNC_PASSWD_DIR}")
message(STATUS "  VNC_PASSWD_FILENAME     = ${VNC_PASSWD_FILENAME}")
message(STATUS "  VNC_MAX_PASSWORD_LENGTH = ${VNC_MAX_PASSWORD_LENGTH}")
message(STATUS "  VNC_MIN_PASSWORD_LENGTH = ${VNC_MIN_PASSWORD_LENGTH}")
