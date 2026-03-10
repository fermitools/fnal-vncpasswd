cmake_minimum_required(VERSION 3.21)

project(fnal-vncpasswd C)

option(BUILD_PAM_MODULE "Build the PAM authentication module" ON)

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
include(CheckCSourceCompiles)
include(CheckCCompilerFlag)
include(CheckIPOSupported)
include(CheckPIESupported)

# ##############################################################################
# Enable testing target
enable_testing()

# ##############################################################################
# Compiler Sanity Test
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

check_c_source_compiles("int main(void) { return 0; }" CAN_COMPILE)
if(NOT CAN_COMPILE)
  message(FATAL_ERROR "C compiler is non-functional")
endif()

message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Standard: C${CMAKE_C_STANDARD}")
message(STATUS "Supported C features: ${CMAKE_C_COMPILE_FEATURES}")

# ##############################################################################
# Required Compiler Warnings These warnings help catch common issues
add_compile_options(
  -Werror # Treat all warnings as errors
  -Wall # Enable most warnings
  -Wextra # Enable extra warnings
  -Wpedantic # ISO C conformance warnings
  -Walloca # Warn on suspicious alloca usage
  -Wcast-align # Warn on alignment-affecting casts
  -Wcast-qual # Warn on cast removing const/volatile
  -Wconversion # Implicit conversion warnings
  -Wdisabled-optimization # Optimization disabled
  -Wdouble-promotion # Implicit float-to-double promotion
  -Werror=implicit-function-declaration # Error on implicit declarations
  -Wformat=2 # Enhanced format string warnings
  -Wformat-security # Format security issues
  -Winline # Inline function can't be inlined
  -Wmissing-declarations # Missing declarations
  -Wmissing-field-initializers # Struct fields left uninitialized
  -Wmissing-prototypes # Missing function prototypes
  -Wnested-externs # Nested extern declarations
  -Wnull-dereference # Potential NULL dereferences
  -Wredundant-decls # Redundant declarations
  -Wshadow # Warn on shadowed variables
  -Wsign-conversion # Sign conversion warnings
  -Wstrict-overflow=2 # Overflow detection (level 2)
  -Wstrict-prototypes # Require function prototypes
  -Wundef # Undefined macro in #if
  -Wvla # Variable length arrays discouraged
  -Wwrite-strings # String literals are const
)

# Ensure our behavior modes are defined
add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700 _GNU_SOURCE)

# Additional GCC features (not supported by all compilers)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(
    -Warith-conversion # Implicit conversions in arithmetic
    -Wduplicated-branches # Identical if/else branches
    -Wduplicated-cond # Duplicated conditions in if/else chains
    -Wjump-misses-init # goto skips variable initialization
    -Wlogical-op # Suspicious logical operations
    -Wstringop-overflow # String operations writing past buffer end
    -Wtrampolines # Nested functions requiring executable stack
  )
endif()

# Position Independent Code (PIE)
check_pie_supported(OUTPUT_VARIABLE output LANGUAGES C)
if(CMAKE_C_LINK_PIE_SUPPORTED)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
  message(STATUS "PIE support: enabled")
else()
  message(WARNING "PIE is not supported at link time: ${output}")
  message(WARNING "PIE link options will not be passed to linker")
endif()

# Interprocedural Optimization (LTO)
check_ipo_supported(RESULT IPO_RESULT)
if(IPO_RESULT)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  message(STATUS "LTO/IPO support: enabled")
else()
  message(WARNING "Interprocedural Optimization is not supported: ${output}")
  message(WARNING "LTO will not be enabled")
endif()

# ##############################################################################
# Compiler Hardening Flags

# Stack protector: ALL
check_c_compiler_flag(-fstack-protector-all HAVE_SSP_ALL)
if (HAVE_SSP_ALL)
  add_compile_options(-fstack-protector-all)
else()
  message(FATAL_ERROR "Required flag -fstack-protector-all not supported")
endif()

# Stack clash protection
CHECK_C_COMPILER_FLAG(-fstack-clash-protection STACK_CLASH)
if (STACK_CLASH)
  add_compile_options(-fstack-clash-protection)
  message(STATUS "Stack clash protection: enabled")
else ()
  message(WARNING "Stack clash protection not supported by compiler")
endif()

# Disable stack slot reuse
CHECK_C_COMPILER_FLAG(-fstack-reuse=none STACK_REUSE)
if (STACK_REUSE)
  add_compile_options(-fstack-reuse=none)
else ()
  message(FATAL_ERROR "Required compiler flag '-fstack-reuse=none' not supported")
endif()

# Zero call-used registers on return
check_c_compiler_flag(-fzero-call-used-regs=all HAVE_ZERO_CALL_REGS)
if (HAVE_ZERO_CALL_REGS)
  add_compile_options(-fzero-call-used-regs=all)
endif()

# Control-flow enforcement
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
  # x86_64
  check_c_compiler_flag(-fcf-protection=full HAVE_CET)
  if (HAVE_CET)
    add_compile_options(-fcf-protection=full)
    add_link_options(
      -Wl,-z,ibt    # Fail at runtime if ibt fails
      -Wl,-z,shstk  # Fail at runtime if no shadow stack
    )
  else()
    message(FATAL_ERROR "Intel CET (-fcf-protection=full) required on x86_64")
  endif()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  # ARM
  check_c_compiler_flag(-mbranch-protection=standard HAVE_BTI)
  if (HAVE_BTI)
    add_compile_options(-mbranch-protection=standard)
    add_link_options(
        -Wl,-z,bti-report=error  # Enforce BTI
    )
  else()
    message(FATAL_ERROR "Branch Protection (-mbranch-protection=standard) required on aarch64")
  endif()
endif()

# Linker Hardening Flags
add_link_options(
  -Wl,--as-needed       # Only link used symbols
  -Wl,-z,noexecstack    # Mark stack as non-executable
  -Wl,-z,relro          # Read-only relocations
  -Wl,-z,now            # Resolve all symbols at load time
  -Wl,-z,combreloc      # Combine relocation sections
)

# ##############################################################################
# Find our source code version string
if(NOT DEFINED VERSION OR VERSION STREQUAL "")
  execute_process(
    COMMAND git describe --tags --abbrev=0
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT)

  if(GIT_RESULT OR VERSION STREQUAL "")
    message(FATAL_ERROR "Could not identify version")
  endif()
endif()

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
