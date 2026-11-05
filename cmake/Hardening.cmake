# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group
# cmake/Hardening.cmake - toolchain sanity checks, compiler warnings, and
# security hardening flags shared by every compiled target.
#
# This is generic toolchain policy, not fnal-vncpasswd policy, so it is kept
# out of the top-level CMakeLists.txt and included() from there instead of
# add_subdirectory()'d: include() shares the caller's directory scope, so the
# add_compile_options()/add_link_options() set here are already in effect by
# the time the top level reaches add_subdirectory(src) and add_subdirectory(test).

include(CheckCSourceCompiles)
include(CheckCCompilerFlag)
include(CheckIPOSupported)
include(CheckPIESupported)

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
    -Wdisabled-optimization # Optimization disabled
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

# Stack unwinding tables (required for backtraces/debugging)
check_c_compiler_flag(-fasynchronous-unwind-tables HAVE_UNWIND_TABLES)
if(HAVE_UNWIND_TABLES)
  add_compile_options(-fasynchronous-unwind-tables)
  message(STATUS "Unwind tables: enabled")
else()
  message(WARNING "Compiler does not support -fasynchronous-unwind-tables")
endif()

# Frame pointer (aid debugging and profiling)
check_c_compiler_flag(-fno-omit-frame-pointer HAVE_FRAME_POINTER)
if(HAVE_FRAME_POINTER)
  add_compile_options(-fno-omit-frame-pointer)
  message(STATUS "Frame pointer: enabled")
else()
  message(WARNING "Compiler does not support -fno-omit-frame-pointer")
endif()

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

# Disable stack slot reuse (GCC-only feature; warn if unsupported)
CHECK_C_COMPILER_FLAG(-fstack-reuse=none STACK_REUSE)
if (STACK_REUSE)
  add_compile_options(-fstack-reuse=none)
else ()
  message(
    WARNING "Stack slot reuse protection (-fstack-reuse=none) not supported by compiler")
endif()

# Zero call-used registers on return. Prefer 'all' (strongest); fall back to
# 'used', which the 'all' form accepts on GCC but Clang only supports directly.
check_c_compiler_flag(-fzero-call-used-regs=all HAVE_ZERO_CALL_REGS)
if(HAVE_ZERO_CALL_REGS)
  add_compile_options(-fzero-call-used-regs=all)
else()
  check_c_compiler_flag(-fzero-call-used-regs=used HAVE_ZERO_CALL_REGS_USED)
  if(HAVE_ZERO_CALL_REGS_USED)
    message(STATUS "Zero call-used registers: using 'used' fallback")
    add_compile_options(-fzero-call-used-regs=used)
  else()
    message(WARNING "Zero call-used registers protection not supported by compiler")
  endif()
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
  -Wl,-z,nodump         # Prevent dumping of the executable
  -Wl,-z,relro          # Read-only relocations
  -Wl,-z,now            # Resolve all symbols at load time
  -Wl,-z,combreloc      # Combine relocation sections
)

# ##############################################################################
# Source Fortification
# _FORTIFY_SOURCE hardens libc string/memory calls. It requires optimization,
# so it is only enabled when the build actually optimizes; under -O0 gcc/clang
# warn, and -Werror would reject that warning. Only the active build type's
# flags (and base CMAKE_C_FLAGS) are inspected, not the always-populated
# config cache entries for the other build types.
set(_HAVE_OPTIMIZATION FALSE)
if(CMAKE_C_FLAGS MATCHES "-O[1-3s]")
  set(_HAVE_OPTIMIZATION TRUE)
endif()
if(DEFINED CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE STREQUAL "")
  string(TOUPPER "${CMAKE_BUILD_TYPE}" _CFG_UPPER)
  if(CMAKE_C_FLAGS_${_CFG_UPPER} MATCHES "-O[1-3s]")
    set(_HAVE_OPTIMIZATION TRUE)
  endif()
endif()
if(_HAVE_OPTIMIZATION)
  add_compile_definitions(_FORTIFY_SOURCE=2)
  message(STATUS "Source fortification: enabled")
else()
  message(STATUS "Source fortification: disabled (no optimization)")
endif()
