# ##############################################################################
# Build-time configuration
# ##############################################################################

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/autoconf.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autoconf.h" @ONLY)

# ##############################################################################
# Shared dependencies
# ##############################################################################

# libxcrypt: for modern crypt_r(3), crypt_gensalt_ra(3)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXCRYPT REQUIRED IMPORTED_TARGET GLOBAL libxcrypt)

# Crypto backend for constant-time comparison (CRYPTO_memcmp / gnutls_memcmp)
add_library(crypto_dep INTERFACE)

find_package(OpenSSL COMPONENTS Crypto)
if(OpenSSL_FOUND)
  include(CheckSymbolExists)
  set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
  set(CMAKE_REQUIRED_QUIET TRUE)
  check_symbol_exists(LIBRESSL_VERSION_TEXT "openssl/opensslv.h"
                      _HAVE_LIBRESSL_MARKER)
  unset(CMAKE_REQUIRED_QUIET)
  unset(CMAKE_REQUIRED_INCLUDES)

  if(_HAVE_LIBRESSL_MARKER)
    message(
      STATUS "Crypto backend: LibreSSL ${OPENSSL_VERSION} (OpenSSL compat)")
    target_compile_definitions(crypto_dep INTERFACE HAVE_LIBRESSL=1)
  else()
    message(STATUS "Crypto backend: OpenSSL ${OPENSSL_VERSION}")
    target_compile_definitions(crypto_dep INTERFACE HAVE_OPENSSL=1)
  endif()

  target_link_libraries(crypto_dep INTERFACE OpenSSL::Crypto)
  target_include_directories(crypto_dep INTERFACE "${OPENSSL_INCLUDE_DIR}")
else()
  find_package(GnuTLS REQUIRED)
  message(STATUS "Crypto backend: GnuTLS ${GnuTLS_VERSION}")
  target_compile_definitions(crypto_dep INTERFACE HAVE_GNUTLS=1)
  target_link_libraries(crypto_dep INTERFACE GnuTLS::GnuTLS)
  target_include_directories(crypto_dep INTERFACE "${GNUTLS_INCLUDE_DIR}")
endif()

# ##############################################################################
# Shared static library
# ##############################################################################

add_library(vnc_shared OBJECT vnc_path.c syscall_ops_default.c)
target_include_directories(vnc_shared PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
                                             "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(vnc_shared PUBLIC PkgConfig::LIBXCRYPT)
set_target_properties(vnc_shared PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ##############################################################################
# Subdirectories
# ##############################################################################

add_subdirectory(pam)
add_subdirectory(fnal-vncpasswd)
