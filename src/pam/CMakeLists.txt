# pam/CMakeLists.txt — builds pam_fnal_vncpasswd.so
#
# NAMING: PAM modules must not carry the "lib" prefix. dlopen looks for
# "pam_fnal_vncpasswd.so". Underscores, not hyphens, are the PAM convention.

# PAM library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED IMPORTED_TARGET pam)

add_library(pam_fnal_vncpasswd MODULE pam_entry.c auth.c)

set_target_properties(pam_fnal_vncpasswd PROPERTIES PREFIX "")

target_include_directories(
  pam_fnal_vncpasswd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${PAM_INCLUDE_DIR}")

target_link_libraries(pam_fnal_vncpasswd PRIVATE vnc_shared crypto_dep
                                                 PkgConfig::PAM)

install(TARGETS pam_fnal_vncpasswd LIBRARY DESTINATION "${PAM_MODULE_DIR}")
