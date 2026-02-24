# fnal-vncpasswd/CMakeLists.txt — builds fnal-vncpasswd

add_executable(fnal-vncpasswd main.c passwd.c)
target_include_directories(fnal-vncpasswd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

pkg_check_modules(SELINUX IMPORTED_TARGET libselinux)

if(SELINUX_FOUND)
  target_compile_definitions(fnal-vncpasswd PRIVATE HAVE_SELINUX)
  target_link_libraries(fnal-vncpasswd PRIVATE PkgConfig::SELINUX)
endif()

pkg_check_modules(LIBBSD REQUIRED IMPORTED_TARGET libbsd)

target_link_libraries(fnal-vncpasswd PRIVATE vnc_shared crypto_dep
                                             PkgConfig::LIBBSD)

install(TARGETS fnal-vncpasswd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
