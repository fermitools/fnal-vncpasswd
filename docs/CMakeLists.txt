find_program(ASCIIDOCTOR asciidoctor)
find_program(ASCIIDOC asciidoc)
find_program(A2X a2x)

# Substitute build-time constants (@VAR@) into .adoc.in templates.
# @ONLY prevents CMake from expanding ${VAR} syntax, which conflicts with
# AsciiDoc's own attribute reference syntax.
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/fnal-vncpasswd.1.adoc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/fnal-vncpasswd.1.adoc"
  @ONLY)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/pam_fnal_vncpasswd.8.adoc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/pam_fnal_vncpasswd.8.adoc"
  @ONLY)

# ##############################################################################
# Figure out how to build manpages
if(ASCIIDOCTOR)
  message(STATUS "Using asciidoctor for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
    COMMAND
      ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
      ${CMAKE_CURRENT_BINARY_DIR}/fnal-vncpasswd.1.adoc
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/fnal-vncpasswd.1.adoc
    COMMENT "Building fnal-vncpasswd manpage with asciidoctor"
    VERBATIM)
  if(BUILD_PAM_MODULE)
    add_custom_command(
      OUTPUT ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
      COMMAND
        ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
        ${CMAKE_CURRENT_BINARY_DIR}/pam_fnal_vncpasswd.8.adoc
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pam_fnal_vncpasswd.8.adoc
      COMMENT "Building pam_fnal_vncpasswd manpage with asciidoctor"
      VERBATIM)
  endif()
elseif(ASCIIDOC AND A2X)
  message(STATUS "Using asciidoc/a2x for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
    COMMAND
      ${A2X} --doctype manpage --format manpage -D ${PROJECT_BINARY_DIR}
      ${CMAKE_CURRENT_BINARY_DIR}/fnal-vncpasswd.1.adoc
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/fnal-vncpasswd.1.adoc
    COMMENT "Building fnal-vncpasswd manpage with a2x"
    VERBATIM)
  if(BUILD_PAM_MODULE)
    add_custom_command(
      OUTPUT ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
      COMMAND
        ${A2X} --doctype manpage --format manpage -D ${PROJECT_BINARY_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/pam_fnal_vncpasswd.8.adoc
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pam_fnal_vncpasswd.8.adoc
      COMMENT "Building pam_fnal_vncpasswd manpage with a2x"
      VERBATIM)
  endif()
else()
  message(FATAL_ERROR "asciidoctor or asciidoc/a2x required for manpages")
endif()

add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1)
install(FILES ${PROJECT_BINARY_DIR}/fnal-vncpasswd.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

if(BUILD_PAM_MODULE)
  add_custom_target(pam_doc DEPENDS ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8)
  add_dependencies(doc pam_doc)
  install(FILES ${PROJECT_BINARY_DIR}/pam_fnal_vncpasswd.8
          DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
endif()
