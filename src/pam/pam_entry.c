/*
 * pam/pam_entry.c - PAM module entry points.
 *
 * Thin glue layer bridging the PAM API to the core logic in auth.c.
 * Extracts username and password from the PAM handle, then calls
 * authenticate_vnc_user(). PAM headers are pulled in via auth.h.
 *
 * All six pam_sm_* entry points are required. Linux-PAM resolves them by
 * symbol name at dlopen time based on which service types appear in
 * /etc/pam.d/. A missing symbol causes dlsym failure and breaks the entire
 * auth stack. The pam_sm_* defines in auth.h declare the corresponding
 * prototypes; the stubs for unused types must still exist.
 */

#include <syslog.h>

#include "auth.h"
#include "autoconf.h"
#include "syscall_ops.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  const char *username = NULL;
  const char *authtok = NULL;
  struct pam_args args = make_pam_args();

  (void)flags;

  parse_pam_args(argc, argv, &args);

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
    pam_syslog(pamh, LOG_ERR, "pam_fnal_vncpasswd: could not get username");
    return PAM_AUTH_ERR;
  }

  if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS ||
      authtok == NULL) {
    pam_syslog(pamh, LOG_ERR, "pam_fnal_vncpasswd: could not get password");
    return PAM_AUTH_ERR;
  }

  return authenticate_vnc_user(&syscall_ops_default, pamh, username, authtok,
                               args.debug);
}

/*
 * This module manages no credentials. PAM_IGNORE signals to the PAM stack
 * that setcred is not applicable here, avoiding interference with stacked
 * modules that inspect setcred return values.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_IGNORE;
}

/* Password changes are not supported; use fnal-vncpasswd instead. */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  (void)flags;
  (void)argc;
  (void)argv;
  pam_syslog(pamh, LOG_INFO,
             "pam_fnal_vncpasswd: password changes not supported via PAM; "
             "use fnal-vncpasswd to set the VNC password");
  return PAM_PERM_DENIED;
}

/*
 * This module implements only password authentication. Placing it in other
 * elements of the PAM stack will return PAM_SERVICE_ERR.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  (void)flags;
  (void)argc;
  (void)argv;
  pam_syslog(pamh, LOG_INFO,
             "pam_fnal_vncpasswd: account management not supported via PAM "
             "for this module; configure it only for auth");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  (void)flags;
  (void)argc;
  (void)argv;
  pam_syslog(pamh, LOG_ERR,
             "pam_fnal_vncpasswd: session management not supported; "
             "check PAM configuration for misplaced session entries");
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
  (void)flags;
  (void)argc;
  (void)argv;
  pam_syslog(pamh, LOG_ERR,
             "pam_fnal_vncpasswd: session management not supported; "
             "check PAM configuration for misplaced session entries");

  return PAM_SERVICE_ERR;
}
