# fnal-vncpasswd

Per-user VNC password authentication for FNAL desktops.

- **fnal-vncpasswd(1)** — sets a per-user VNC password.
- **pam_fnal_vncpasswd(8)** — authenticates against it from inside a VNC session.

The PAM module is intended for VNC session processes that run as the authenticated
user. It binds authentication to the calling process UID and **must not** be used
in multi-user services (sshd, login, sudo) where the process runs as root.

## Requirements

- CMake >= 3.21, pkg-config
- C17 compiler (GCC or Clang)
- libxcrypt, PAM, libbsd
- OpenSSL, LibreSSL, or GnuTLS
- Optional: libselinux

## Building

```shell
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DPAM_MODULE_DIR=/usr/lib64/security
cmake --build build
cmake --install build
```

Key build options (defined in `autoconf.h.in`):

| Variable | Default | Description |
|---|---|---|
| `PAM_MODULE_DIR` | `${CMAKE_INSTALL_FULL_LIBDIR}/security` | Installation directory for `pam_fnal_vncpasswd.so` |
| `VNC_PASSWD_DIR` | `.config/vnc` | Relative path under `$HOME` for the VNC configuration directory |
| `VNC_PASSWD_FILENAME` | `fnal-vncpasswd` | Filename of the per-user password file |
| `VNC_MIN_PASSWORD_LENGTH` | `6` | Minimum password length; must be between 1 and 8 |

The maximum password length is fixed at 8 by the RFB protocol and is not configurable.

## Usage

```shell
$ fnal-vncpasswd
New VNC password:
Confirm VNC password:
VNC password updated successfully.
```

Requires a controlling terminal. The directory `~/.config/vnc/` is created
with mode 0700 if absent. To remove the VNC password, delete the password
file directly. With no file present the PAM stack can fall through to
`pam_unix` or `pam_sss`.  See the PAM Configuration for details.

To remove the password:
```shell
rm ~/.config/vnc/fnal-vncpasswd
```

## PAM Configuration

The following is an example configuration. Copy it to `/etc/pam.d/` and
rename it to match the service name your VNC daemon passes to `pam_start(3)`.

### /etc/pam.d/fnal-vnc-example
```conf
#%PAM-1.0
auth       [success=done default=ignore]          pam_fnal_vncpasswd.so
auth    include login
account include login
```

The bracket syntax is intentional and required — see `pam.conf(5)`.

The `account` and `auth` stacks delegate to a substack so that
site-local policy is inherited automatically.

You must use `fnal-vncpasswd` directly to change the password.

## SELinux

```shell
ls -Z ~/.config/vnc/fnal-vncpasswd   # after first run
```

If the context is wrong, run `restorecon -vF` on the affected file.
`fnal-vncpasswd` calls `selinux_restorecon(3)` after each password write when
built with libselinux.

## Limitations

- Not suitable for multi-user PAM services. See `pam_fnal_vncpasswd(8)`.
- Password changes via PAM (`pam_sm_chauthtok`) are not supported.
- `rename(2)` atomicity is not guaranteed on network filesystems.

## See Also

`fnal-vncpasswd(1)`, `pam_fnal_vncpasswd(8)`, `pam.conf(5)`

## Contributing

Report bugs and submit patches via https://github.com/fermitools/fnal-vncpasswd
