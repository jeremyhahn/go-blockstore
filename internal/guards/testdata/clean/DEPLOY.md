# A fixture proving the privileged scanner accepts a warning

Never `--privileged`: it grants every capability, disables the seccomp profile
and the LSM confinement wholesale, and exposes every host device.

Do NOT use --privileged as a fix. Grant `CAP_SYS_ADMIN` and pass the specific
device instead.
