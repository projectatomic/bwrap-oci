#!/bin/sh
ocitools generate --seccomp-default=SCMP_ACT_KILL --seccomp-arch=SCMP_ARCH_X86_64 --seccomp-allow=read --seccomp-errno=write
