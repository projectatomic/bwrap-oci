#!/bin/sh
oci-runtime-tool generate --seccomp-arch=amd64 --seccomp-allow=read --seccomp-errno=write
