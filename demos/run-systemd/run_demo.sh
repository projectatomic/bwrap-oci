#!/bin/sh

rm -rf cache
mkdir cache
bwrap --ro-bind / / --dev /dev --proc /proc --bind $(pwd) $(pwd) skopeo copy docker://fedora oci:cache:latest

mkdir rootfs

(
    cd rootfs
    # Hack, this works only because fedora is a single layer image
    for i in ../cache/blobs/sha256/*
    do
        bwrap --ro-bind / / --dev /dev --proc /proc --bind $(pwd) $(pwd) tar xf $i || true
    done
    mkdir {dev,proc,sys}
)

bwrap --uid 0 --gid 0 --unshare-user --bind rootfs / --dev /dev --proc /proc --tmpfs /run --tmpfs /var --tmpfs /var/log systemd-tmpfiles --create

bwrap --uid 0 --gid 0 --unshare-user --bind rootfs / --dev /dev --proc /proc --tmpfs /run --tmpfs /var --tmpfs /var/log systemctl mask dev-hugepages.mount systemd-update-utmp.service systemd-tmpfiles-setup.service

systemd-run --user --scope bwrap-oci --pid-file=/tmp/pidfile

kill -37 $(cat /tmp/pidfile)
