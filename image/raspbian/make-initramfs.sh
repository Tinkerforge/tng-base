#!/bin/bash -ex

#
# TNG Base Raspberry Pi CMX Image
# Copyright (C) 2020 Matthias Bolte <matthias@tinkerforge.com>
#

if [ "$(id -u)" -eq "0" ]; then
	echo "error: must be executed as user"
	exit 1
fi

builddir=build-initramfs

sudo rm -rf ${builddir}/

mkdir -p ${builddir}/build/proc/
mkdir -p ${builddir}/build/sys/
mkdir -p ${builddir}/build/dev/
mkdir -p ${builddir}/build/root/

sudo mknod -m 644 ${builddir}/build/dev/kmsg c 1 11
sudo mknod -m 660 ${builddir}/build/dev/i2c-1 c 89 1
sudo mknod -m 660 ${builddir}/build/dev/mmcblk0p2 b 179 2

arm-linux-gnueabihf-gcc -s -O2 -Wall -Wextra -Werror -static -pthread \
    -Ibuild-libkmod/build/libkmod -Ibuild-cryptoauthlib/build/cryptoauthlib \
    init.c -lcrypt build-libkmod/build/libkmod.a \
    build-cryptoauthlib/build/lib/libcryptoauth.a -lrt -o ${builddir}/build/init

pushd ${builddir}/build/
find . | cpio -H newc -o | gzip > ../initramfs7.img
popd
