#!/bin/bash -ex

if [ "$(id -u)" -eq "0" ]; then
	echo "error: must be executed as user"
	exit 1
fi

builddir=build-initramfs

sudo rm -rf build-initramfs/

mkdir -p ${builddir}/initramfs/proc/
mkdir -p ${builddir}/initramfs/sys/
mkdir -p ${builddir}/initramfs/dev/
mkdir -p ${builddir}/initramfs/root/

sudo mknod -m 644 ${builddir}/initramfs/dev/kmsg c 1 11
sudo mknod -m 660 ${builddir}/initramfs/dev/i2c-1 c 89 1
sudo mknod -m 660 ${builddir}/initramfs/dev/mmcblk0p1 b 179 1
sudo mknod -m 660 ${builddir}/initramfs/dev/mmcblk0p2 b 179 2

arm-linux-gnueabihf-gcc -O2 -Wall -Wextra -Werror -pedantic -static init.c -lcrypt -o ${builddir}/initramfs/init

pushd ${builddir}/initramfs/
find . | cpio -H newc -o | gzip > ../initramfs7.img
popd
