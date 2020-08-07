#!/bin/bash -ex

#
# TNG Base Raspberry Pi CMX Image
# Copyright (C) 2020 Matthias Bolte <matthias@tinkerforge.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
mkdir -p ${builddir}/build/mnt/

sudo mknod -m 644 ${builddir}/build/dev/kmsg c 1 11
sudo mknod -m 660 ${builddir}/build/dev/i2c-1 c 89 1
sudo mknod -m 660 ${builddir}/build/dev/mmcblk0p2 b 179 2

arm-linux-gnueabihf-gcc -s -O2 -Wall -Wextra -Werror -static -pthread \
  -Ibuild-libkmod/build/libkmod -Ibuild-zlib/build init.c -lcrypt \
  build-libkmod/build/libkmod.a build-zlib/build/libz.a -lrt\
  -o ${builddir}/build/init

pushd ${builddir}/build/
find . | cpio -H newc -o | gzip > ../initramfs7.img
popd
