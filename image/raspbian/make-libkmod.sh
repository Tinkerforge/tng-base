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

version=27
builddir=build-libkmod

rm -rf ${builddir}/
mkdir -p ${builddir}/

pushd ${builddir}/

wget https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git/snapshot/kmod-${version}.tar.gz

tar -xf kmod-${version}.tar.gz

pushd kmod-${version}
./autogen.sh
./configure --host=arm-linux-gnueabihf
popd

mkdir -p build/libkmod/
mkdir -p build/shared/

cp kmod-${version}/libkmod/*.c kmod-${version}/libkmod/*.h build/libkmod/
cp kmod-${version}/shared/*.c kmod-${version}/shared/*.h build/shared/
cp kmod-${version}/config.h build/
cp ../Makefile.libkmod build/Makefile

pushd build/
make
popd
