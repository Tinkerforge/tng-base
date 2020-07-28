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

version=1.2.11
builddir=build-zlib

rm -rf ${builddir}/
mkdir -p ${builddir}

pushd ${builddir}/

wget https://zlib.net/zlib-${version}.tar.gz

tar -xf zlib-${version}.tar.gz

pushd zlib-${version}/

CC=arm-linux-gnueabihf-gcc ./configure --static
make

popd

mkdir build/

cp zlib-${version}/zlib.h zlib-${version}/zconf.h zlib-${version}/libz.a build/
