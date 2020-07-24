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

version=3.2.1
builddir=build-cryptoauthlib

rm -rf ${builddir}/
mkdir -p ${builddir}

pushd ${builddir}/

wget https://github.com/MicrochipTech/cryptoauthlib/archive/v${version}.tar.gz

tar -xf v${version}.tar.gz

mkdir -p build/
pushd build/

cmake \
    -DCMAKE_TOOLCHAIN_FILE=../../arm-linux-gnueabihf.cmake-toolchain \
    -DATCA_ATECC108A_SUPPORT=OFF \
    -DATCA_ATECC508A_SUPPORT=OFF \
    -DATCA_ATSHA204A_SUPPORT=OFF \
    -DATCA_ATSHA206A_SUPPORT=OFF \
    -DATCA_BUILD_SHARED_LIBS=OFF \
    -DATCA_HAL_I2C=ON \
    ../cryptoauthlib-${version}/

cmake --build .

ln -s ../cryptoauthlib-${version}/lib cryptoauthlib
ln -s ../../build/lib/atca_config.h ../cryptoauthlib-${version}/lib/atca_config.h
