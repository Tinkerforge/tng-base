#!/bin/bash -ex

#
# TNG Base Raspberry Pi CMX Image
# Copyright (C) 2020 Matthias Bolte <matthias@tinkerforge.com>
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
