#!/bin/bash -ex

#
# TNG Base Raspberry Pi CMX Image
# Copyright (C) 2020 Matthias Bolte <matthias@tinkerforge.com>
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
