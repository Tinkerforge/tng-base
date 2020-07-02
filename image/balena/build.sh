#!/bin/bash -ex

pushd containers

../balena-cli/balena build --deviceType raspberrypi3 --arch armv7hf --emulated

popd
