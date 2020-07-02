#!/bin/bash -ex

balena_cli_version=v11.33.3
balena_os_version=2.47.0+rev1

# install host tools
sudo apt-get install docker.io

# download balena-cli tool
balena_cli_basename=balena-cli-${balena_cli_version}-linux-x64-standalone

if [ -f ${balena_cli_basename}.zip ]; then
	rm ${balena_cli_basename}.zip
fi

if [ -d balena-cli ]; then
	rm -r balena-cli
fi

curl -L https://github.com/balena-io/balena-cli/releases/download/${balena_cli_version}/${balena_cli_basename}.zip -o ${balena_cli_basename}.zip

unzip -q ${balena_cli_basename}.zip

# download balena-os images
for variant in dev prod; do
	balena_os_basename=balena-os-rpi3-${balena_os_version}-${variant}

	if [ -f ${balena_os_basename}.zip ]; then
		rm ${balena_os_basename}.zip
	fi

	if [ -f balena.img ]; then
		rm balena.img
	fi

	if [ -f ${balena_os_basename}.img ]; then
		rm ${balena_os_basename}.img
	fi

	curl -L https://files.balena-cloud.com/images/raspberrypi3/$(echo "${balena_os_version}" | sed -e s/+/%2B/g).dev/image/balena.img.zip -o ${balena_os_basename}.zip

	unzip -q ${balena_os_basename}.zip

	mv balena.img ${balena_os_basename}.img
done
