FROM balenalib/raspberrypi3-debian-python:3-build

RUN apt-get update && apt-get install -y --no-install-recommends pm-utils

RUN wget https://download.tinkerforge.com/tools/brickd/linux/brickd-2.4.1_armhf.deb
RUN dpkg -i brickd-2.4.1_armhf.deb

CMD ["brickd"]
