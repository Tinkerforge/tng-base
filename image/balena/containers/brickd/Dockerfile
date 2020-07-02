FROM balenalib/raspberrypi3-alpine

RUN wget https://download.tinkerforge.com/tools/brickd/alpine/brickd-2.4.1_git20200514192222-r0-armv7.apk
RUN apk add --allow-untrusted brickd-*-armv7.apk
RUN rm brickd-*-armv7.apk
CMD brickd --libusb-hotplug-mknod
