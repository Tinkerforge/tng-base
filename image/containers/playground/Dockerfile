FROM balenalib/raspberrypi3-debian-python:3

RUN pip3 install tinkerforge

COPY enumerate.py /

CMD while true; do echo "Idling..."; sleep 600; done
