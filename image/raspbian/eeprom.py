#!/usr/bin/python3 -u

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

import os
import sys
import struct
import crypt
import binascii
import time
import argparse
import subprocess
from datetime import datetime

TNG_CONFIG_LENGTH = 450
ETH_CONFIG_LENGTH = 256

def print_hex(data):
    subprocess.run(['xxd', '-g', '1', '-'], input=data)

def encrypt_password(password):
    return crypt.crypt(password, salt=crypt.mksalt(crypt.METHOD_SHA512))

def bcd(decimal):
    bcd = 0
    offset = 0

    while decimal > 0:
        bcd = bcd | ((decimal % 10) << offset)
        decimal //= 10
        offset += 4

    return bcd

#
# TNG EEPROM content is defined as a series of fields, stored as little endian.
#
# header:
# - uint32_t     magic_number:       magic number 0x21474E54 (TNG!)
# - uint32_t     checksum:           zlib CRC32 checksum over all following bytes
# - uint16_t     data_length:        length of data blocks in byte
# - uint8_t      data_version:       indicating the available data blocks
#
# data (version 1):
# - uint32_t     production_date:    BCD formatted production date (0x20200827 -> 2020-08-27), exposed at /etc/tng-base-production-date
# - char[7]      uid:                null-terminated unique identifier, exposed at /etc/tng-base-uid
# - char[65]     hostname:           null-terminated /etc/hostname entry, also exposed at /etc/tng-base-hostname
# - char[107]    encrypted_password: null-terminated /etc/shadow password entry
# - uint8_t[256] ethernet_config:    config for Ethernet chip
#

def format_tng_config(uid, hostname, password, mac_address):
    encrypted_password = encrypt_password(password)

    assert len(uid) <= 6, uid
    assert len(hostname) <= 64, hostname
    assert len(encrypted_password) <= 106, encrypted_password

    now = datetime.now()

    production_date_bytes = struct.pack('<I', bcd(now.year * 10000 + now.month * 100 + now.day))
    uid_bytes = struct.pack('<7s', uid.encode('ascii'))
    hostname_bytes = struct.pack('<65s', hostname.encode('ascii'))
    encrypted_password_bytes = struct.pack('<107s', encrypted_password.encode('ascii'))
    ethernet_config_bytes = format_eth_config(mac_address)

    data_bytes = production_date_bytes + uid_bytes + hostname_bytes + encrypted_password_bytes + ethernet_config_bytes

    data_length_bytes = struct.pack('<H', len(data_bytes))
    data_version_bytes = struct.pack('<B', 1)

    checksum = binascii.crc32(data_length_bytes + data_version_bytes + data_bytes) & 0xFFFFFFFF
    checksum_bytes = struct.pack('<I', checksum)

    magic_number_bytes = struct.pack('<I', 0x21474E54)
    config_bytes = magic_number_bytes + checksum_bytes + data_length_bytes + data_version_bytes + data_bytes

    assert len(config_bytes) == TNG_CONFIG_LENGTH, len(config_bytes)

    return config_bytes

def read_tng_eeprom(length):
    import smbus

    sys.stdout.write('reading: ...')

    bus = smbus.SMBus(1)
    address = 0x50
    data = []

    bus.write_byte_data(address, 0, 0)

    for offset in range(length):
        sys.stdout.write('\rreading: {0} of {1}'.format(offset, length))
        data.append(bus.read_byte(address))

    bus.close()

    sys.stdout.write('\rreading: {0} of {0}\n'.format(length))

    return bytes(data)

def write_tng_eeprom(data):
    import smbus

    sys.stdout.write('writing: ...')

    bus = smbus.SMBus(1)
    address = 0x50

    for offset in range(0, len(data), 32):
        sys.stdout.write('\rwriting: {0} of {1}'.format(offset, len(data)))

        block = list(data[offset:offset + 32])

        # the EEPROM support 32 byte page writes, but because the write_i2c_block_data
        # function only allows for a single byte command the second byte of the 16bit
        # data address becomes the first byte of the data argument that is limited to
        # 32 byte leaving only 31 byte left for actual data
        bus.write_i2c_block_data(address, offset // 256, [offset % 256] + block[:31])
        time.sleep(0.015)

        if len(block) > 31:
            # write the last byte of the 32 byte data block, if it exists
            bus.write_i2c_block_data(address, (offset + 31) // 256, [(offset + 31) % 256, block[31]])
            time.sleep(0.015)

    bus.close()

    sys.stdout.write('\rwriting: {0} of {0}\n'.format(len(data)))

def format_string_descriptor(string):
    string_bytes = string.encode('utf-16le')

    return struct.pack('<BB', 2 + len(string_bytes), 3) + string_bytes

def parse_string_descriptor(data):
    if len(data) == 0:
        return []

    assert data[0] == len(data)
    assert data[1] == 3

    return [('string', data[2:].decode('utf-16le'))]

def format_device_descriptor():
    device_bytes = b''

    # USB version
    device_bytes += struct.pack('<H', 0x0200)

    # class code
    device_bytes += b'\xFF'

    # subclass code
    device_bytes += b'\x00'

    # protocol code
    device_bytes += b'\xFF'

    # max packet size
    device_bytes += b'\x40'

    # vendor ID
    device_bytes += struct.pack('<H', 0x0424)

    # product ID
    device_bytes += struct.pack('<H', 0x7500)

    # device release
    device_bytes += struct.pack('<H', 0x0100)

    # manufacturer index
    device_bytes += b'\x01'

    # product name index
    device_bytes += b'\x02'

    # serial number index
    device_bytes += b'\x03'

    # configuration count
    device_bytes += b'\x01'

    assert len(device_bytes) == 16

    return struct.pack('<BB', 2 + len(device_bytes), 1) + device_bytes

def parse_device_descriptor(data):
    if len(data) == 0:
        return []

    assert data[0] == 18
    assert data[1] == 1

    return [
        ('usb_version', struct.unpack_from('<H', data, 2)[0], lambda value: '{0}.{1:02}'.format(value >> 8, value & 0xFF)),
        ('class_code', data[4], str),
        ('subclass_code', data[5], str),
        ('protocol_code', data[6], str),
        ('max_packet_size', data[7], str),
        ('vendor_id', struct.unpack_from('<H', data, 8)[0], '0x{0:04X}'.format),
        ('product_id', struct.unpack_from('<H', data, 10)[0], '0x{0:04X}'.format),
        ('device_release', struct.unpack_from('<H', data, 12)[0], lambda value: '{0}.{1:02}'.format(value >> 8, value & 0xFF)),
        ('manufacturer_index', data[14], str),
        ('product_name_index', data[15], str),
        ('serial_number_index', data[16], str),
        ('configuration_count', data[17], str)
    ]

def parse_config_and_iface_descriptor(data):
    if len(data) == 0:
        return []

    assert data[0] == 9
    assert data[1] == 2

    result = [
        ('total_length', struct.unpack_from('<H', data, 2)[0], str),
        ('interface_count', data[4], str),
        ('configuration_value', data[5], str),
        ('description_index', data[6], str),
        ('attributes', data[7], '0b{0:08b}'.format),
        ('max_power', data[8], lambda value: '{0} mA'.format(value * 2)),
    ]

    offset = 9
    interface_index = 0

    while offset < len(data):
        assert data[offset] == 9
        assert data[offset + 1] == 4

        result.append(('interface_{0}_number'.format(interface_index), data[offset + 2], str))
        result.append(('interface_{0}_alternate_setting'.format(interface_index), data[offset + 3], str))
        result.append(('interface_{0}_endpoint_count'.format(interface_index), data[offset + 4], str))
        result.append(('interface_{0}_class_code'.format(interface_index), data[offset + 5], str))
        result.append(('interface_{0}_subclass_code'.format(interface_index), data[offset + 6], str))
        result.append(('interface_{0}_protocol_code'.format(interface_index), data[offset + 7], str))
        result.append(('interface_{0}_description_index'.format(interface_index), data[offset + 8], str))

        offset += 9
        interface_index += 1

    return result

def format_eth_config(mac_address):
    manufacturer_bytes = format_string_descriptor('Tinkerforge')
    product_name_bytes = format_string_descriptor('LAN7500')
    serial_number_bytes = format_string_descriptor('{0:02X}{1:02X}{2:02X}{3:02X}{4:02X}{5:02X}'.format(*mac_address))
    device_descriptor_bytes = format_device_descriptor()

    # programmed indicator
    config_bytes = b'\xA5'

    # MAC address
    config_bytes += bytes(mac_address)

    # full-speed polling interval for interrupt endpoint
    config_bytes += b'\x01' # 1 ms

    # hi-speed polling interval for interrupt endpoint
    config_bytes += b'\x04' # 4 ms

    # configuration flags 0
    # - no port swap
    # - no PHY boost
    # - automatic duplex detection
    # - automatic speed detection
    # - LED0 and LED1 are used as link/speed/activity LEDs
    # - remote wakeup
    # - self-powered
    config_bytes += b'\x1F' # 0b00011111

    # language ID descriptor
    config_bytes += struct.pack('<H', 0x0409) # English

    # manufacturer string descriptor length (bytes)
    config_bytes += struct.pack('<B', len(manufacturer_bytes))

    # manufacturer string descriptor offset (words)
    config_bytes += struct.pack('<B', 0x22 // 2)

    # product name string descriptor length (bytes)
    config_bytes += struct.pack('<B', len(product_name_bytes))

    # product name string descriptor offset (words)
    config_bytes += struct.pack('<B', (0x22 + len(manufacturer_bytes)) // 2)

    # serial number string descriptor length (bytes)
    config_bytes += struct.pack('<B', len(serial_number_bytes))

    # serial number string descriptor offset (words)
    config_bytes += struct.pack('<B', (0x22 + len(manufacturer_bytes) + len(product_name_bytes)) // 2)

    # configuration string descriptor length (bytes)
    config_bytes += b'\x00'

    # configuration string descriptor offset (words)
    config_bytes += b'\x00'

    # interface string descriptor length (bytes)
    config_bytes += b'\x00'

    # interface string descriptor offset (words)
    config_bytes += b'\x00'

    # hi-speed device descriptor length (bytes)
    config_bytes += struct.pack('<B', len(device_descriptor_bytes))

    # hi-speed device descriptor offset (words)
    config_bytes += struct.pack('<B', (0x22 + len(manufacturer_bytes) + len(product_name_bytes) + len(serial_number_bytes)) // 2)

    # hi-speed configuration and interface descriptor length (bytes)
    config_bytes += b'\x00'

    # hi-speed configuration and interface descriptor offset (words)
    config_bytes += b'\x00'

    # full-speed device descriptor length (bytes)
    config_bytes += struct.pack('<B', len(device_descriptor_bytes))

    # full-speed device descriptor offset (words)
    config_bytes += struct.pack('<B', (0x22 + len(manufacturer_bytes) + len(product_name_bytes) + len(serial_number_bytes)) // 2)

    # full-speed configuration and interface descriptor length (bytes)
    config_bytes += b'\x00'

    # full-speed configuration and interface descriptor offset (words)
    config_bytes += b'\x00'

    # GPIO wakeup enables
    config_bytes += b'\x00\x00'

    # GPIO PME flags
    # - GPIO PME disable
    # - GPIO PME signal via level
    # - GPIO PME pulse length is 1.5 ms
    # - GPIO PME signaling polarity is low
    # - GPIO PME open drain driver
    # - WOL event wakeup supported
    # - Magic Packet event wakeup disabled
    # - Perfect DA event wakeup disabled
    config_bytes += b'\x00' # 0b00000000

    # configuration flags 1
    # - LED2 is used as activity LED
    # - GPIO2 and GPIO3 are used for LEDs
    # - SW_MODE is just asserted for SUSPEND2
    # - SW_MODE is active-low
    config_bytes += b'\xB0' # 0b10110000

    assert len(config_bytes) == 0x22, len(config_bytes)

    config_bytes += manufacturer_bytes
    config_bytes += product_name_bytes
    config_bytes += serial_number_bytes
    config_bytes += device_descriptor_bytes

    assert len(config_bytes) <= ETH_CONFIG_LENGTH, len(config_bytes)

    return config_bytes + b'\x00' * (ETH_CONFIG_LENGTH - len(config_bytes))

def parse_eth_config(config_bytes):
    def get_descriptor(offset, length):
        return config_bytes[offset * 2:offset * 2 + length]

    # programmed indicator
    programmed_indicator = config_bytes[0x00]

    if programmed_indicator != 0xA5:
        print('EEPROM is not programmed')
        return

    print('programmed_indicator:                          0x{0:02X}'.format(programmed_indicator))

    # MAC address
    mac_address = config_bytes[0x01:0x07]

    print('mac_address:                                   {0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(*mac_address))

    # full-speed polling interval for interrupt endpoint
    full_speed_polling_interval = config_bytes[0x07]

    print('full_speed_polling_interval:                   {0} ms'.format(full_speed_polling_interval))

    # hi-speed polling interval for interrupt endpoint
    hi_speed_polling_interval = config_bytes[0x08]

    print('hi_speed_polling_interval:                     {0} ms'.format(hi_speed_polling_interval))

    # configuration flags 0
    configuration_flags_0 = config_bytes[0x09]

    print('configuration_flags_0:                         0b{0:08b}'.format(configuration_flags_0))
    print('  port_swap:                                   0b{0:b}'.format((configuration_flags_0 >> 7) & 0b1))
    print('  pyh_boost:                                   0b{0:02b}'.format((configuration_flags_0 >> 5) & 0b11))
    print('  duplex_detection:                            0b{0:b}'.format((configuration_flags_0 >> 4) & 0b1))
    print('  speed_detection:                             0b{0:b}'.format((configuration_flags_0 >> 3) & 0b1))
    print('  speed_led_function:                          0b{0:b}'.format((configuration_flags_0 >> 2) & 0b1))
    print('  remote_wakeup_support:                       0b{0:b}'.format((configuration_flags_0 >> 1) & 0b1))
    print('  power_method:                                0b{0:b}'.format(configuration_flags_0 & 0b1))

    # language ID descriptor
    language_id_descriptor = struct.unpack('<H', config_bytes[0x0A:0x0C])[0]

    print('language_id_descriptor:                        0x{0:04X}'.format(language_id_descriptor))

    # manufacturer string descriptor length (bytes)
    manufacturer_string_descriptor_length = config_bytes[0x0C]

    print('manufacturer_string_descriptor_length:         0x{0:04X}'
          .format(manufacturer_string_descriptor_length))

    # manufacturer string descriptor offset (words)
    manufacturer_string_descriptor_offset = config_bytes[0x0D]

    print('manufacturer_string_descriptor_offset:         0x{0:04X} (0x{1:04X})'
          .format(manufacturer_string_descriptor_offset, manufacturer_string_descriptor_offset * 2))

    # manufacturer string descriptor
    manufacturer_string_descriptor = get_descriptor(manufacturer_string_descriptor_offset, manufacturer_string_descriptor_length)

    print('manufacturer_string_descriptor:                {0}'.format(manufacturer_string_descriptor))

    for name, value in parse_string_descriptor(manufacturer_string_descriptor):
        print('  {0:45}{1}'.format(name + ':', value))

    # product name string descriptor length (bytes)
    product_name_string_descriptor_length = config_bytes[0x0E]

    print('product_name_string_descriptor_length:         0x{0:04X}'
          .format(product_name_string_descriptor_length))

    # product name string descriptor offset (words)
    product_name_string_descriptor_offset = config_bytes[0x0F]

    print('product_name_string_descriptor_offset:         0x{0:04X} (0x{1:04X})'
          .format(product_name_string_descriptor_offset, product_name_string_descriptor_offset * 2))

    # product name string descriptor
    product_name_string_descriptor = get_descriptor(product_name_string_descriptor_offset, product_name_string_descriptor_length)

    print('product_name_string_descriptor:                {0}'.format(product_name_string_descriptor))

    for name, value in parse_string_descriptor(product_name_string_descriptor):
        print('  {0:45}{1}'.format(name + ':', value))

    # serial number string descriptor length (bytes)
    serial_number_string_descriptor_length = config_bytes[0x10]

    print('serial_number_string_descriptor_length:        0x{0:04X}'
          .format(serial_number_string_descriptor_length))

    # serial number string descriptor offset (words)
    serial_number_string_descriptor_offset = config_bytes[0x11]

    print('serial_number_string_descriptor_offset:        0x{0:04X} (0x{1:04X})'
          .format(serial_number_string_descriptor_offset, serial_number_string_descriptor_offset * 2))

    # serial number string descriptor
    serial_number_string_descriptor = get_descriptor(serial_number_string_descriptor_offset, serial_number_string_descriptor_length)

    print('serial_number_string_descriptor:               {0}'.format(serial_number_string_descriptor))

    for name, value in parse_string_descriptor(serial_number_string_descriptor):
        print('  {0:45}{1}'.format(name + ':', value))

    # configuration string descriptor length (bytes)
    configuration_string_descriptor_length = config_bytes[0x12]

    print('configuration_string_descriptor_length:        0x{0:04X}'
          .format(configuration_string_descriptor_length))

    # configuration string descriptor offset (words)
    configuration_string_descriptor_offset = config_bytes[0x13]

    print('configuration_string_descriptor_offset:        0x{0:04X} (0x{1:04X})'
          .format(configuration_string_descriptor_offset, configuration_string_descriptor_offset * 2))

    # configuration string descriptor
    configuration_string_descriptor = get_descriptor(configuration_string_descriptor_offset, configuration_string_descriptor_length)

    print('configuration_string_descriptor:               {0}'.format(configuration_string_descriptor))

    for name, value in parse_string_descriptor(configuration_string_descriptor):
        print('  {0:45}{1}'.format(name + ':', value))

    # interface string descriptor length (bytes)
    interface_string_descriptor_length = config_bytes[0x14]

    print('interface_string_descriptor_length:            0x{0:04X}'
          .format(interface_string_descriptor_length))

    # interface string descriptor offset (words)
    interface_string_descriptor_offset = config_bytes[0x15]

    print('interface_string_descriptor_offset:            0x{0:04X} (0x{1:04X})'
          .format(interface_string_descriptor_offset, interface_string_descriptor_offset * 2))

    # interface string descriptor
    interface_string_descriptor = get_descriptor(interface_string_descriptor_offset, interface_string_descriptor_length)

    print('interface_string_descriptor:                   {0}'.format(interface_string_descriptor))

    for name, value in parse_string_descriptor(interface_string_descriptor):
        print('  {0:45}{1}'.format(name + ':', value))

    # hi-speed device descriptor length (bytes)
    hi_speed_device_descriptor_length = config_bytes[0x16]

    print('hi_speed_device_descriptor_length:             0x{0:04X}'
          .format(hi_speed_device_descriptor_length))

    # hi-speed device descriptor offset (words)
    hi_speed_device_descriptor_offset = config_bytes[0x17]

    print('hi_speed_device_descriptor_offset:             0x{0:04X} (0x{1:04X})'
          .format(hi_speed_device_descriptor_offset, hi_speed_device_descriptor_offset * 2))

    # hi-speed device descriptor
    hi_speed_device_descriptor = get_descriptor(hi_speed_device_descriptor_offset, hi_speed_device_descriptor_length)

    print('hi_speed_device_descriptor:                    {0}'.format(hi_speed_device_descriptor))

    for name, value, value_format in parse_device_descriptor(hi_speed_device_descriptor):
        print('  {0:45}{1}'.format(name + ':', value_format(value)))

    # hi-speed configuration and interface descriptor length (bytes)
    hi_speed_config_and_iface_descriptor_length = config_bytes[0x18]

    print('hi_speed_config_and_iface_descriptor_length:   0x{0:04X}'
          .format(hi_speed_config_and_iface_descriptor_length))

    # hi-speed configuration and interface descriptor offset (words)
    hi_speed_config_and_iface_descriptor_offset = config_bytes[0x19]

    print('hi_speed_config_and_iface_descriptor_offset:   0x{0:04X} (0x{1:04X})'
          .format(hi_speed_config_and_iface_descriptor_offset, hi_speed_config_and_iface_descriptor_offset * 2))

    # hi-speed configuration and interface descriptor
    hi_speed_config_and_iface_descriptor = get_descriptor(hi_speed_config_and_iface_descriptor_offset, hi_speed_config_and_iface_descriptor_length)

    print('hi_speed_config_and_iface_descriptor:          {0}'.format(hi_speed_config_and_iface_descriptor))

    for name, value, value_format in parse_config_and_iface_descriptor(hi_speed_config_and_iface_descriptor):
        print('  {0:45}{1}'.format(name + ':', value_format(value)))

    # full-speed device descriptor length (bytes)
    full_speed_device_descriptor_length = config_bytes[0x1A]

    print('full_speed_device_descriptor_length:           0x{0:04X}'
          .format(full_speed_device_descriptor_length))

    # full-speed device descriptor offset (words)
    full_speed_device_descriptor_offset = config_bytes[0x1B]

    print('full_speed_device_descriptor_offset:           0x{0:04X} (0x{1:04X})'
          .format(full_speed_device_descriptor_offset, full_speed_device_descriptor_offset * 2))

    # full-speed device descriptor
    full_speed_device_descriptor = get_descriptor(full_speed_device_descriptor_offset, full_speed_device_descriptor_length)

    print('full_speed_device_descriptor:                  {0}'.format(full_speed_device_descriptor))

    for name, value, value_format in parse_device_descriptor(full_speed_device_descriptor):
        print('  {0:45}{1}'.format(name + ':', value_format(value)))

    # full-speed configuration and interface descriptor length (bytes)
    full_speed_config_and_iface_descriptor_length = config_bytes[0x1C]

    print('full_speed_config_and_iface_descriptor_length: 0x{0:04X}'
          .format(full_speed_config_and_iface_descriptor_length))

    # full-speed configuration and interface descriptor offset (words)
    full_speed_config_and_iface_descriptor_offset = config_bytes[0x1D]

    print('full_speed_config_and_iface_descriptor_offset: 0x{0:04X} (0x{1:04X})'
          .format(full_speed_config_and_iface_descriptor_offset, full_speed_config_and_iface_descriptor_offset * 2))

    # full-speed configuration and interface descriptor
    full_speed_config_and_iface_descriptor = get_descriptor(full_speed_config_and_iface_descriptor_offset, full_speed_config_and_iface_descriptor_length)

    print('full_speed_config_and_iface_descriptor:        {0}'.format(full_speed_config_and_iface_descriptor))

    for name, value, value_format in parse_config_and_iface_descriptor(full_speed_config_and_iface_descriptor):
        print('  {0:45}{1}'.format(name + ':', value_format(value)))

    # GPIO wakeup enables
    gpio_wakeup_enables = struct.unpack('<H', config_bytes[0x1E:0x20])[0]

    print('gpio_wakeup_enables:                           0b{0:012b}'.format(gpio_wakeup_enables))

    for i in range(12):
        print('  gpio{0}_wakeup:                               {1}0b{2:b}'.format(i, ' ' if i < 10 else '', (gpio_wakeup_enables >> i) & 0b1))

    # GPIO PME flags
    gpio_pme_flags = config_bytes[0x20]

    print('gpio_pme_flags:                                0b{0:08b}'.format(gpio_pme_flags))
    print('  enable:                                      0b{0:b}'.format((gpio_pme_flags >> 7) & 0b1))
    print('  configuration:                               0b{0:b}'.format((gpio_pme_flags >> 6) & 0b1))
    print('  length:                                      0b{0:b}'.format((gpio_pme_flags >> 5) & 0b1))
    print('  polarity:                                    0b{0:b}'.format((gpio_pme_flags >> 4) & 0b1))
    print('  buffer_type:                                 0b{0:b}'.format((gpio_pme_flags >> 3) & 0b1))
    print('  wol_select:                                  0b{0:b}'.format((gpio_pme_flags >> 2) & 0b1))
    print('  magic packet enable:                         0b{0:b}'.format((gpio_pme_flags >> 1) & 0b1))
    print('  perfect_da_enable:                           0b{0:b}'.format(gpio_pme_flags & 0b1))

    # configuration flags 1
    configuration_flags_1 = config_bytes[0x21]

    print('configuration_flags_1:                         0b{0:08b}'.format(configuration_flags_1))
    print('  led2_function:                               0b{0:b}'.format((configuration_flags_1 >> 7) & 0b1))
    print('  gpio_enable:                                 0b{0:05b}'.format((configuration_flags_1 >> 2) & 0b11111))
    print('  sw_mode_sel:                                 0b{0:b}'.format((configuration_flags_1 >> 1) & 0b1))
    print('  sw_mode_pol:                                 0b{0:b}'.format(configuration_flags_1 & 0b1))

def read_eth_eeprom(device):
    if device == None:
        device = os.listdir('/sys/devices/platform/soc/3f980000.usb/usb1/1-1/1-1.7/1-1.7:1.0/net/')[0]

    print('reading from {0}'.format(device))

    data = subprocess.check_output(['ethtool', '-e', device, 'raw', 'on', 'offset', '0', 'length', str(ETH_CONFIG_LENGTH)])

    assert len(data) == ETH_CONFIG_LENGTH

    return data

def write_eth_eeprom(device, data):
    assert len(data) == ETH_CONFIG_LENGTH

    if device == None:
        device = os.listdir('/sys/devices/platform/soc/3f980000.usb/usb1/1-1/1-1.7/1-1.7:1.0/net/')[0]

    print('writing to {0}'.format(device))

    return subprocess.check_output(['ethtool', '-E', device, 'magic', '29952', 'offset', '0', 'length', str(ETH_CONFIG_LENGTH)], input=data)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('action', choices=['tng-print', 'tng-read', 'tng-write', 'eth-print', 'eth-read', 'eth-write', 'eth-clear'])
    parser.add_argument('--eth-device')

    args = parser.parse_args()

    uid = '7xwQ9g' # FIXME
    hostname = 'tng-base-' + uid
    password = 'foobar' # FIXME
    mac_address = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC] # FIXME

    if args.action == 'tng-print':
        config_bytes = format_tng_config(uid, hostname, password, mac_address)

        print_hex(config_bytes)
    elif args.action == 'tng-read':
        config_bytes = read_tng_eeprom(TNG_CONFIG_LENGTH)

        print_hex(config_bytes)
    elif args.action == 'tng-write':
        config_bytes = format_tng_config(uid, hostname, password, mac_address)

        write_tng_eeprom(config_bytes)

        data = read_tng_eeprom(len(config_bytes))

        if config_bytes != data:
            print('error: verification failed')
            exit(1)
    elif args.action == 'eth-print':
        config_bytes = format_eth_config(mac_address)

        print_hex(config_bytes)
        print()
        parse_eth_config(config_bytes)
    elif args.action == 'eth-read':
        config_bytes = read_eth_eeprom(args.eth_device)

        print()
        print_hex(config_bytes)
        print()
        parse_eth_config(config_bytes)
    elif args.action == 'eth-write':
        config_bytes = format_eth_config(mac_address)

        write_eth_eeprom(args.eth_device, config_bytes)

        data = read_eth_eeprom(args.eth_device)

        if config_bytes != data:
            print('error: verification failed')
            exit(1)
    elif args.action == 'eth-clear':
        config_bytes = b'\xFF' * ETH_CONFIG_LENGTH

        write_eth_eeprom(args.eth_device, config_bytes)

        data = read_eth_eeprom(args.eth_device)

        if config_bytes != data:
            print('error: verification failed')
            exit(1)

if __name__ == '__main__':
    main()
