#!/usr/bin/env python3
#
# decode_image_data - extract payload and unpack data from an image packet
#
# Copyright 2019, Collabora Ltd
# Author: Antonio Ospite <antonio.ospite@collabora.com>
#
# SPDX-License-Identifier: LGPL-2.1-or-later

import binascii
import struct
import sys


# The data passed is the raw image packet received from a Goodix fingerprint
# reader, e.g. the Leftover Capture Data of a USB URB in a Wireshark capture.
def extract_payload(data):
    assert len(data) >= 4
    assert data[0] == 0x20

    payload_size = struct.unpack_from('<H', data[1:3])[0]

    assert payload_size > 0

    payload = bytearray()

    # first chunk
    offset = 3
    remaining = payload_size - 1  # skip checksum byte

    # the first chunk can also be the last one
    if remaining < 64 - 3:
        payload += data[offset:offset + remaining]
        return payload

    # first of multiple chunks
    chunk_size = 64 - 3

    payload += data[offset:offset + chunk_size]
    offset += chunk_size + 1  # skip the next continuation byte
    remaining -= chunk_size

    # copy most of the data, skipping the continuation bytes
    chunk_size = 64 - 1
    while remaining >= chunk_size:
        payload += data[offset:offset + chunk_size]
        offset += chunk_size + 1  # skip the next continuation byte
        remaining -= chunk_size

    # copy the last chunk
    payload += data[offset:offset + remaining]

    return payload


# data is 12-bit packed, unpack it to 16-bit elements
def unpack_data_to_16bit_le(data):
    # 3 bytes are needed to represent 2 16-bit values
    assert (len(data) % 3) == 0

    mask = (1 << 12) - 1
    num_values = len(data) // (12 / 8)

    i = 0
    offset = 0
    unpacked_data = []

    while i < num_values:
        tmp_buffer = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

        value1 = (tmp_buffer >> 12) & mask
        upper = (value1 >> 8) & 0xff
        lower = value1 & 0xff
        # Write single bytes in little-endian order
        unpacked_data.append(lower)
        unpacked_data.append(upper)

        value2 = tmp_buffer & mask
        upper = (value2 >> 8) & 0xff
        lower = value2 & 0xff
        # Write single bytes in little-endian order
        unpacked_data.append(lower)
        unpacked_data.append(upper)

        # If instead one wants a single 16bit value, something like the
        # following can be used:
        #   dest.append(value1)
        #   dest.append(value2)

        i += 2
        offset += 3

    return unpacked_data


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: %s <datafile>\n" % sys.argv[0])
        return 1

    fin = open(sys.argv[1], 'rb')
    buf = fin.read()
    fin.close()

    payload = extract_payload(buf)

    fout = open('payload.bin', 'wb+')
    fout.write(bytearray(payload))
    fout.close()

    # According to the Windows driver the first 5 bytes are to be skipped
    # (probably some header), and the last 4 bytes too as they should be a crc.
    image_data = payload[5:-4]

    fout = open('image.bin', 'wb+')
    fout.write(bytearray(payload))
    fout.close()

    # XXX the CRC has not been fully figured out yet.
    #
    # It should be the on the last 4 bytes, but the value does not match, the
    # calculated one.
    crc = struct.unpack_from('<I', payload[-4:])[0]
    print(crc)
    print(hex(crc))
    print(hex(binascii.crc32(image_data)))

    unpacked = unpack_data_to_16bit_le(image_data)
    fout = open('unpacked_image.bin', 'wb+')
    fout.write(bytearray(unpacked))
    fout.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
