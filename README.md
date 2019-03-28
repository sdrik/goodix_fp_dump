`goodix_fp_dump` is a simple test program for the Goodix HTK32 Fingerprint reader present in the
Dell XPS13 9370.

# Test setup

In order to make the device accessible the user needs access to the USB device
node (e.g. `/dev/bus/usb/001/004`); so either run the program with sudo, or add
a udev rule.

Assuming that the user is in the `plugdev` group, something like the following
should work:

```
ACTION=="add", SUBSYSTEM=="usb", ATTRS{idVendor}=="27c6", ATTRS{idProduct}=="5385", MODE="0660", GROUP="plugdev" TAG+="uaccess"
```
# Goodix USB Fingerprint scanner protocol

The USB protocol seems to be quite simple at the packet level:

1. The host sends a command packet with a one-byte command ID.
2. The device replies with a generic reply packet (ID 0xb0) followed by a length
   field (usually with the value of 3) and a short payload containing the ID of
   the packet to which this is a reply.
3. For some commands there are one or further reply packets, starting with the
   ID of the command, followed by the payload length, and the payload data.

However at some point the data gets encrypted, and it is not clear yet what all the different packets mean and how to encryption is performed.

## General packet structure

Packets are sent with bulk-out requests of 64 bytes on endpoint 0x03 of interface 1.

Replies are read with bulk-in requests of 32768 bytes on endpoint 0x81 of interface 1.

The [http://kaitai.io/](Kaitai struct) description of a packet is:

```
meta:
  id: goodix_fp
  endian: le
  license: CC0-1.0
seq:
  - id: header
    type: header
types:
  header:
    seq:
      - id: packet_id
        type: u1
        enum: packet_type
      - id: payload
        type:
          switch-on: packet_id
          cases:
            'packet_type::reply': payload_reply
            'packet_type::firmware_version': payload_firmware_version
            'packet_type::otp': payload_otp
  payload_reply:
    seq:
      - id: payload_size
        type: u2
      - id: reply_to
        type: u1
        enum: packet_type
      - id: unknown
        size: payload_size - 1
  payload_firmware_version:
    seq:
      - id: payload_size
        type: u2
      - id: firmware_version
        type: str
        encoding: ascii
        size: payload_size - 1
  payload_otp:
    seq:
      - id: payload_size
        type: u2
      - id: otp
        size: payload_size - 1
enums:
  packet_type:
    0xb0: reply
    0xa8: firmware_version
    0xa6: otp
```

## Packet types

### Packet 0xb0

This is the generic reply, it is sent in response to every packet and precedes the actual reply packet if there is any.


### Type 0xa8

Seems to be related to the sensor identification: it contains a string which described the sensor, maybe a numeric ID too.

