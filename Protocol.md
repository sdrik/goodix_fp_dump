# Goodix USB Fingerprint scanner protocol

The USB protocol seems to be quite simple at the packet level:

1. The host send a command packet with a one-byte command ID
2. The device replies with a generic reply packer (ID 0xB0 followed by a length
   and the ID of the packet to which this is a reply).
3. For some commands there are one or more further reply packets, starting with
   the ID of the command.

However at some point the data gets encrypted, and it is not clear yet what all the different packets mean and how to encryption is performed.

## General packet structure

Packets are sent with bulk-out requests of 64 bytes.

Replies are read with bulk-in requests of 32768 bytes.

The [http://kaitai.io/](Kaitai struct) description of the packet is:

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
      - id: packet_type
        type: u1
        enum: packet_type
      - id: payload_size
        type: u2
      - id: payload
        size: payload_size
enums:
  packet_type:
    0xb0: reply
    0xa8: sensor_id 
```

## Packet types

### Packet 0xb0

This is the generic reply, it is sent in response to every packet and precedes the actual reply packet if there is any.


### Type 0xa8

Seems to be related to the sensor identification: it contains a string which described the sensor, maybe a numeric ID too.

