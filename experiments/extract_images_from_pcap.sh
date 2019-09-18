#!/bin/bash

set -e

[ "x$1" = "x" ] && { echo "usage: $(basename "$0") <pcapng_file>" 1>&2; exit 1; }

i=0

tshark -r "$1" -Y 'frame.len > 1000' -T fields -e usb.capdata | \
while read -r line
do
  suffix=$(printf "%04d" $i)
  echo -n -e "\\x${line//:/\\x}" > image_packet_$suffix.bin

  ./decode_image_packet.py "image_packet_$suffix.bin" "$suffix"
  ./convert_to_pseudo_colors.py "unpacked_image_$suffix.bin" "$suffix"

  i=$((i + 1))
done
