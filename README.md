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
