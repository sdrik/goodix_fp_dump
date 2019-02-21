/*
 * goodix_fp_dump - dump data from the Goodix HTK32 fingerprint reader
 *
 * Copyright 2019, Collabora Ltd
 * Author: Antonio Ospite <antonio.ospite@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libusb.h>

#define GOODIX_FP_VID           0x27c6
#define GOODIX_FP_PID           0x5385
#define GOODIX_FP_CONFIGURATION 1
#define GOODIX_FP_INTERFACE     0
#define GOODIX_FP_IN_EP         0x81
#define GOODIX_FP_OUT_EP        0x03

#define trace(...) fprintf(stderr, __VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)

static inline unsigned int in_80chars(unsigned int i)
{
	/* The 3 below is the length of "xx " where xx is the hex string
	 * representation of a byte */
	return ((i + 1) % (80 / 3));
}

static void trace_dump_buffer(const char *message, uint8_t *buffer, unsigned int len)
{
	unsigned int i;

	if (buffer == NULL || len == 0)
		return;

	trace("\n");
	if (message)
		trace("%s\n", message);

	for (i = 0; i < len; i++) {
		trace("%02hhX%c", buffer[i], (in_80chars(i) && (i < len - 1)) ? ' ' : '\n');
	}
	trace("\n");
}

static int send_data(libusb_device_handle *dev, uint8_t *buffer, unsigned int len)
{
	int ret;
	int transferred;

	trace_dump_buffer("sending -->", buffer, len);

	transferred = 0;
	ret = libusb_bulk_transfer(dev, GOODIX_FP_OUT_EP, buffer, len, &transferred, 0);
	if (ret != 0 || (unsigned int)transferred != len) {
		error("%s. Transferred: %d (expected %u)\n",
		      libusb_error_name(ret), transferred, len);
		return ret;
	}

	return 0;
}

static int read_data(libusb_device_handle *dev, uint8_t *buffer, unsigned int len)
{

	int ret;
	int transferred;

	transferred = 0;
	ret = libusb_bulk_transfer(dev, GOODIX_FP_IN_EP, buffer, len, &transferred, 0);
	if (ret != 0) {
		error("%s. Transferred: %d (expected %u)\n",
		      libusb_error_name(ret), transferred, len);
		return ret;
	}

	trace_dump_buffer("<-- received", buffer, transferred);

	return transferred;
}

static int init(libusb_device_handle *dev)
{
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt1[64] = "\xa8\x03\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			    "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			    "\x88\xfa\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			    "\xa0\xf4\x7c\x21\x91\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ;
	int ret;

	ret =libusb_control_transfer(dev,
				     LIBUSB_ENDPOINT_IN |
				     LIBUSB_REQUEST_TYPE_VENDOR |
				     LIBUSB_RECIPIENT_DEVICE,
				     1, 0, 4, buffer, 16, 0);
	if (ret != 16) {
		error("Error, control message 1: %d\n", ret);
		goto out;
	}
	trace_dump_buffer("<-- received", buffer, ret);

	ret = libusb_control_transfer(dev,
				      LIBUSB_ENDPOINT_IN |
				      LIBUSB_REQUEST_TYPE_VENDOR |
				      LIBUSB_RECIPIENT_DEVICE,
				      1, 0, 4, buffer, 64, 0);
	if (ret != 64) {
		error("Error, control message 2: %d\n", ret);
		goto out;
	}
	trace_dump_buffer("<-- received", buffer, ret);

	ret = send_data(dev, pkt1, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	printf("Sensor model: %s\n", buffer + 3);

out:
	return ret;
}

int main(void)
{
	libusb_device_handle *dev;
	int ret;

	ret = libusb_init(NULL);
	if (ret < 0) {
		fprintf(stderr, "libusb_init failed: %s\n",
			libusb_error_name(ret));
		goto out;
	}

	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, 3);

	dev = libusb_open_device_with_vid_pid(NULL, GOODIX_FP_VID, GOODIX_FP_PID);
	if (dev == NULL) {
		fprintf(stderr, "libusb_open failed: %s\n", strerror(errno));
		ret = -errno;
		goto out_libusb_exit;
	}

	int current_configuration = -1;
	ret = libusb_get_configuration(dev, &current_configuration);
	if (ret < 0) {
		fprintf(stderr, "libusb_get_configuration failed: %s\n",
			libusb_error_name(ret));
		goto out_libusb_close;
	}

	if (current_configuration != GOODIX_FP_CONFIGURATION) {
		ret = libusb_set_configuration(dev, GOODIX_FP_CONFIGURATION);
		if (ret < 0) {
			fprintf(stderr, "libusb_set_configuration failed: %s\n",
				libusb_error_name(ret));
			fprintf(stderr, "Cannot set configuration %d\n",
				GOODIX_FP_CONFIGURATION);
			goto out_libusb_close;
		}
	}

	libusb_set_auto_detach_kernel_driver(dev, 1);

	ret = libusb_claim_interface(dev, GOODIX_FP_INTERFACE);
	if (ret < 0) {
		fprintf(stderr, "libusb_claim_interface failed: %s\n",
			libusb_error_name(ret));
		fprintf(stderr, "Cannot claim interface %d\n",
			GOODIX_FP_INTERFACE);
		goto out_libusb_close;
	}

	/*
	 * Checking that the configuration has not changed, as suggested in
	 * http://libusb.sourceforge.net/api-1.0/caveats.html
	 */
	current_configuration = -1;
	ret = libusb_get_configuration(dev, &current_configuration);
	if (ret < 0) {
		fprintf(stderr, "libusb_get_configuration after claim failed: %s\n",
			libusb_error_name(ret));
		goto out_libusb_release_interface;
	}

	if (current_configuration != GOODIX_FP_CONFIGURATION) {
		fprintf(stderr, "libusb configuration changed (expected: %d, current: %d)\n",
			GOODIX_FP_CONFIGURATION, current_configuration);
		ret = -EINVAL;
		goto out_libusb_release_interface;
	}

	init(dev);

out_libusb_release_interface:
	libusb_release_interface(dev, GOODIX_FP_INTERFACE);
out_libusb_close:
	libusb_close(dev);
out_libusb_exit:
	libusb_exit(NULL);
out:
	return ret;
}
