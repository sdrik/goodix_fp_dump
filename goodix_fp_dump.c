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

#define GOODIX_FP_VID            0x27c6
#define GOODIX_FP_PID            0x5385
#define GOODIX_FP_CONFIGURATION  1
#define GOODIX_FP_COMM_INTERFACE 0
#define GOODIX_FP_DATA_INTERFACE 1
#define GOODIX_FP_IN_EP          0x81
#define GOODIX_FP_OUT_EP         0x03

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

static int get_msg_a8_sensor_id(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt[64] = "\xa8\x03\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			   "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			   "\x88\xfa\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			   "\xa0\xf4\x7c\x21\x91\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ;

	ret = send_data(dev, pkt, 64);
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

static int get_msg_a2(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt[64] = "\xa2\x03\x00\x01\x14\xf0\x00\x00\x3d\xe9\x6d\x0f\xf9\x7f\x00\x00" \
			   "\xed\x00\x00\x00\x91\x01\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			   "\x78\xfa\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	ret = send_data(dev, pkt, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

#if 0
	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;
#endif

out:
	return ret;
}

static int get_msg_82(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt[64] = "\x82\x06\x00\x00\x00\x00\x04\x00\x1e\x00\x00\x00\x00\x00\x00\x00" \
			   "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			   "\xe8\xf9\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	ret = send_data(dev, pkt, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

out:
	return ret;
}

static int get_msg_a6(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt[64] = "\xa6\x03\x00\x00\x00\x01\x00\x00\x3d\xe9\x6d\x0f\xf9\x7f\x00\x00" \
			   "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			   "\x88\xf9\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	ret = send_data(dev, pkt, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

out:
	return ret;
}

static int get_msg_e4(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt1[64] = "\xe4\x05\x00\x01\xb0\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00" \
			    "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			    "\xa8\xec\xb7\x53\x15\x00\x00\x00\x60\x74\x35\x0a\xf9\x7f\x00\x00" \
			    "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x27\x7f\x21\x91\x01\x00\x00";

	uint8_t pkt2[64] = "\xe4\x05\x00\x03\xb0\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00" \
			    "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			    "\xa8\xec\xb7\x53\x15\x00\x00\x00\x60\x74\x35\x0a\xf9\x7f\x00\x00" \
			    "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x27\x7f\x21\x91\x01\x00\x00";


	ret = send_data(dev, pkt1, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = send_data(dev, pkt2, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

out:
	return ret;
}

/* some negotiatoin happens with packet d2 */
static int get_msg_d2(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };
	uint8_t pkt1[64] = "\xd2\x29\x00\x01\xff\x00\x00\x28\x00\x00\x00\x1b\x98\xfa\xeb\x82" \
			   "\xd9\x80\xbd\xd7\x28\xbe\x65\x47\xf9\x70\xd7\x94\x5d\xd7\xbf\x48" \
			   "\x95\x2f\xeb\x42\x38\x29\x40\xfd\xb5\xfb\x11\x8f\x00\x00\x00\x00" \
			   "\x00\x00\x00\x00\x00\x00\x00\x00\x30\x14\x77\x21\x91\x01\x00\x00";

	uint8_t pkt2[64] = "\xd2\x2d\x00\x03\xff\x00\x00\x2c\x00\x00\x00\xe9\xb6\x54\xc9\x6d" \
			    "\xe7\x6e\x2a\x19\xf5\x3a\xfc\x96\x35\x6b\x14\x11\x7c\xe3\x9b\x18" \
			    "\x23\x67\xda\x46\x05\xda\x50\x7d\x75\xc1\x1d\xee\xee\xee\xee\xc3" \
			    "\x00\x00\x00\x00\x00\x00\x00\x00\x30\x14\x77\x21\x91\x01\x00\x00";

	ret = send_data(dev, pkt1, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	/*
	 * It looks like packet 2 content must not be constant, it depends on
	 * some earlier value or from the reply to the first paket
	 */

#if 0
	ret = send_data(dev, pkt2, 64);
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	ret = read_data(dev, buffer, sizeof(buffer));
	if (ret < 0)
		goto out;

	/* If we pass this point negotiation succeeded */
	trace("Hurrah!\n");
#endif

out:
	return ret;
}

#if 0

static int get_msg_90(libusb_device_handle *dev)
{}

static int get_msg_91(libusb_device_handle *dev)
{}

static int get_msg_36(libusb_device_handle *dev)
{}

/* this is probably the message to get an image, together with 36 */
static int get_msg_20(libusb_device_handle *dev)
{}

/* maybe some shutdown message */
static int get_msg_60(libusb_device_handle *dev)
{}

/* maybe some shutdown message */
static int get_msg_ae(libusb_device_handle *dev)
{}

/* maybe some shutdown message */
static int get_msg_32(libusb_device_handle *dev)
{}

#endif

static int init(libusb_device_handle *dev)
{
	int ret;
	uint8_t buffer[32768] = { 0 };

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

	ret = get_msg_a8_sensor_id(dev);
	if (ret < 0) {
		error("Error, cannot get sensor ID: %d\n", ret);
		goto out;
	}

	ret = get_msg_a2(dev);
	if (ret < 0) {
		error("Error, cannot get message 0xa2: %d\n", ret);
		goto out;
	}

	ret = get_msg_82(dev);
	if (ret < 0) {
		error("Error, cannot get message 0x82: %d\n", ret);
		goto out;
	}

	ret = get_msg_a6(dev);
	if (ret < 0) {
		error("Error, cannot get message 0xa6: %d\n", ret);
		goto out;
	}

	ret = get_msg_e4(dev);
	if (ret < 0) {
		error("Error, cannot get message 0xe4: %d\n", ret);
		goto out;
	}

	ret = get_msg_d2(dev);
	if (ret < 0) {
		error("Error, cannot get message 0xd2: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static int claim_interface(libusb_device_handle *dev, int interface_number)
{
	int ret = libusb_claim_interface(dev, interface_number);
	if (ret < 0) {
		fprintf(stderr, "libusb_claim_interface failed: %s\n",
			libusb_error_name(ret));
		fprintf(stderr, "Cannot claim interface %d\n",
			interface_number);
	}

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

	/* Claim both interfaces, the cdc_acm driver may be bound to them. */
	ret = claim_interface(dev, GOODIX_FP_COMM_INTERFACE);
	if (ret < 0)
		goto out_libusb_close;

	ret = claim_interface(dev, GOODIX_FP_DATA_INTERFACE);
	if (ret < 0)
		goto out_libusb_release_comm_interface;

	/*
	 * Checking that the configuration has not changed, as suggested in
	 * http://libusb.sourceforge.net/api-1.0/caveats.html
	 */
	current_configuration = -1;
	ret = libusb_get_configuration(dev, &current_configuration);
	if (ret < 0) {
		fprintf(stderr, "libusb_get_configuration after claim failed: %s\n",
			libusb_error_name(ret));
		goto out_libusb_release_interfaces;
	}

	if (current_configuration != GOODIX_FP_CONFIGURATION) {
		fprintf(stderr, "libusb configuration changed (expected: %d, current: %d)\n",
			GOODIX_FP_CONFIGURATION, current_configuration);
		ret = -EINVAL;
		goto out_libusb_release_interfaces;
	}

	init(dev);

out_libusb_release_interfaces:
	libusb_release_interface(dev, GOODIX_FP_DATA_INTERFACE);
out_libusb_release_comm_interface:
	libusb_release_interface(dev, GOODIX_FP_COMM_INTERFACE);
out_libusb_close:
	libusb_close(dev);
out_libusb_exit:
	libusb_exit(NULL);
out:
	return ret;
}
