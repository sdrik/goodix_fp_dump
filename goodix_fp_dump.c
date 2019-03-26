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
#include <stdbool.h>
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

#define MIN(a,b) (((a)<(b))?(a):(b))

/*
 * The device expects umeric values as little-endian.
 *
 * Endian conversion is needed if the code is run on big-endian systems.
 */
typedef union {
	uint8_t data[64];
	struct __attribute__((packed)) {
		uint8_t type;
		uint16_t payload_size;
		uint8_t payload[61];
	} fields;
} goodix_fp_out_packet;

typedef union {
	uint8_t data[32768];
	struct __attribute__((packed)) {
		uint8_t type;
		uint16_t payload_size;
		uint8_t payload[32765];
	} fields;
} goodix_fp_in_packet;

typedef enum {
	GOODIX_FP_PACKET_TYPE_REPLY = 0xb0,
	GOODIX_FP_PACKET_TYPE_FIRMWARE_VERSION = 0xa8,
	GOODIX_FP_PACKET_TYPE_OTP = 0xa6,
	GOODIX_FP_PACKET_TYPE_PSK = 0xe4,
} goodix_fp_packet_type;

static void trace_dump_buffer(const char *message, uint8_t *buffer, unsigned int len)
{
	unsigned int i;

	if (buffer == NULL || len == 0)
		return;

	trace("\n");
	if (message)
		trace("%s\n", message);

	for (i = 0; i < len; i++) {
		trace("%02hhX%c", buffer[i], (((i + 1) % 16) && (i < len - 1)) ? ' ' : '\n');
	}
	trace("\n");
}

static void trace_dump_buffer_to_file(const char *filename, uint8_t *buffer, unsigned int len)
{
	FILE *fp;

	fp = fopen(filename, "wb");
	if (fp == NULL) {
		perror(filename);
		return;
	}

	fwrite(buffer, 1, len, fp);
	fclose(fp);
}

static void trace_out_packet(goodix_fp_out_packet *packet)
{
	trace("\n");
	trace("out packet\n");
	trace("type: 0x%02hhx %d\n", packet->fields.type, packet->fields.type);
	if (packet->fields.type % 2)
		trace("continuation packet\n");
	else
		trace("size: 0x%02hx %d\n", packet->fields.payload_size, packet->fields.payload_size);
}

static void trace_in_packet(goodix_fp_in_packet *packet)
{
	trace("in packet\n");
	trace("type: 0x%02hhx %d\n", packet->fields.type, packet->fields.type);
	trace("size: 0x%02hx %d\n", packet->fields.payload_size, packet->fields.payload_size);
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

/*
 * Long payloads have some bytes on the 64 bytes boundary of the packet which
 * have to be skipped when copying data.
 */
static unsigned int payload_memcpy(uint8_t *dst, uint8_t *src, size_t n)
{
	unsigned int src_offset;
	unsigned int dst_offset;
	int chunk_size;
	int remaining;
	unsigned int extra_packets;

	src_offset = 0;
	dst_offset = 0;
	remaining = n;
	extra_packets = 0;

	/* skip the header and copy the first chunk of data */
	chunk_size = MIN(n, 64 - 3);
	memcpy(dst, src, chunk_size);
	src_offset += chunk_size + 1; /* skip the next continuation byte */
	dst_offset += chunk_size;
	remaining -= chunk_size;

	/* copy most of the data, skipping the continuation bytes */
	chunk_size = 64 - 1;
	while (remaining >= chunk_size) {
		memcpy(dst + dst_offset, src + src_offset, chunk_size);
		src_offset += chunk_size + 1; /* skip the next continuation byte */
		dst_offset += chunk_size;
		remaining -= chunk_size;
		extra_packets++;
	}

	/* copy the last chunk if there is one */
	if (remaining > 0) {
		memcpy(dst + dst_offset, src + src_offset, remaining);
		extra_packets++;
	}

	return extra_packets;
}

static uint8_t calc_checksum(uint8_t packet_type, uint8_t *payload, uint16_t payload_size)
{
	unsigned int i;
	uint8_t sum;

	sum = packet_type;
	sum += (payload_size + 1) & 0xff;
	sum += (payload_size + 1) >> 8;
	for (i = 0; i < payload_size; i++)
		sum += payload[i];

	return (uint8_t)(0xaa - sum);
}

static bool verify_checksum(uint8_t packet_type, uint8_t *payload, uint16_t payload_size, uint8_t checksum)
{
	uint8_t sum;

	sum = calc_checksum(packet_type, payload, payload_size);

	return sum == checksum;
}

static unsigned int send_multi_packet(libusb_device_handle *dev,
				      goodix_fp_packet_type packet_type,
				      uint8_t *request, uint16_t request_size)
{
	(void) dev;
	(void) packet_type;
	(void) request;
	(void) request_size;

	trace("multi packet requests not implemented yet\n");
	return -1;
}

static int send_packet(libusb_device_handle *dev,
		       goodix_fp_packet_type packet_type,
		       uint8_t *request, uint16_t request_size,
		       uint8_t *response, uint16_t *response_size,
		       bool fixed_checksum)
{
	goodix_fp_out_packet packet = {
		.fields = {
			.type = packet_type,
			.payload_size = request_size + 1,
			.payload = { 0 }
		}
	};
	goodix_fp_in_packet reply = {
		.data = { 0 }
	};
	int ret;
	uint8_t checksum;
	bool is_valid_checksum;

	/* If the request buffer fits into a single packet, send it */
	if (request_size + 1 < 64 - 3) {
		memcpy(packet.fields.payload, request, request_size);

		checksum = calc_checksum(packet_type, request, request_size);
		packet.fields.payload[request_size] = checksum;

		trace_out_packet(&packet);

		ret = send_data(dev, packet.data, sizeof(packet.data));
		if (ret < 0)
			goto out;
	} else {
		ret = send_multi_packet(dev, packet_type, request, request_size);
		if (ret < 0)
			goto out;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet %02x\n", packet.fields.type);
		ret = -1;
		goto out;
	}

	is_valid_checksum = verify_checksum(reply.fields.type,
					    reply.fields.payload,
					    reply.fields.payload_size - 1,
					    reply.fields.payload[reply.fields.payload_size - 1]);
	if (!is_valid_checksum) {
		error("Invalid checksum for reply packet %02x\n", packet.fields.type);
		ret = -1;
		goto out;
	}

	if (response) {
		int extra_packets;
		uint8_t response_checksum;

		ret = read_data(dev, reply.data, sizeof(reply.data));
		if (ret < 0)
			goto out;

		trace_in_packet(&reply);

		if (reply.fields.type != packet_type) {
			error("Invalid input packet %02x (got: %02x)\n", packet_type, reply.fields.type);
			ret = -1;
			goto out;
		}

		extra_packets = payload_memcpy(response, reply.fields.payload, reply.fields.payload_size - 1);

		if (fixed_checksum) {
			response_checksum = 0x88;
		} else {
			response_checksum = reply.fields.payload[reply.fields.payload_size - 1 + extra_packets];
		}

		is_valid_checksum = verify_checksum(reply.fields.type,
						    response,
						    reply.fields.payload_size - 1,
						    response_checksum);
		if (!is_valid_checksum) {
			error("Invalid checksum for input packet %02x\n", reply.fields.type);
			ret = -1;
			goto out;
		}

		*response_size = reply.fields.payload_size - 1;
	}

	ret = 0;

out:
	return ret;

}

static int send_simple_packet(libusb_device_handle *dev,
			      goodix_fp_packet_type packet_type,
			      uint8_t *response,  uint16_t *response_size)
{
	uint8_t payload[2] = { 0 };

	return send_packet(dev, packet_type, payload, 2, response, response_size, false);
}

static int get_msg_a8_firmware_version(libusb_device_handle *dev)
{
	int ret;
	char firmware_version[64] = "";
	uint16_t string_len;


	ret = send_simple_packet(dev, GOODIX_FP_PACKET_TYPE_FIRMWARE_VERSION,
				 (uint8_t *)firmware_version, &string_len);
	if (ret < 0)
		goto out;

	printf("Firmware version: %s\n", firmware_version);
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

static int get_msg_a6_otp(libusb_device_handle *dev)
{
	int ret;
	goodix_fp_out_packet pkt = {
		.data  = "\xa6\x03\x00\x00\x00\x01\x00\x00\x3d\xe9\x6d\x0f\xf9\x7f\x00\x00" \
			  "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			  "\x88\xf9\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	};
	goodix_fp_in_packet reply = {
		.data = { 0 }
	};
	uint8_t otp[32];

	ret = send_data(dev, pkt.data, sizeof(pkt.data));
	if (ret < 0)
		goto out;

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet 0xa6\n");
		return -1;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_OTP) {
		error("Invalid reply to packet 0xa6\n");
		return -1;
	}

	memcpy(otp, reply.fields.payload, reply.fields.payload_size - 1);

	trace_dump_buffer("OTP:", otp, sizeof(otp));
	trace_dump_buffer_to_file("payload_otp.bin", otp, sizeof(otp));
out:
	return ret;
}

static int get_msg_e4_psk(libusb_device_handle *dev)
{
	int ret;
	goodix_fp_out_packet pkt1 = {
		.data = "\xe4\x05\x00\x01\xb0\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00" \
			 "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			 "\xa8\xec\xb7\x53\x15\x00\x00\x00\x60\x74\x35\x0a\xf9\x7f\x00\x00" \
			 "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x27\x7f\x21\x91\x01\x00\x00"
	};

	goodix_fp_out_packet pkt2 = {
		.data = "\xe4\x05\x00\x03\xb0\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00" \
			 "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x33\x0a\xf9\x7f\x00\x00" \
			 "\xa8\xec\xb7\x53\x15\x00\x00\x00\x60\x74\x35\x0a\xf9\x7f\x00\x00" \
			 "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x27\x7f\x21\x91\x01\x00\x00"
	};
	goodix_fp_in_packet reply = {
		.data = { 0 }
	};
	uint8_t psk[601] = { 0 };
	uint8_t hash[41] = { 0 };

	ret = send_data(dev, pkt1.data, sizeof(pkt1.data));
	if (ret < 0)
		goto out;

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet 0xe4\n");
		return -1;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_PSK) {
		error("Invalid reply to packet 0xe4\n");
		return -1;
	}

	/*
	 * The PSK payload contains one leading byte representing an error
	 * code, followed by Type-Length-Value data.
	 *
	 * The TLV structure is as follows.
	 *
	 * The Type field is uint32_t (little-endian):
	 *   - 0x0000b001 means PSK
	 *   - 0x0000b003 mean HASH
	 *
	 * The Length field is uint32_t (little-endian):
	 *   - 0x00000250 for the PSK
	 *   - 0x00000020 for the HASH
	 *
	 * Then the data follows:
	 *   - for the PSK this is a sgx_sealed_data_t
	 *     https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-sealed-data-t
	 *   - for the HASH it should be 32 bytes representing a sha256 hash
	 *     of something from the PSK, after unsealing the data
	 */
	payload_memcpy(psk, reply.fields.payload, reply.fields.payload_size - 1);
	trace_dump_buffer("PSK:", psk, sizeof(psk));
	trace_dump_buffer_to_file("payload_psk.bin", psk, sizeof(psk));

	ret = send_data(dev, pkt2.data, sizeof(pkt2.data));
	if (ret < 0)
		goto out;

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet 0xe4\n");
		return -1;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_PSK) {
		error("Invalid reply to packet 0xe4\n");
		return -1;
	}

	memcpy(hash, reply.fields.payload, reply.fields.payload_size - 1);
	trace_dump_buffer("HASH:", hash, sizeof(hash));
	trace_dump_buffer_to_file("payload_hash.bin", hash, sizeof(hash));

out:
	return ret;
}

/* some negotiation happens with packet d2 */
static int get_msg_d2(libusb_device_handle *dev)
{
	int ret;
	unsigned int i;
	uint8_t client_hello[32 + 8] = "\x01\xff\x00\x00\x28\x00\x00\x00";
	uint8_t server_reply[64 + 8] = { 0 } ;
	uint16_t server_reply_size = 0;
	uint8_t client_handshake[32 + 8 + 4] = "\x03\xff\x00\x00\x2c\x00\x00\x00";

	/* Use a constant secret for now */
	for (i = 0; i < 32; i++)
		client_hello[i + 8] = 0;

	trace_dump_buffer_to_file("client_random.bin", client_hello + 8, 32);

	ret = send_packet(dev, 0xd2, client_hello, sizeof(client_hello), server_reply, &server_reply_size, false);
	if (ret < 0)
		goto out;

	/*
	 * It looks like packet 2 content must not be constant, it depends on
	 * some earlier value or from the reply to the first packet
	 */

	trace_dump_buffer_to_file("server_random1.bin", server_reply + 8, 32);
	trace_dump_buffer_to_file("server_random2.bin", server_reply + 8 + 32, 32);

	trace_dump_buffer("server_reply:", server_reply, sizeof(server_reply));

	/* copy the server key into the reply packet */
	memcpy(client_handshake + 8, server_reply + 8 + 32, 32);

	/* add some constant bytes */
	memcpy(client_handshake + 8 + 32, "\xee\xee\xee\xee", 4);

	ret = send_packet(dev, 0xd2, client_handshake, sizeof(client_handshake), NULL, NULL, false);
	if (ret < 0)
		goto out;

	/* If we pass this point negotiation succeeded */
	trace("Hurrah!\n");

out:
	return ret;
}

#if 0

static int get_msg_90(libusb_device_handle *dev)
{
	int ret;
	unsigned int i;
	goodix_fp_out_packet pkts[5] = {
		[0] = {
			.data = "\x90\x01\x01\x40\x11\x6c\x7d\x28\xa5\x28\xcd\x1c\xe9\x10\xf9\x00" \
				 "\xf9\x00\xf9\x00\x04\x02\x00\x00\x08\x00\x11\x11\xba\x00\x01\x80" \
				 "\xca\x00\x07\x00\x84\x00\xbe\xb2\x86\x00\xc5\xb9\x88\x00\xb5\xad" \
				 "\x8a\x00\x9d\x95\x8c\x00\x00\xbe\x8e\x00\x00\xc5\x90\x00\x00\xb5"
		},
		[1] = {
			.data = "\x91\x92\x00\x00\x9d\x94\x00\x00\xaf\x96\x00\x00\xbf\x98\x00\x00" \
				 "\xb6\x9a\x00\x00\xa7\x30\x00\x6c\x1c\x50\x00\x01\x05\xd0\x00\x00" \
				 "\x00\x70\x00\x00\x00\x72\x00\x78\x56\x74\x00\x34\x12\x26\x00\x00" \
				 "\x12\x20\x00\x10\x40\x12\x00\x03\x04\x02\x02\x16\x21\x2c\x02\x0a"

		},
		[2] = {
			.data = "\x91\x03\x2a\x01\x02\x00\x22\x00\x01\x20\x24\x00\x32\x00\x80\x00" \
				 "\x05\x04\x5c\x00\x00\x01\x56\x00\x28\x20\x58\x00\x01\x00\x32\x00" \
				 "\x24\x02\x82\x00\x80\x0c\x20\x02\x88\x0d\x2a\x01\x92\x07\x22\x00" \
				 "\x01\x20\x24\x00\x14\x00\x80\x00\x05\x04\x5c\x00\x9b\x00\x56\x00"
		},
		[3] = {
			.data = "\x91\x08\x20\x58\x00\x03\x00\x32\x00\x08\x04\x82\x00\x80\x12\x20" \
				 "\x02\xf8\x0c\x2a\x01\x18\x04\x5c\x00\x9b\x00\x54\x00\x00\x01\x62" \
				 "\x00\x09\x03\x64\x00\x18\x00\x82\x00\x80\x0c\x20\x02\xf8\x0c\x2a" \
				 "\x01\x18\x04\x5c\x00\x9b\x00\x52\x00\x08\x00\x54\x00\x00\x01\x00"
		},
		[4] = {
			.data = "\x91\x00\x00\x00\x00\x50\x5e\x6f\x00\x08\x04\x82\x00\x80\x12\x20" \
				 "\x02\xf8\x0c\x2a\x01\x18\x04\x5c\x00\x9b\x00\x54\x00\x00\x01\x62" \
				 "\x00\x09\x03\x64\x00\x18\x00\x82\x00\x80\x0c\x20\x02\xf8\x0c\x2a" \
				 "\x01\x18\x04\x5c\x00\x9b\x00\x52\x00\x08\x00\x54\x00\x00\x01\x00"
		}
	};
	goodix_fp_in_packet reply = {
		.data = { 0 }
	};

	for (i = 0; i < 5; i++) {
		goodix_fp_out_packet *pkt = &pkts[i];

		trace_out_packet(pkt);

		ret = send_data(dev, pkt->data, sizeof(pkt->data));
		if (ret < 0)
			goto out;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet 0x90\n");
		return -1;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != 0x90) {
		error("Invalid reply to packet 0x90\n");
		return -1;
	}

out:
	return ret;
}

static int get_msg_36(libusb_device_handle *dev)
{
	int ret;
	goodix_fp_out_packet pkt = {
		.data = "\x36\x1b\x00\x0d\x01\x97\x97\xa1\xa1\x9b\x9b\x92\x92\x96\x96\xa4" \
			 "\xa4\x9d\x9d\x95\x95\x94\x94\xa1\xa1\x9c\x9c\x8e\x8e\xeb\x00\x00" \
			 "\x48\xf8\xb7\x53\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			 "\x00\x00\x00\x00\x00\x00\x00\x00\x30\x14\x77\x21\x91\x01\x00\x00"
	};
	goodix_fp_in_packet reply = {
		.data = { 0 }
	};

	trace_out_packet(&pkt);

	ret = send_data(dev, pkt.data, sizeof(pkt.data));
	if (ret < 0)
		goto out;

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet 0x36\n");
		return -1;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != 0x36) {
		error("Invalid reply to packet 0x36\n");
		return -1;
	}

out:
	return ret;

}

/* this is probably the message to get an image, together with 36 */
static int get_msg_20(libusb_device_handle *dev)
{
	int ret;
	goodix_fp_out_packet pkt = {
		.data = "\x20\x05\x00\x01\x06\xcf\x00\xaf\x00\x00\x00\x00\x00\x00\x00\x00" \
			 "\xed\x00\x00\x00\x00\x00\x00\x00\x88\xba\x79\x81\xfb\x7f\x00\x00" \
			 "\x08\xf1\xdf\x52\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			 "\x00\x00\x00\x00\x00\x00\x00\x00\x20\x89\xac\x47\xd0\x01\x00\x00"
	};
	goodix_fp_in_packet reply = {
		.data = { 0 }
	};
	uint8_t image[14656] = { 0 };

	trace_out_packet(&pkt);

	ret = send_data(dev, pkt.data, sizeof(pkt.data));
	if (ret < 0)
		goto out;

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != GOODIX_FP_PACKET_TYPE_REPLY) {
		error("Invalid reply to packet 0x20\n");
		return -1;
	}

	ret = read_data(dev, reply.data, sizeof(reply.data));
	if (ret < 0)
		goto out;

	trace_in_packet(&reply);

	if (reply.fields.type != 0x20) {
		error("Invalid reply to packet 0x20\n");
		return -1;
	}

	payload_memcpy(image, reply.fields.payload, reply.fields.payload_size - 1);
	trace_dump_buffer_to_file("payload_image.bin", image, reply.fields.payload_size - 1);

out:
	return ret;
}

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

	ret = get_msg_a8_firmware_version(dev);
	if (ret < 0) {
		error("Error, cannot get Firmware version: %d\n", ret);
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

	ret = get_msg_a6_otp(dev);
	if (ret < 0) {
		error("Error, cannot get OTP: %d\n", ret);
		goto out;
	}

	ret = get_msg_e4_psk(dev);
	if (ret < 0) {
		error("Error, cannot get message 0xe4: %d\n", ret);
		goto out;
	}

	ret = get_msg_d2(dev);
	if (ret < 0) {
		error("Error, cannot get message 0xd2: %d\n", ret);
		goto out;
	}

#if 0
	ret = get_msg_90(dev);
	if (ret < 0) {
		error("Error, cannot get message 0x90: %d\n", ret);
		goto out;
	}

	ret = get_msg_36(dev);
	if (ret < 0) {
		error("Error, cannot get message 0x36: %d\n", ret);
		goto out;
	}

	ret = get_msg_20(dev);
	if (ret < 0) {
		error("Error, cannot get message 0x20: %d\n", ret);
		goto out;
	}
#endif

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
