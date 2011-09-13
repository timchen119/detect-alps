/*
 * Copyright (C) 2010-2011 Canonical
 * Author: Seth Forshee <seth.forshee@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <glob.h>

/*
 * PS/2 mouse commands (copied from kernel)
 *
 * Bits 12 - 15: Data bytes to send following command
 * Bits  8 - 11: Data bytes to receive following command
 * Bits  0 -  7: Command
 */
#define PSMOUSE_CMD_SETSCALE11	0x00e6
#define PSMOUSE_CMD_SETSCALE21	0x00e7
#define PSMOUSE_CMD_SETRES	0x10e8
#define PSMOUSE_CMD_GETINFO	0x03e9
#define PSMOUSE_CMD_SETSTREAM	0x00ea
#define PSMOUSE_CMD_SETPOLL	0x00f0
#define PSMOUSE_CMD_POLL	0x00eb	/* caller sets number of bytes to receive */
#define PSMOUSE_CMD_GETID	0x02f2
#define PSMOUSE_CMD_SETRATE	0x10f3
#define PSMOUSE_CMD_ENABLE	0x00f4
#define PSMOUSE_CMD_DISABLE	0x00f5
#define PSMOUSE_CMD_RESET_DIS	0x00f6
#define PSMOUSE_CMD_RESET_BAT	0x02ff

enum {
	ALPS_PROTO_V3,
	ALPS_PROTO_V4,
};

struct alps_serio_dev {
	int proto_version;
	char *serio_drvctl_path;
	int serio_fd;
};

static int verbose = 0;

#define verbose_printf(fmt, args...) do { if (verbose) printf(fmt, ##args); } while (0)

/*
 * Read wrapper that continues until the requested number of bytes have
 * been read or an error occurs. Returns 0 on success.
 */
static int do_read(int fd, void *buf, size_t count)
{
	size_t bytes_read = 0;
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;

	do {
		/* Use poll to timeout if we aren't getting data */
		ret = poll(&pfd, 1, 500);
		if (ret == 0 || ret == -1)
			return -1;

		ret = read(fd, (char *)buf + bytes_read, count - bytes_read);
		if (ret == -1) {
			switch (errno) {
			case EAGAIN:
				continue;
			default:
				return -1;
			}
		} else if (ret == 0) {
			fprintf(stderr, "Unexpected end of file\n");
			return -1;
		}
		bytes_read += ret;
	} while (bytes_read < count);

	return 0;
}

/*
 * Write wrapper that continues until the requested number of bytes have
 * been written or an error occurs. Returns 0 on success.
 */
static int do_write(int fd, const void *buf, size_t count)
{
	size_t bytes_written = 0;

	do {
		size_t ret = write(fd, (const char *)buf + bytes_written,
				   count - bytes_written);
		if (ret == -1) {
			switch (errno) {
			case EAGAIN:
				continue;
			default:
				return -1;
			}
		} else if (ret == 0) {
			fprintf(stderr, "Unexpected end of file\n");
			return -1;
		}
		bytes_written += ret;
	} while (bytes_written < count);

	return 0;
}

static struct alps_serio_dev *alps_serio_alloc(void)
{
	struct alps_serio_dev *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->serio_fd = -1;
	return dev;
}

static void alps_serio_free(struct alps_serio_dev *dev)
{
	if (dev->serio_drvctl_path)
		free(dev->serio_drvctl_path);
	free(dev);
}

static int serio_mouse_init(struct alps_serio_dev *dev)
{
	static const char serio_mouse_desc[] = "i8042 AUX port";
	char *path;
	glob_t globbuf;
	int ret;
	int i;
	int fd;
       
	path = malloc(PATH_MAX);
	if (!path)
		return -1;

	globbuf.gl_offs = 0;
	ret = glob("/sys/bus/serio/devices/serio*",
		   GLOB_ERR|GLOB_MARK|GLOB_NOSORT|GLOB_ONLYDIR, NULL, &globbuf);
	if (ret)
		goto free_path;

	ret = -1;
	for (i = 0; i < globbuf.gl_pathc; i++) {
		char read_buf[64] = {0,};
		verbose_printf("Checking path %s\n", globbuf.gl_pathv[i]);

		snprintf(path, PATH_MAX, "%sdescription", globbuf.gl_pathv[i]);

		fd = open(path, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Could not open %s for reading: %s\n",
				path, strerror(errno));
			continue;
		}

		if (read(fd, read_buf, sizeof(read_buf)) <= 0) {
			fprintf(stderr, "Could not read from %s\n", path);
		} else if (!strncmp(read_buf, serio_mouse_desc,
				    sizeof(serio_mouse_desc) - 1)) {
			printf("Found serio mouse at %s\n", globbuf.gl_pathv[i]);
			close(fd);
			snprintf(path, PATH_MAX, "%sdrvctl", globbuf.gl_pathv[i]);
			fd = open(path, O_WRONLY);
			if (fd == -1) {
				fprintf(stderr, "Could not open %s for writing: %s\n",
					path, strerror(errno));
				return -1;
			}

			if (write(fd, "serio_raw", 9) != 9) {
				fprintf(stderr, "Error writing to %s\n", path);
			} else {
				dev->serio_drvctl_path = strdup(path);
				if (dev->serio_drvctl_path)
					ret = 0;
			}

			close(fd);
			break;
		}

		close(fd);
	}

	if (dev->serio_drvctl_path) {
		/*
		 * XXX: Assume that the first serio device we find
		 * is the right one, should be improved
		 */
		globfree(&globbuf);
		ret = glob("/dev/serio_raw*", GLOB_ERR, NULL, &globbuf);
		if (ret) {
			fprintf(stderr, "Could not find serio_raw device node\n");
			goto free_glob;
		}

		ret = open(globbuf.gl_pathv[0], O_RDWR);
		if (ret != -1) {
			dev->serio_fd = ret;
			ret = 0;
		} else {
			fprintf(stderr, "Failed to open device node %s\n",
				globbuf.gl_pathv[0]);
		}
	}

free_glob:
	globfree(&globbuf);
free_path:
	free(path);
	return ret ? -1 : 0;
}
	
static void serio_mouse_deinit(struct alps_serio_dev *dev)
{
	int fd;

	if (dev->serio_fd != -1) {
		close(dev->serio_fd);
		dev->serio_fd = -1;
	}

	fd = open(dev->serio_drvctl_path, O_WRONLY);
	if (fd != -1) {
		write(fd, "psmouse", 7);
		close(fd);
	}
}

/*
 * This is quick and dirty, and prone to errors. I'm basically assuming
 * that there will be no data send other than responses to the commands
 * we send the touchpad. Of course this might not be true, and if it
 * isn't we're going to fail.
 */
static int ps2_command(struct alps_serio_dev *dev, unsigned char *data,
		       int command)
{
	int send_bytes = (command & 0xf000) >> 12;
	int recv_bytes = (command & 0x0f00) >> 8;
	unsigned char cmd = command & 0x00ff;
	unsigned char ack_byte;

	if ((send_bytes || recv_bytes) && !data)
		return -1;

	if (do_write(dev->serio_fd, &cmd, 1)) {
		fprintf(stderr, "Error writing to serio device\n");
		return -1;
	}

	/* Need to read ack byte before sending/receiving data */
	if (do_read(dev->serio_fd, &ack_byte, 1)) {
		fprintf(stderr, "Error reading ack byte\n");
		return -1;
	}
	if (ack_byte != 0xfa) {
		fprintf(stderr, "Invalid ack byte 0x%02hhx after command\n",
			ack_byte);
		return -1;
	}

	if (send_bytes) {
		if (do_write(dev->serio_fd, data, send_bytes)) {
			fprintf(stderr, "Error writing command data\n");
			return -1;
		} else if (do_read(dev->serio_fd, &ack_byte, 1)) {
			fprintf(stderr, "Error reading ack byte after sending data\n");
			return -1;
		} else if (ack_byte != 0xfa) {
			fprintf(stderr, "Invalid ack byte 0x%02hhx after data\n",
					ack_byte);
			return -1;
		}
	}

	if (recv_bytes && do_read(dev->serio_fd, data, recv_bytes)) {
		fprintf(stderr, "Error reading command response\n");
		return -1;
	}

	return 0;
}

static void ps2_drain(struct alps_serio_dev *dev)
{
	unsigned char byte;
	long flags;

	flags = fcntl(dev->serio_fd, F_GETFL);
	if (flags == -1) {
		fprintf(stderr, "Could not get serio_fd flags, device will not be drained\n");
		return;
	}
	if (fcntl(dev->serio_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		fprintf(stderr, "Could not set serio_fd flags, device will not be drained\n");
		return;
	}

	while (read(dev->serio_fd, &byte, 1) == 1)
		;

	if (fcntl(dev->serio_fd, F_SETFL, flags))
		fprintf(stderr, "Error restoring serio_fd flags, left in nonblock mode\n");
}

#define ALPS_CMD_NIBBLE_10 0x01f2

struct alps_command_nibbles {
	int command;
	unsigned char data;
};

static const struct alps_command_nibbles alps_nibble_commands_v3[] = {
	{ PSMOUSE_CMD_SETPOLL,		0x00 }, /* 0 */
	{ PSMOUSE_CMD_RESET_DIS,	0x00 }, /* 1 */
	{ PSMOUSE_CMD_SETSCALE21,	0x00 }, /* 2 */
	{ PSMOUSE_CMD_SETRATE,		0x0a }, /* 3 */
	{ PSMOUSE_CMD_SETRATE,		0x14 }, /* 4 */
	{ PSMOUSE_CMD_SETRATE,		0x28 }, /* 5 */
	{ PSMOUSE_CMD_SETRATE,		0x3c }, /* 6 */
	{ PSMOUSE_CMD_SETRATE,		0x50 }, /* 7 */
	{ PSMOUSE_CMD_SETRATE,		0x64 }, /* 8 */
	{ PSMOUSE_CMD_SETRATE,		0xc8 }, /* 9 */
	{ ALPS_CMD_NIBBLE_10,		0x00 }, /* a */
	{ PSMOUSE_CMD_SETRES,		0x00 }, /* b */
	{ PSMOUSE_CMD_SETRES,		0x01 }, /* c */
	{ PSMOUSE_CMD_SETRES,		0x02 }, /* d */
	{ PSMOUSE_CMD_SETRES,		0x03 }, /* e */
	{ PSMOUSE_CMD_SETSCALE11,	0x00 }, /* f */
};

static const struct alps_command_nibbles alps_nibble_commands_v4[] = {
	{ PSMOUSE_CMD_ENABLE,		0x00 }, /* 0 y*/
	{ PSMOUSE_CMD_RESET_DIS,	0x00 }, /* 1 y*/
	{ PSMOUSE_CMD_SETSCALE21,	0x00 }, /* 2 p*/
	{ PSMOUSE_CMD_SETRATE,		0x0a }, /* 3 p*/
	{ PSMOUSE_CMD_SETRATE,		0x14 }, /* 4 y*/
	{ PSMOUSE_CMD_SETRATE,		0x28 }, /* 5 y*/
	{ PSMOUSE_CMD_SETRATE,		0x3c }, /* 6 y*/
	{ PSMOUSE_CMD_SETRATE,		0x50 }, /* 7 y*/
	{ PSMOUSE_CMD_SETRATE,		0x64 }, /* 8 y*/
	{ PSMOUSE_CMD_SETRATE,		0xc8 }, /* 9 y*/
	{ ALPS_CMD_NIBBLE_10,		0x00 }, /* a p*/
	{ PSMOUSE_CMD_SETRES,		0x00 }, /* b y*/
	{ PSMOUSE_CMD_SETRES,		0x01 }, /* c p*/
	{ PSMOUSE_CMD_SETRES,		0x02 }, /* d ?*/
	{ PSMOUSE_CMD_SETRES,		0x03 }, /* e ?*/
	{ PSMOUSE_CMD_SETSCALE11,	0x00 }, /* f y*/
};

static int alps_send_nibble(struct alps_serio_dev *dev, int nibble)
{
	const struct alps_command_nibbles *addr_commands;
	int command;
	unsigned char *param;
	unsigned char dummy[4];

	if (nibble > 0xf)
		return -1;

	switch (dev->proto_version) {
	case ALPS_PROTO_V3:
		addr_commands = alps_nibble_commands_v3;
		break;
	case ALPS_PROTO_V4:
		addr_commands = alps_nibble_commands_v4;
		break;
	default:
		return -1;
	}

	command = addr_commands[nibble].command;
	param = (command & 0x0f00) ?
		dummy : (unsigned char *)&addr_commands[nibble].data;

	return ps2_command(dev, param, command);
}

static int alps_set_reg_addr(struct alps_serio_dev *dev, int addr)
{
	int i, nibble;
	int command;

	switch (dev->proto_version) {
	case ALPS_PROTO_V3:
		command = 0x00ec;
		break;
	case ALPS_PROTO_V4:
		command = 0x00f5;
		break;
	default:
		return -1;
	}

	if (ps2_command(dev, NULL, command))
		return -1;

	for (i = 12; i >=0; i -= 4) {
		nibble = (addr >> i) & 0xf;
		if (alps_send_nibble(dev, nibble))
			return -1;
	}

	return 0;
}

/*
 * Returns register value, or -1 on error.
 */
static int alps_read_reg(struct alps_serio_dev *dev, int addr)
{
	unsigned char param[4];

	if (alps_set_reg_addr(dev, addr))
		return -1;

	if (ps2_command(dev, param, PSMOUSE_CMD_GETINFO))
		return -1;

	/*
	 * Address being read is returned in the first two bytes of
	 * the result. Verify this matches the requested address.
	 */
	if (addr != ((param[0] << 8) | param[1]))
		return -1;

	/* Register value is in third byte of result */
	return param[2];
}

static int alps_enter_command_mode(struct alps_serio_dev *dev,
				   unsigned char *param)
{
	unsigned char dummy[4];
	unsigned char *data = param ? param : dummy;

	if (ps2_command(dev, NULL, 0xec) ||
	    ps2_command(dev, NULL, 0xec) ||
	    ps2_command(dev, NULL, 0xec) ||
	    ps2_command(dev, data, PSMOUSE_CMD_GETINFO)) {
		fprintf(stderr, "Failed to enter command mode\n");
		return -1;
	}

	return 0;
}

static void alps_exit_command_mode(struct alps_serio_dev *dev)
{
	ps2_command(dev, NULL, PSMOUSE_CMD_SETSTREAM);
}

static void alps_dump_registers(struct alps_serio_dev *dev)
{
	int i, val;
	int retries;
	unsigned char param[4];

	/* XXX: Need to determine max address to check */
	for (i = 0; i <= 0xffff; i++) {
		retries = 3;
		do {
			val = alps_read_reg(dev, i);
			if (val != -1)
				break;

			/* Try resetting a few times before giving up */
			alps_exit_command_mode(dev);
			ps2_command(dev, param, PSMOUSE_CMD_RESET_BAT);
			alps_enter_command_mode(dev, param);
		} while (--retries);

		if (val != -1)
			printf("%04x %02x\n", i, val);
		else
			printf("%04x Failed!\n", i);
	}
}

int main(void)
{
	struct alps_serio_dev *dev;
	unsigned char param[4];

	if (geteuid() != 0) {
		fprintf(stderr, "Error: Must be run as root\n");
		exit(EXIT_FAILURE);
	}

	dev = alps_serio_alloc();
	if (!dev) {
		fprintf(stderr, "Error: Could not allocate device\n");
		exit(EXIT_FAILURE);
	}

	if (serio_mouse_init(dev)) {
		fprintf(stderr, "Error: Could not locate serio mouse\n");
		serio_mouse_deinit(dev);
		exit(EXIT_FAILURE);
	}

	/*
	 * First reset the device. Hopefully this will reset any changes
	 * already made and will get it to stop reporting data. We ignore
	 * errors for this one.
	 */
	ps2_command(dev, param, PSMOUSE_CMD_RESET_BAT);

	/*
	 * Now drain the device. If any data has been queued up from the
	 * driver this will get rid of it, and hopefully things will go
	 * smoothly from here.
	 */
	ps2_drain(dev);

	/*
	 * E6 report. ALPS should return 0,0,10 or 0,0,100.
	 */
	param[0] = 0;
	if (ps2_command(dev, param, PSMOUSE_CMD_SETRES) ||
	    ps2_command(dev, NULL, PSMOUSE_CMD_SETSCALE11) ||
	    ps2_command(dev, NULL, PSMOUSE_CMD_SETSCALE11) ||
	    ps2_command(dev, NULL, PSMOUSE_CMD_SETSCALE11) ||
	    ps2_command(dev, param, PSMOUSE_CMD_GETINFO)) {
		printf("E6 report failed, not an ALPS touchpad\n");
		goto cleanup;
	}

	if (param[0] != 0 || param[1] != 0 ||
	    (param[2] != 10 && param[2] != 100)) {
		printf("Invalid E6 report: %02hhx %02hhx %02hhx\n",
		       param[0], param[1], param[2]);
		printf("Not an ALPS touchpad\n");
		goto cleanup;
	}

	/*
	 * E7 report. Expect 0x73,0x02,0x64 for a v3 touchpad.
	 */
	param[0] = 0;
	if (ps2_command(dev, param, PSMOUSE_CMD_SETRES) ||
	    ps2_command(dev, NULL, PSMOUSE_CMD_SETSCALE21) ||
	    ps2_command(dev, NULL, PSMOUSE_CMD_SETSCALE21) ||
	    ps2_command(dev, NULL, PSMOUSE_CMD_SETSCALE21) ||
	    ps2_command(dev, param, PSMOUSE_CMD_GETINFO)) {
		printf("E7 report failed, not an ALPS touchpad\n");
		goto cleanup;
	}

	if (param[0] != 0x73 || param[1] != 0x02 || param[2] != 0x64) {
		printf("E7 report: %02hhx %02hhx %02hhx\n",
		       param[0], param[1], param[2]);
		printf("Not a v3 ALPS touchpad\n");
		goto cleanup;
	}

	/*
	 * Enter command mode for reading registers. Output response,
	 * as I don't know what it means and would like to see what
	 * values are being reported.
	 */
	if (alps_enter_command_mode(dev, param)) {
		printf("ALPS device failed to enter command mode\n");
		goto cleanup;
	}
	printf("Command mode response: %02hhx %02hhx %02hhx\n",
	       param[0], param[1], param[2]);

	/*
	 * XXX: Currently we're assuming that the last byte of the
	 * command mode response allows us to differentiate between
	 * V3 and V4 protocol.
	 */
	switch (param[2]) {
	case 0x9b:
	case 0x9d:
		/* revision 1 */
		dev->proto_version = ALPS_PROTO_V3;
		break;
	case 0x8a:
		/* revision 2 */
		dev->proto_version = ALPS_PROTO_V4;
		break;
	default:
		/* unknown revision */
		printf("Unknown command mode response, assuming protocol version 3\n");
		dev->proto_version = ALPS_PROTO_V3;
		break;
	}

	alps_dump_registers(dev);

	alps_exit_command_mode(dev);

cleanup:
	serio_mouse_deinit(dev);
	alps_serio_free(dev);
	exit(EXIT_SUCCESS);
}
