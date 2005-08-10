/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <net/if.h>

#ifdef DRAGONFLY_BSD
#include <net/tun/if_tun.h>
#else
#include <net/if_tun.h>
#endif

#include "sysdep.h"

/* 
 * Allocate TUN device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */
int tun_open(char *dev)
{
	char tunname[14];
	int i, fd;

	if (*dev) {
		if (strncmp(dev, "tun", 3))
			error(1, 0,
				"error: arbitrary naming tunnel interface only supported on linux\n");
		snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
		return open(tunname, O_RDWR);
	}

	for (i = 0; i < 255; i++) {
		snprintf(tunname, sizeof(tunname), "/dev/tun%d", i);
		/* Open device */
		if ((fd = open(tunname, O_RDWR)) > 0) {
			snprintf(dev, IFNAMSIZ, "tun%d", i);
			return fd;
		}
	}
	return -1;
}

int tun_close(int fd, char *dev)
{
	dev = NULL; /*unused */
	return close(fd);
}

#ifdef NEW_TUN
#define MAX_MRU 2048
struct tun_data {
	union {
		uint32_t family;
		uint32_t timeout;
	} header;
	u_char data[MAX_MRU];
};

/* Read/write frames from TUN device */
int tun_write(int fd, unsigned char *buf, int len)
{
	char *data;
	struct tun_data tun;

	if (len > (int)sizeof(tun.data))
		return -1;

	memcpy(tun.data, buf, len);
	tun.header.family = htonl(AF_INET);
	len += (sizeof(tun) - sizeof(tun.data));
	data = (char *)&tun;

	return write(fd, data, len) - (sizeof(tun) - sizeof(tun.data));
}

int tun_read(int fd, unsigned char *buf, int len)
{
	struct tun_data tun;
	char *data;
	size_t sz;
	int pack;

	data = (char *)&tun;
	sz = sizeof(tun);
	pack = read(fd, data, sz);
	if (pack == -1)
		return -1;

	pack -= sz - sizeof(tun.data);
	if (pack > len)
		pack = len; /* truncate paket */

	memcpy(buf, tun.data, pack);

	return pack;
}

#else

int tun_write(int fd, char *buf, int len)
{
	return write(fd, buf, len);
}

int tun_read(int fd, char *buf, int len)
{
	return read(fd, buf, len);
}
#endif

/***********************************************************************/
/* other support functions */

void error(int status, int errornum, const char *fmt, ...)
{
	char *buf2;
	va_list ap;

	va_start(ap, fmt);
	vasprintf(&buf2, fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s", buf2);
	if (errornum)
		fprintf(stderr, ": %s\n", strerror(errornum));
	free(buf2);

	if (status)
		exit(status);
}

int getline(char **line, size_t * length, FILE * stream)
{
	char *tmpline;
	size_t len;

	tmpline = fgetln(stream, &len);
	if (feof(stream))
		return -1;
	if (*line == NULL) {
		*line = malloc(len + 1);
		*length = len + 1;
	}
	if (*length < len + 1) {
		*line = realloc(*line, len + 1);
		*length = len + 1;
	}
	if (*line == NULL)
		return -1;
	memcpy(*line, tmpline, len);
	(*line)[len] = '\0';
	return len;
}
