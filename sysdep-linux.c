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

/*
 * $Id: tun_dev.c,v 1.1.2.2 2000/11/20 08:15:53 maxk Exp $
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "sysdep.h"

/* 
 * Allocate TUN device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */
#ifdef IFF_TUN
int tun_open(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		error(0, errno,
			"can't open /dev/net/tun, check that it is either device char 10 200 or (with DevFS) a symlink to ../misc/net/tun (not misc/net/tun)");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}
#else
int tun_open(char *dev)
{
	char tunname[14];
	int i, fd;

	if (*dev) {
		if (strncmp(dev, "tun", 3))
			error(1, 0,
				"error: arbitrary naming tunnel interface is not supported in this version\n");
		sprintf(tunname, "/dev/%s", dev);
		return open(tunname, O_RDWR);
	}

	for (i = 0; i < 255; i++) {
		sprintf(tunname, "/dev/tun%d", i);
		/* Open device */
		if ((fd = open(tunname, O_RDWR)) > 0) {
			sprintf(dev, "tun%d", i);
			return fd;
		}
	}
	return -1;
}

#endif /* New driver support */

int tun_close(int fd, char *dev)
{
	dev = NULL; /*unused */
	return close(fd);
}

/* Read/write frames from TUN device */
int tun_write(int fd, char *buf, int len)
{
	return write(fd, buf, len);
}

int tun_read(int fd, char *buf, int len)
{
	return read(fd, buf, len);
}

/***********************************************************************/
/* other support functions */

const char *sysdep_config_script(void)
{
	return "ifconfig $TUNDEV inet $INTERNAL_IP4_ADDRESS pointopoint $INTERNAL_IP4_ADDRESS netmask 255.255.255.255 mtu 1412 up";
}
