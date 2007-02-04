/* IPSec VPN client compatible with Cisco equipment.
    Copyright (C) 2007      Maurice Massar

    based on VTun - Virtual Tunnel over TCP/IP network.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <sys/socket.h>
#include <net/if.h>

#if defined(__DragonFly__)
#include <net/tun/if_tun.h>
#elif defined(__linux__)
#include <linux/if_tun.h>
#elif defined(__APPLE__)
#else
#include <net/if_tun.h>
#endif

#ifdef __sun__
#include <ctype.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <signal.h>
#include <stropts.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#include "sysdep.h"

#if !defined(HAVE_VASPRINTF) || !defined(HAVE_ASPRINTF) || !defined(HAVE_ERROR)
#include <stdarg.h>
#endif

#if defined(__sun__)
extern char **environ;
static int ip_fd = -1, muxid;
#endif

/* 
 * Allocate TUN/TAP device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */
#if defined(__sun__)
int tun_open(char *dev, enum if_mode_enum mode)
{
	int tun_fd, if_fd, ppa = -1;
	struct ifreq ifr;
	char *ptr;

	if (*dev) {
		ptr = dev;
		while (*ptr && !isdigit((int)*ptr))
			ptr++;
		ppa = atoi(ptr);
	}

	if ((ip_fd = open("/dev/ip", O_RDWR, 0)) < 0) {
		syslog(LOG_ERR, "Can't open /dev/ip");
		return -1;
	}

	if ((tun_fd = open(((mode == IF_MODE_TUN) ? "/dev/tun" : "/dev/tap"), O_RDWR, 0)) < 0) {
		syslog(LOG_ERR, "Can't open /dev/tun");
		return -1;
	}

	/* Assign a new PPA and get its unit number. */
	if ((ppa = ioctl(tun_fd, TUNNEWPPA, ppa)) < 0) {
		syslog(LOG_ERR, "Can't assign new interface");
		return -1;
	}

	if ((if_fd = open(((mode == IF_MODE_TUN) ? "/dev/tun" : "/dev/tap"), O_RDWR, 0)) < 0) {
		syslog(LOG_ERR, "Can't open /dev/tun (2)");
		return -1;
	}
	if (ioctl(if_fd, I_PUSH, "ip") < 0) {
		syslog(LOG_ERR, "Can't push IP module");
		return -1;
	}

	/* Assign ppa according to the unit number returned by tun device */
	if (ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0 && errno != EEXIST) {
		syslog(LOG_ERR, "Can't set PPA %d", ppa);
		return -1;
	}
	if ((muxid = ioctl(ip_fd, I_PLINK, if_fd)) < 0) {
		syslog(LOG_ERR, "Can't link TUN device to IP");
		return -1;
	}
	close(if_fd);

	snprintf(dev, IFNAMSIZ, "%s%d", ((mode == IF_MODE_TUN) ? "tun" : "tap"), ppa);

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);
	ifr.ifr_ip_muxid = muxid;

	if (ioctl(ip_fd, SIOCSIFMUXID, &ifr) < 0) {
		ioctl(ip_fd, I_PUNLINK, muxid);
		syslog(LOG_ERR, "Can't set multiplexor id");
		return -1;
	}

	return tun_fd;
}
#elif defined(IFF_TUN)
int tun_open(char *dev, enum if_mode_enum mode)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		error(0, errno,
			"can't open /dev/net/tun, check that it is either device char 10 200 or (with DevFS) a symlink to ../misc/net/tun (not misc/net/tun)");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = ((mode == IF_MODE_TUN) ? IFF_TUN : IFF_TAP) | IFF_NO_PI;
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
int tun_open(char *dev, enum if_mode_enum mode)
{
	char tunname[14];
	int i, fd;

	if (*dev) {
		if (strncmp(dev, ((mode == IF_MODE_TUN) ? "tun" : "tap"), 3))
			error(1, 0,
				"error: arbitrary naming tunnel interface is not supported in this version\n");
		snprintf(tunname, sizeof(tunname), "/dev/%s", dev);
		return open(tunname, O_RDWR);
	}

	for (i = 0; i < 255; i++) {
		snprintf(tunname, sizeof(tunname), "/dev/%s%d",
			((mode == IF_MODE_TUN) ? "tun" : "tap"), i);
		/* Open device */
		if ((fd = open(tunname, O_RDWR)) > 0) {
			snprintf(dev, IFNAMSIZ, "%s%d",
				((mode == IF_MODE_TUN) ? "tun" : "tap"), i);
			return fd;
		}
	}
	return -1;
}
#endif /* New driver support */

/* 
 * Close TUN device. 
 */
#if defined(__sun__)
int tun_close(int fd, char *dev)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);
	if (ioctl(ip_fd, SIOCGIFFLAGS, &ifr) < 0) {
		syslog(LOG_ERR, "Can't get iface flags");
		return 0;
	}

	if (ioctl(ip_fd, I_PUNLINK, muxid) < 0) {
		syslog(LOG_ERR, "Can't unlink interface");
		return 0;
	}

	close(ip_fd);
	close(fd);
	return 0;
}
#else
int tun_close(int fd, char *dev)
{
	dev = NULL; /*unused */
	return close(fd);
}
#endif


#if defined(__sun__)
int tun_write(int fd, unsigned char *buf, int len)
{
	struct strbuf sbuf;
	sbuf.len = len;
	sbuf.buf = buf;
	return putmsg(fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
}

int tun_read(int fd, unsigned char *buf, int len)
{
	struct strbuf sbuf;
	int f = 0;

	sbuf.maxlen = len;
	sbuf.buf = buf;
	return getmsg(fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
}
#elif defined(NEW_TUN)
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

int tun_write(int fd, unsigned char *buf, int len)
{
	return write(fd, buf, len);
}

int tun_read(int fd, unsigned char *buf, int len)
{
	return read(fd, buf, len);
}

#endif

/*
 * Get HW addr
 */
int tun_get_hwaddr(int fd, char *dev, uint8_t *hwaddr)
{
#ifdef SIOCGIFHWADDR
	struct ifreq ifr;
	
	/* Use a new socket fd! */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}
	
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		return -1;
	}
	
	memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	
	return 0;
#else
	/* todo: implement using SIOCGLIFADDR */
	errno = ENOSYS;
	return -1;
#endif
}

/***********************************************************************/
/* other support functions */

#ifndef HAVE_VASPRINTF
int vasprintf(char **strp, const char *fmt, va_list ap)
{
	int ret;
	char *strbuf;

	ret = vsnprintf(NULL, 0, fmt, ap);
	strbuf = (char *)malloc(ret + 1);
	if (strbuf == NULL) {
		errno = ENOMEM;
		ret = -1;
	}
	vsnprintf(strbuf, ret + 1, fmt, ap);
	*strp = strbuf;
	return ret;
}
#endif

#ifndef HAVE_ASPRINTF
int asprintf(char **strp, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vasprintf(strp, fmt, ap);
	va_end(ap);

	return ret;
}
#endif

#ifndef HAVE_ERROR
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
#endif

#ifndef HAVE_GETLINE
int getline(char **line, size_t * length, FILE * stream)
{
	size_t len;
#ifdef HAVE_FGETLN
	char *tmpline;

	tmpline = fgetln(stream, &len);
#else
	char tmpline[512];

	fgets(tmpline, sizeof(tmpline), stream);
	len = strlen(tmpline);
#endif
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
#endif

#ifndef HAVE_UNSETENV
int unsetenv(const char *name)
{
	int i, len;

	len = strlen(name);
	for (i = 0; environ[i]; i++)
		if (!strncmp(name, environ[i], len))
			if (environ[i][len] == '=')
				break;

	for (; environ[i] && environ[i + 1]; i++)
		environ[i] = environ[i + 1];
	
	return 0;
}
#endif

#ifndef HAVE_SETENV
int setenv(const char *name, const char *value, int overwrite)
{
	int ret;
	char *newenv;

	if (overwrite == 0)
		if (getenv(name) != NULL)
			return 0;

	newenv = malloc(strlen(name) + 1 + strlen(value) + 1);
	if (newenv == NULL)
		return -1;

	*newenv = '\0';
	strcat(newenv, name);
	strcat(newenv, "=");
	strcat(newenv, value);

	ret = putenv(newenv);
	if (ret == -1)
		free(newenv);

	return ret;
}
#endif
