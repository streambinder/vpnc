#ifndef __TUN_DEV_H__
#define __TUN_DEV_H__

#include <netinet/in.h>

int tun_open(char *dev);
int tun_close(int fd, char *dev);
int tun_write(int fd, char *buf, int len);
int tun_read(int fd, char *buf, int len);

#if defined(__linux__)
#include <error.h>
#else
extern void error(int fd, int errorno, const char *fmt, ...);
extern int getline(char **line, size_t *length, FILE *stream);
#endif

#endif
