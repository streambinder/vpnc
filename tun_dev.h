#ifndef __TUN_DEV_H__
#define __TUN_DEV_H__

int tun_open(char *dev);
int tun_close(int fd, char *dev);
int tun_write(int fd, char *buf, int len);
int tun_read(int fd, char *buf, int len);

#endif
