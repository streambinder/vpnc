#ifndef __SYSDEP_H__
#define __SYSDEP_H__

#include <sys/types.h>
#include <netinet/in.h>

int tun_open(char *dev);
int tun_close(int fd, char *dev);
int tun_write(int fd, char *buf, int len);
int tun_read(int fd, char *buf, int len);

const char *sysdep_config_script(void);

#if defined(__linux__)
#include <error.h>
#else
extern void error(int fd, int errorno, const char *fmt, ...);
extern int getline(char **line, size_t * length, FILE * stream);
#endif

#if defined(__sun__)
#include <stdarg.h>

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif

extern int vasprintf(char **strp, const char *fmt, va_list ap);
extern int asprintf(char **strp, const char *fmt, ...);
extern int setenv(const char *name, const char *value, int overwrite);
extern void unsetenv(const char *name);

/* where is this defined? */
#include <sys/socket.h>
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
#endif

#ifndef IPDEFTTL
#define IPDEFTTL 64 /* default ttl, from RFC 1340 */
#endif

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP IPPROTO_ENCAP
#endif

#endif
