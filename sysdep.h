#ifndef __SYSDEP_H__
#define __SYSDEP_H__

/*
 * Different systems define different macros.
 * For vpnc, this list should be used as
 * reference:
 *
 * __linux__ 
 * __NetBSD__
 * __OpenBSD__
 * __FreeBSD__
 * __DragonFly__
 * __APPLE__      Darwin / MacOS X
 * __sun__        SunOS / Solaris
 * __CYGWIN__
 *
 */

#include <sys/types.h>
#include <netinet/in.h>

int tun_open(char *dev);
int tun_close(int fd, char *dev);
int tun_write(int fd, unsigned char *buf, int len);
int tun_read(int fd, unsigned char *buf, int len);

#if defined(__linux__)
#include <error.h>
#else
extern void error(int fd, int errorno, const char *fmt, ...);
extern int getline(char **line, size_t * length, FILE * stream);
#endif

#if defined(__NetBSD__)
#define HAVE_SA_LEN 1
#endif

#if defined(__OpenBSD__)
#define HAVE_SA_LEN 1
#define NEED_IPLEN_FIX 1
#define NEW_TUN 1
#endif

#if defined(__FreeBSD__)
#define HAVE_SA_LEN 1
#endif

#if defined(__DragonFly__)
#define HAVE_SA_LEN 1
#endif

#if defined(__APPLE__)
#define HAVE_SA_LEN 1
#define NEED_IPLEN_FIX 1
#endif

#if defined(__sun__)
#include <stdarg.h>

#define NEED_IPLEN_FIX 1

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif

#define getpass(prompt) getpassphrase(prompt)

extern int vasprintf(char **strp, const char *fmt, va_list ap);
extern int asprintf(char **strp, const char *fmt, ...);
extern int setenv(const char *name, const char *value, int overwrite);
extern int unsetenv(const char *name);

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
