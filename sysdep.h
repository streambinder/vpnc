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
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include "config.h"

int tun_open(char *dev, enum if_mode_enum mode);
int tun_close(int fd, char *dev);
int tun_write(int fd, unsigned char *buf, int len);
int tun_read(int fd, unsigned char *buf, int len);
int tun_get_hwaddr(int fd, char *dev, struct sockaddr *hwaddr);

/***************************************************************************/
#if defined(__linux__)
#include <error.h>

#define HAVE_VASPRINTF 1
#define HAVE_ASPRINTF  1
#define HAVE_ERROR     1
#define HAVE_GETLINE   1
#define HAVE_UNSETENV  1
#define HAVE_SETENV    1
#endif

/***************************************************************************/
#if defined(__NetBSD__)
#define HAVE_SA_LEN 1

#define HAVE_VASPRINTF 1
#define HAVE_ASPRINTF  1
#define HAVE_FGETLN    1
#define HAVE_UNSETENV  1
#define HAVE_SETENV    1
#endif

/***************************************************************************/
#if defined(__OpenBSD__)
#define HAVE_SA_LEN 1
#define NEED_IPLEN_FIX 1
#define NEW_TUN 1

#define HAVE_VASPRINTF 1
#define HAVE_ASPRINTF  1
#define HAVE_FGETLN    1
#define HAVE_UNSETENV  1
#define HAVE_SETENV    1
#endif

/***************************************************************************/
#if defined(__FreeBSD__)
#define HAVE_SA_LEN 1

#define HAVE_VASPRINTF 1
#define HAVE_ASPRINTF  1
#define HAVE_FGETLN    1
#define HAVE_UNSETENV  1
#define HAVE_SETENV    1
#endif

/***************************************************************************/
#if defined(__DragonFly__)
#define HAVE_SA_LEN 1

#define HAVE_VASPRINTF 1
#define HAVE_ASPRINTF  1
#define HAVE_FGETLN    1
#define HAVE_UNSETENV  1
#define HAVE_SETENV    1
#endif

/***************************************************************************/
#if defined(__APPLE__)
#define HAVE_SA_LEN 1
#define NEED_IPLEN_FIX 1

#define HAVE_VASPRINTF 1
#define HAVE_ASPRINTF  1
#define HAVE_FGETLN    1
#define HAVE_UNSETENV  1
#define HAVE_SETENV    1
#endif

/***************************************************************************/
#if defined(__sun__)
#define NEED_IPLEN_FIX 1

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif

#define getpass(prompt) getpassphrase(prompt)

/* where is this defined? */
#include <sys/socket.h>
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
#endif
/***************************************************************************/


#ifndef IPDEFTTL
#define IPDEFTTL 64 /* default ttl, from RFC 1340 */
#endif

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP IPPROTO_ENCAP
#endif

#ifndef ETH_HLEN
#define ETH_HLEN (sizeof(struct ether_header))
#endif

#ifndef ETH_ALEN
#define ETH_ALEN (sizeof(struct ether_addr))
#endif

#ifndef HAVE_ERROR
extern void error(int fd, int errorno, const char *fmt, ...);
#endif
#ifndef HAVE_GETLINE
extern int getline(char **line, size_t * length, FILE * stream);
#endif
#ifndef HAVE_VASPRINTF
extern int vasprintf(char **strp, const char *fmt, va_list ap);
#endif
#ifndef HAVE_ASPRINTF
extern int asprintf(char **strp, const char *fmt, ...);
#endif
#ifndef HAVE_SETENV
extern int setenv(const char *name, const char *value, int overwrite);
#endif
#ifndef HAVE_UNSETENV
extern int unsetenv(const char *name);
#endif


#endif
